# Security Remediation Plan: Aligning with Agentic-Ecosystem Best Practices

Scope: the flow `user prompt -> web-frontend -> agent-orchestrator (SPIRE/Istio) -> Azure MCP server (Entra OBO) / GCP MCP server (Google WIF/STS)`.

Principles the plan is measured against: least privilege, token downscoping and audience binding, a real on-behalf-of (OBO) chain that keeps user and agent separate, no token passthrough (MCP authorization spec), verified identity at every hop, tool-call authorization independent of the LLM, and auditable lineage.

## 1. What the code does today

1. `web-frontend` `/api/login` does not authenticate anyone. It picks a canned user, then **mints** a Keycloak token (HS256, shared secret), an Entra-looking token, and a Google-looking token, and returns them all to the browser (`app/web-frontend/src/index.js:76-215`).
2. `agent-orchestrator` `/api/agent/chat` **decodes but never verifies** the user token (`index.js:204-223`). A keyword-matching "LLM simulator" picks the tools (`llmSimulator.js`). A JS reimplementation of the policy ("OPA") gates them (`opaPolicy.js`).
3. `tokenExchange.js` builds the per-cloud token:
   - **Azure:** real Entra OBO if a user assertion and client secret exist. Otherwise it falls back to a password grant with a hard-coded password, then to client-credentials, then to a locally signed "Entra" token.
   - **GCP:** an STS call whose parameters are wrong (see 3.4). When it fails, it signs a fake `iss: sts.googleapis.com` token with a committed key.
4. The MCP servers verify those self-signed tokens against committed certs, then decide access with string checks such as `userUpn.includes('alice')`.
5. The orchestrator returns the raw tokens, SVIDs and full claims to the browser in every response.

The design intent (SPIFFE agent identity, `act` chain, scope intersection, CAB, per-resource policy) is right. The gap is that most enforcement is simulated, and the simulation fails open.

## 2. Target architecture

```
Browser --OIDC code+PKCE--> IdP (Entra or Keycloak)           [user authn, MFA, short-lived token aud=orchestrator]
Browser --Bearer user token--> Orchestrator                   [verifies sig/iss/aud/exp via JWKS]
Orchestrator (SPIFFE JWT-SVID, real SPIRE)
   |-- RFC 8693 exchange at IdP: subject=user token, actor=JWT-SVID, resource=<mcp-server>, scope=<one tool scope>
   |      -> token: sub=user, act={sub: spiffe id}, aud=that one MCP server, ttl<=5m
   |-- Azure MCP: Bearer (aud=azure-mcp) --> MCP does Entra OBO itself --> Storage as the user (RBAC enforces)
   `-- GCP MCP:   Bearer (aud=gcp-mcp)   --> MCP does Workforce-Federation STS exchange + CAB --> BigQuery as the user
```

Rules that hold throughout:

- Each MCP server accepts only tokens minted for it, and does its own downstream exchange. No token is forwarded to a different audience.
- The cloud's native IAM is the final authority. MCP-layer role checks are defence in depth, never the only gate.
- A policy engine outside the LLM decides whether a tool call is allowed. LLM output is untrusted input.

## 3. Gap analysis by layer

Severity: **C** critical (fails open or breaks the trust model), **H** high, **M** medium.

### 3.1 Identity and authentication (frontend, orchestrator)

| # | Finding | Evidence | Sev |
|---|---|---|---|
| I1 | Frontend mints tokens itself; no real login. Passwords and a shared HMAC secret are in code | `web-frontend/src/index.js:33-64, 91-106` | C |
| I2 | Orchestrator trusts unverified user tokens; any base64 JSON with `roles:[admin]` is accepted | `agent-orchestrator/src/index.js:204-223` | C |
| I3 | Keycloak realm ships plaintext user passwords, a client secret, direct-grant enabled, public client | `k8s/keycloak/keycloak-realm-configmap.yaml:38,55,120-150` | H |
| I4 | Password-grant fallback with hard-coded password to get a user token for any `userEmail` | `tokenExchange.js:386-410` | C |
| I5 | Fallback chain silently degrades from user-delegated to app-only (client credentials) | `tokenExchange.js:433-440` | C |
| I6 | Raw user, SVID and exchanged tokens returned to the browser | `index.js` (`hopToHop.*.rawToken`) | H |
| I7 | A `simulate_rogue_actor` / "tamper" branch is in the production request path | `index.js:1128-1139` | M |
| I8 | Hard-coded default secrets (`demo-obo-token-secret-key-2026`, `demo-spire-secret-key-2026`) in code and in `k8s/gcp-mcp-server-deployment.yaml` | several | H |
| I9 | Committed private keys (`certs/*-key.pem`) | `certs/` | H |

### 3.2 Agent identity and delegation

| # | Finding | Evidence | Sev |
|---|---|---|---|
| A1 | The SVID is HMAC-signed locally; the SPIRE Workload API is never called. Simulated mode is silent | `spireClient.js:27-48` | C |
| A2 | The `act` chain is built by the orchestrator and signed by itself. Hop provenance is asserted, not attested | `tokenExchange.js:135-165` | H |
| A3 | Downstream "trusted actor" = any `spiffe://example.org/ns/*` or `urn:agent:*` | `gcp-mcp-server/src/auth.js:148-175`, `mcp-server/src/auth.js:108-131` | H |
| A4 | `X-Delegated-Identity` header can override the token's user (`sub`, `roles`) | `gcp-mcp-server/src/auth.js:211-229`, `mcp-server/src/auth.js:179-198` | C |
| A5 | Missing `aud` is accepted (`if (!hasValidAud && decoded.aud)`); any audience containing `gcp` or `run.app` passes | `gcp-mcp-server/src/auth.js:116-117` | H |
| A6 | One orchestrator identity and one broad OBO scope (`user_impersonation`) cover every tool | `tokenExchange.js:430` | M |

### 3.3 Tool authorization and prompt handling

| # | Finding | Evidence | Sev |
|---|---|---|---|
| T1 | The policy is JS, not OPA. The `.rego` file is never evaluated and disagrees with the JS (no BigQuery tools in rego) | `opaPolicy.js`, `orchestrator_policy.rego` | H |
| T2 | The only policy rules are a weekend check and a tool allow-list; nothing checks user, arguments or data sensitivity | `opaPolicy.js:28-81` | H |
| T3 | Role/scope logic uses string matches (`includes('alice')`, `includes('bob')`) | `mcp-server/src/auth.js:155`, `azureStorage.js:78-79` | C |
| T4 | Tool arguments come from the plan with no schema or injection controls. Model-supplied values reach SQL by string interpolation | `bigqueryClient.js:129` | C |
| T5 | Tool outputs flow back into the LLM context with no trust boundary (indirect prompt injection from blob/BigQuery contents) | pipeline Turn 3 | H |
| T6 | `Mail.Send` to an external address is executed with no human approval or confirmation | `index.js:819-960` | H |
| T7 | No budgets: no limits on turns, calls, rows or bytes per request | n/a | M |

### 3.4 Google Cloud

(Details in the earlier review; summarised.)

| # | Finding | Sev |
|---|---|---|
| G1 | `roles/iam.workloadIdentityUser` is bound to `principalSet://…/k8s-agent-pool/*`; any pool identity can use `gcp-mcp-sa` (`terraform/gcp/main.tf:111`, `setup-gcp-wif.sh:141`) | C |
| G2 | The provider has no `attribute_condition` (issuer/subject/audience pinning) | H |
| G3 | Humans are modelled as **workload pool** subjects with direct project-level `bigquery.admin`/`dataViewer` grants (`main.tf:118-136`). Human principals belong in a **workforce** pool | H |
| G4 | BigQuery roles are granted at project level, not on the dataset | H |
| G5 | The STS call is malformed: `access_boundary` is not a valid parameter (CAB goes in `options` on a second exchange), the actor token is not a JWT, and the SPIFFE subject token type is wrong. The 2s timeout hides failures | H |
| G6 | The CAB points at a table that does not exist (`audit_logs.access_audit`), and its condition uses project ID where project number is required | M |
| G7 | The BigQuery client never uses the downscoped token. It uses `GCP_ACCESS_TOKEN`, then the Cloud Run service account's metadata token, so the CAB has no effect | C |
| G8 | The MCP server verifies a self-signed "Google STS" token. Real STS access tokens are opaque and cannot be verified this way | C |
| G9 | Audit-log access is decided from a token claim (`bigqueryClient.js:247-257`), not Google IAM | H |

### 3.5 Azure

| # | Finding | Sev |
|---|---|---|
| Z1 | Orchestrator uses a **client secret** for OBO (`ENTRA_CLIENT_SECRET`) although it already holds a SPIFFE JWT-SVID. Use a federated client assertion instead | H |
| Z2 | The managed identity has `Storage Blob Data Contributor` on both containers (`azure/main.tf:61-72`). The read-only tools need Reader | H |
| Z3 | The Storage call sends the MCP-audience token to blob storage (aud mismatch) and labels it "JIT user delegation". No user delegation key or SAS is created (`azureStorage.js:29-71, 108-110`) | H |
| Z4 | The `AUTHORIZED_SENDERS` check allows a token with no `azp` and no `act` ("minimal tests" clause) (`mcp-server/src/auth.js:111`) | H |
| Z5 | Storage account network access is open (no private endpoint or firewall), shared key not disabled, public network access not restricted | M |
| Z6 | CI deploys with `AZURE_CREDENTIALS` (long-lived secret) and calls a `foundry-deploy.sh` that is not in the repo | M |

### 3.6 Platform, mesh and observability

| # | Finding | Sev |
|---|---|---|
| P1 | Istio is installed with SPIRE-issued certs, but there are no `PeerAuthentication` (STRICT) or `AuthorizationPolicy` resources. Nothing restricts who may call the orchestrator or MCP pods | H |
| P2 | No `NetworkPolicy`, egress control, pod security context (non-root, read-only FS, drop caps) | M |
| P3 | MCP endpoints expose a REST bypass (`/api/tools/:name`) with weaker handling than `/mcp`; unauthenticated `/` health returns tool counts | M |
| P4 | Logs print token contents and user identifiers. No tamper-evident audit sink; correlation is manual strings | M |
| P5 | Tests assert behaviour against the mocks (committed keys, simulated mode), so a green suite proves little about real enforcement | M |

## 4. Remediation plan

Each phase ends in a verifiable state. Phases 0 and 1 block everything else.

### Phase 0: Stop failing open (days)

Goal: no path where a missing credential produces a *working* but fake one.

1. Add `ALLOW_SIMULATION=false` as the default. When false, the orchestrator and MCP servers refuse to start with simulated SPIRE, HMAC tokens, or committed keys. Simulation moves behind an explicit `demo` profile.
2. Delete the fallback chain in `tokenExchange.js`: no password grant, no client-credentials downgrade, no locally signed Entra/Google tokens. A failed exchange returns an error and halts the turn (I4, I5, G5).
3. Remove the `simulate_rogue_actor` branch from production code; move to a test-only helper (I7).
4. Stop returning `rawToken`, SVID and full claims to the browser. Return a redacted lineage summary (subject, actor chain, audiences, scopes, expiry) (I6).
5. Remove committed private keys from the repo and history; rotate anything that was used outside a laptop. Remove default secrets from code and manifests (I8, I9).
6. Strip or ignore `X-Delegated-Identity`. The user comes only from the verified token (A4).
7. Parameterize BigQuery queries (T4), and make `aud` mandatory with exact-match comparison (A5).

### Phase 1: Real identity foundation (1-2 weeks)

1. **User authentication.** Replace `/api/login` with OIDC authorization code + PKCE against the IdP (pick one: Entra or Keycloak, see Decision D1). Disable direct grants and ROPC. Drop hard-coded users, passwords and client secrets from the realm config (I1, I3).
2. **Verify the user token** in the orchestrator: JWKS signature, `iss`, `aud=orchestrator`, `exp`, and required scope. Reject on any failure (I2).
3. **Real SPIRE JWT-SVIDs** via the Workload API (e.g. `spiffe` / `@spiffe/spiffe-js` client). Fail if the socket is absent (A1).
4. **Exact SPIFFE allow-list.** Replace prefix checks with a configured list of exact IDs per MCP server (A3).
5. Make the IdP the **only** token-exchange authority (RFC 8693): subject = verified user token, actor = JWT-SVID, `resource`/`audience` = one MCP server, scope = one tool scope. The IdP, not the orchestrator, stamps `act`. The orchestrator stops signing any token (A2).

### Phase 2: Google Cloud (1-2 weeks)

1. **Human access via Workforce Identity Federation** with the same IdP. Users appear as `principal://iam.googleapis.com/locations/global/workforcePools/<pool>/subject/<id>` (G3). Remove Alice/Bob grants from the workload pool.
2. **Keep the workload pool for the agent/MCP workloads only**, with an `attribute_condition` such as `assertion.iss == "<spire issuer>" && assertion.sub == "spiffe://…/gcp-mcp"` and a pinned `allowed_audiences` (G2). Replace `principalSet …/*` with a single `principal://…/subject/<spiffe id>` (G1).
3. **Where the downscoping happens: inside the GCP MCP server**, not the orchestrator.
   - Receive a token with `aud=gcp-mcp`.
   - Exchange the user's IdP token at Google STS (workforce provider) for a federated access token.
   - Perform the second exchange with `options` carrying the CAB (resource `//bigquery.googleapis.com/projects/<number>/datasets/<ds>/tables/<t>`, role `inRole:roles/bigquery.dataViewer`, condition built with project **number**) (G5, G6).
   - Call BigQuery with that token only. Remove the `GCP_ACCESS_TOKEN`/metadata-server fallbacks (G7).
   - **Check before building:** confirm that your BigQuery operations are supported by CAB. If not, use dataset/table-level IAM and BigQuery row-level or column-level security with the user's own federated identity as the enforcement point, plus an IAM condition.
4. **Replace token-based verification (G8)**: the MCP server verifies the IdP-issued token (JWKS), and Google verifies the STS-exchanged one. Delete `google-sts-*.pem`.
5. **IAM:** dataset-scoped `roles/bigquery.dataViewer` for the analytics dataset only; a separate dataset-scoped role (or authorized view) for `audit_logs`, granted to a distinct group (G4, G9). `jobUser` only where queries run. Drop `bigquery.admin` from user principals.
6. Attribute agent actions: set BigQuery job labels from the verified `act` chain (SPIFFE ID, correlation ID) and enable Data Access audit logs for BigQuery, STS and IAM Credentials. Note that Google STS does not carry an `act` claim, so lineage lives in labels and logs, not in the token.

### Phase 3: Azure (about 1 week)

1. Replace `ENTRA_CLIENT_SECRET` with a **federated client assertion** (client_assertion = SPIFFE JWT-SVID, using the existing federated identity credential) for the orchestrator's token request (Z1).
2. Move the OBO step to the **Azure MCP server** (it receives `aud=azure-mcp` and exchanges to `https://storage.azure.com/user_impersonation`). The Storage call then carries the user's own Storage token, so Azure RBAC enforces the decision. Remove the "JIT user delegation" metadata theatre, or implement real user delegation SAS scoped to one blob, 60s, read-only (Z3).
3. Least privilege on Storage: `Storage Blob Data Reader` at container scope for the agent's managed identity; users get their own per-container role assignments (Z2). Define fine-grained delegated scopes (`Mcp.Storage.ReadApp1`, `Mcp.Storage.ReadApp2`, `Mail.Send` as a separate, gated app) instead of `user_impersonation`.
4. Remove string-matched authorization (`includes('alice')`) and the "allow if no `azp`/`act`" clause (T3, Z4).
5. Storage hardening: disable shared-key access, restrict public network access/private endpoint, enable diagnostic logs (Z5).
6. CI: GitHub OIDC federation instead of `AZURE_CREDENTIALS`; add or remove the missing `foundry-deploy.sh` (Z6).

### Phase 4: Agent-specific controls (1-2 weeks)

1. **Real policy engine.** Run OPA (sidecar or in-process WASM) using the `.rego` as the single source of truth; delete the JS reimplementation (T1). Policy input: verified user, group/role, actor SPIFFE ID, tool, validated arguments, target resource, time, risk tier. Default deny.
2. **Tool contracts.** JSON-Schema validation of every tool call's arguments; allow-lists for container/file, dataset/table/columns/region; parameterized queries only; row and byte caps (T2, T4, T7).
3. **Treat model output and tool results as untrusted.** Keep authorization out of the prompt; strip or quarantine tool outputs before they re-enter the planner; do not let tool output influence which tools or recipients are chosen (T5).
4. **Human-in-the-loop** for high-impact actions (send mail, any write, any external recipient): the orchestrator returns a pending-approval state and the user confirms through the authenticated UI (T6).
5. **Per-request budgets**: max turns, tool calls, rows, tokens, wall-clock; per-user rate limits.
6. **Swap the simulator for a real model behind a fixed tool interface** once Phases 1-3 land, and keep the simulator for deterministic tests only.

### Phase 5: Platform, observability, verification (ongoing)

1. Istio: `PeerAuthentication` STRICT; `AuthorizationPolicy` allowing only `frontend -> orchestrator` and `orchestrator -> MCP` by SPIFFE principal; deny everything else (P1). Add `NetworkPolicy` and egress allow-lists (P2).
2. Pod hardening: non-root, read-only root FS, drop all capabilities, resource limits, secrets via the cluster secret store (not ConfigMaps/env literals).
3. Remove `/api/tools/:name` or put it behind the same verifier; make the health endpoints return only status (P3).
4. Structured audit events (who, via which agent, which tool, which resource, decision, correlation ID) written to an append-only sink; redact tokens from all logs (P4).
5. Tests that exercise real enforcement (P5): run the verifiers against a local IdP (Keycloak/mock JWKS) and assert rejection for wrong `iss`, wrong `aud`, expired, `alg:none`/HS256, tampered `act`, missing `act`, forged delegated header, SQL injection in arguments, and a prompt-injected tool result. Add one gated end-to-end test per cloud against a sandbox tenant/project.

## 5. Acceptance criteria

- No code path produces a token the cloud or the MCP server accepts without a successful call to the real IdP/STS. Starting with simulation disabled and the IdP unreachable yields errors, not tokens.
- A forged user token, a forged `X-Delegated-Identity`, or an unlisted SPIFFE ID is rejected by the orchestrator and by both MCP servers.
- Deleting an app-layer role check does not widen access: Azure RBAC and Google IAM/CAB still deny the user.
- The GCP workload pool provider has an attribute condition, the service-account binding names one principal, and BigQuery roles are dataset-scoped.
- Each exchanged token has exactly one audience, one tool scope, and a lifetime of 5 minutes or less.
- Browser responses contain no bearer tokens.
- Tool calls that send mail or write data require an explicit approval event.
- The test suite includes the negative cases in 4.5.5, and CI runs them.

## 6. Decisions needed

- **D1: One IdP or two?** Recommended: Entra as the single user IdP and token-exchange authority if Azure is already the primary tenant; otherwise Keycloak for both clouds. Running both with ad hoc exchange between them is the main source of the current complexity.
- **D2: GCP user model.** Workforce federation (recommended) versus a service account with per-request authorization at the MCP layer. The second is simpler but gives up Google-side per-user enforcement.
- **D3: Keep the simulation profile?** If yes, it must be a separate build/profile that cannot start in a cluster namespace labelled production.
- **D4: Approval UX** for high-impact tools (inline confirmation versus out-of-band).

## 7. Suggested order and effort

| Phase | Effort | Depends on |
|---|---|---|
| 0 Stop failing open | 2-3 days | none |
| 1 Identity foundation | 1-2 weeks | D1 |
| 2 Google Cloud | 1-2 weeks | 1, D2 |
| 3 Azure | about 1 week | 1 |
| 4 Agent controls | 1-2 weeks | 1 (partly parallel with 2-3) |
| 5 Platform and verification | ongoing | each phase adds its own tests |
