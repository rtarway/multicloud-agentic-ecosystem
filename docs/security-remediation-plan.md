# Security Remediation Plan: Aligning with Agentic-Ecosystem Best Practices

Scope: `user prompt -> web-frontend -> agent-orchestrator (SPIRE/Istio) -> Azure MCP server / GCP MCP server`.

Companion document: [`poc-setup-guide.md`](./poc-setup-guide.md) lists the manual steps (tenant, project and console actions) that Terraform and scripts cannot do.

Principles the plan is measured against: least privilege, audience-bound and downscoped tokens, a real on-behalf-of chain that keeps user and agent separate, no token passthrough (MCP authorization spec), verified identity at every hop, tool authorization independent of the LLM, minimal credential storage, and auditable lineage.

## 1. Assumptions

**Real enterprise (not built by this project):**
- Users, groups and role assignments are synced from the enterprise IdP into Entra ID and into Google (Cloud Identity). That sync has run for years and is owned by other teams.
- Azure is federated to the enterprise IdP. Entra sign-in is silent with an enterprise SSO session.
- Google IAM is bound to the synced Google identities (`user:` or groups). **Workforce Identity Federation is not wanted by other teams.** The agent therefore acts as the user's own Google identity.
- Cloud permissions already exist. This project must not copy them into app-level role tables.

**This POC (local Rancher Desktop, no enterprise org):**
- The enterprise sync does not exist, so the POC includes an **identity-seed step** that provisions the same test users into Keycloak, an Entra test tenant and Google accounts from one source file. It is a stand-in for the sync, nothing more.
- Keycloak stands in for the enterprise IdP.
- Entra federation to Keycloak is not available in the test tenant. The POC uses an interactive Entra sign-in at login (auth code + PKCE) as a stand-in for the silent federated sign-in.
- Google has no organization. The POC uses an external OAuth client in Testing mode with real Google accounts added as test users. See the setup guide.

Everything marked *POC stand-in* below is replaced by configuration, not code changes, in the enterprise.

## 2. What the code does today

1. `web-frontend` `/api/login` does not authenticate anyone. It picks a canned user, then **mints** a Keycloak token (HS256, shared secret), an Entra-looking token and a Google-looking token, and returns all of them to the browser (`app/web-frontend/src/index.js:76-215`).
2. `agent-orchestrator` `/api/agent/chat` **decodes but never verifies** the user token (`index.js:204-223`). A keyword-matching "LLM simulator" picks the tools (`llmSimulator.js`). A JS reimplementation of the policy ("OPA") gates them (`opaPolicy.js`).
3. `tokenExchange.js` builds the per-cloud token:
   - **Azure:** real Entra OBO if a user assertion and client secret exist; otherwise a password grant with a hard-coded password, then client-credentials, then a locally signed "Entra" token.
   - **GCP:** a malformed STS call. When it fails, it signs a fake `iss: sts.googleapis.com` token with a committed key.
4. The MCP servers verify those self-signed tokens against committed certs, then decide access with string checks such as `userUpn.includes('alice')`.
5. The orchestrator returns raw tokens, SVIDs and full claims to the browser in every response.
6. Identities are seeded inconsistently: users and plaintext passwords in `k8s/keycloak/keycloak-realm-configmap.yaml`; no Entra user provisioning in Terraform (`azure/main.tf`, `scripts/setup-entra-wif.sh`); Google grants to workload-pool `principal://` subjects (`terraform/gcp/main.tf:118-136`).

The design intent (SPIFFE agent identity, `act` chain, scope intersection, per-resource policy) is right. The gap is that most enforcement is simulated, and the simulation fails open.

## 3. Target architecture

```
Enterprise IdP (Keycloak in POC) --OIDC code+PKCE--> Browser/BFF        user authn, MFA, consent-required scopes
BFF session (opaque cookie)  -->  Orchestrator                          verifies user token (JWKS: iss, aud, exp, scope)
Orchestrator (real SPIRE JWT-SVID)
   |- RFC 8693 exchange at the IdP: subject=user token, actor=orchestrator identity,
   |    audience=ONE MCP server, scope=ONE tool scope  ->  ttl <= 5 min, sub=user, act=agent
   |
   |- Azure MCP  (aud=azure-mcp)
   |     Entra OBO (client assertion = SPIFFE JWT-SVID, no client secret)
   |     -> Storage token for the user -> Azure RBAC decides (synced roles)
   |
   `- GCP MCP    (aud=gcp-mcp)
         MCP server is the OAuth client to Google for this user:
         - first use: returns authorization_required + link; user consents once (SSO, silent if app is admin-trusted)
         - MCP holds the user's grant (encrypted, per user), mints 1h access tokens per call
         -> BigQuery as the user's own Google identity -> Google IAM decides (synced roles)
```

Rules that hold throughout:
- Each MCP server accepts only tokens minted for it and performs its own downstream exchange. No token is forwarded to a different audience.
- The cloud's native IAM is the final authority. Roles the cloud already holds are not duplicated. MCP-layer checks are defence in depth only.
- The orchestrator, browser and LLM never hold a cloud token that can reach data directly, except the short-lived Entra assertion described in Phase 3.
- A policy engine outside the LLM decides whether a tool call is allowed. Model output and tool results are untrusted input.
- Effective access = user's synced cloud permissions ∩ scopes the user consented to for the agent ∩ tool policy.

## 4. Credential and consent model

**Three different consents, kept separate:**

| Consent | Who grants | Where it lives |
|---|---|---|
| Cloud app consent (Entra delegated permissions for orchestrator/MCP apps) | Tenant admin, once | Entra (admin consent, pre-authorized client). No user prompts. |
| Google OAuth app trust | Workspace/Cloud Identity admin | Admin console app access control (Internal app, marked Trusted, limited to OUs/groups). In POC (external, Testing mode) test users see a consent screen once. |
| Agent delegation consent: "this agent may act for me for scopes X, until Y" | The user | Keycloak consent-required optional client scopes. Revocable by the user. Consent version is written to the audit trail on every exchange. |
| Per-action approval for high-impact actions (mail, writes, audit data) | The user, at the time | Orchestrator returns `approval_required`; the UI confirms; the approval is bound to the exact action. |

**Storage rules:**
- Nothing is stored in the browser. The BFF keeps an opaque cookie session.
- Access tokens live in memory with a TTL no longer than the token, keyed by (user, audience, scope).
- **The only persisted credential** is the user's Google grant (refresh token) at the **GCP MCP server**:
  - One secret per user, encrypted with a KMS key (CMEK), readable only by the MCP's own identity.
  - Narrow scope (`bigquery.readonly` plus `openid email`), not `cloud-platform`.
  - Purged on logout, consent revoke, and IdP deprovision. Account suspension in the synced directory also invalidates it.
  - Never logged. Rotation handled by Google's refresh behaviour.
- The callback must verify that the Google `email` in the ID token equals the email mapped from the verified Keycloak `sub`. Otherwise one user could link another user's Google account.
- If policy forbids stored refresh tokens: the BFF runs the Google flow with `prompt=none`, `access_type=online`, seals the 1-hour access token to the GCP MCP's public key (JWE), and the orchestrator forwards it as an opaque blob. This is interactive-only, with no background jobs.

**Step-up is a protocol, not stored state:** a resource or cloud rejects with a challenge (Entra `insufficient_claims`; RFC 9470 `insufficient_user_authentication`; `insufficient_scope`; Google reauthentication / session-length / Context-Aware Access errors). The orchestrator maps it to `step_up_required`, the UI performs an interactive re-auth at the IdP (`acr=mfa`, `max_age=0`), and the orchestrator retries. High-impact actions use action-bound approval (RFC 9396 rich authorization requests, or CIBA when the user is away).

## 5. Gap analysis

Severity: **C** critical (fails open or breaks the trust model), **H** high, **M** medium.

### 5.1 Identity and authentication

| # | Finding | Evidence | Sev |
|---|---|---|---|
| I1 | Frontend mints tokens itself; no real login. Passwords and a shared HMAC secret are in code | `web-frontend/src/index.js:33-64, 91-106` | C |
| I2 | Orchestrator trusts unverified user tokens | `agent-orchestrator/src/index.js:204-223` | C |
| I3 | Keycloak realm ships plaintext user passwords, a client secret, direct-grant enabled, public client | `k8s/keycloak/keycloak-realm-configmap.yaml:38,55,120-150` | H |
| I4 | Password-grant fallback with hard-coded password to get a user token for any `userEmail` | `tokenExchange.js:386-410` | C |
| I5 | Fallback chain silently degrades from user-delegated to app-only | `tokenExchange.js:433-440` | C |
| I6 | Raw user, SVID and exchanged tokens returned to the browser | `index.js` (`hopToHop.*.rawToken`) | H |
| I7 | A `simulate_rogue_actor` / "tamper" branch is in the production request path | `index.js:1128-1139` | M |
| I8 | Hard-coded default secrets in code and in `k8s/gcp-mcp-server-deployment.yaml` | several | H |
| I9 | Committed private keys | `certs/*-key.pem` | H |
| I10 | Users are seeded differently in each IdP; no single source and no identity-mapping function | see section 2, item 6 | H |
| I11 | Keycloak 24.0.4 with the legacy preview `token-exchange` feature; it does not natively accept `actor_token` or emit `act` (verify) | `terraform/keycloak.tf` | H |

### 5.2 Agent identity and delegation

| # | Finding | Evidence | Sev |
|---|---|---|---|
| A1 | The SVID is HMAC-signed locally; the SPIRE Workload API is never called | `spireClient.js:27-48` | C |
| A2 | The `act` chain is built and signed by the orchestrator itself | `tokenExchange.js:135-165` | H |
| A3 | Downstream "trusted actor" is any `spiffe://example.org/ns/*` or `urn:agent:*` | `gcp-mcp-server/src/auth.js:148-175`, `mcp-server/src/auth.js:108-131` | H |
| A4 | `X-Delegated-Identity` header can override the token's user | `gcp-mcp-server/src/auth.js:211-229`, `mcp-server/src/auth.js:179-198` | C |
| A5 | Missing `aud` accepted; any audience containing `gcp` or `run.app` passes | `gcp-mcp-server/src/auth.js:116-117` | H |
| A6 | One broad OBO scope (`user_impersonation`) covers every tool | `tokenExchange.js:430` | M |

### 5.3 Tool authorization and prompt handling

| # | Finding | Evidence | Sev |
|---|---|---|---|
| T1 | The policy is JS, not OPA; the `.rego` file is never evaluated and disagrees with the JS | `opaPolicy.js`, `orchestrator_policy.rego` | H |
| T2 | Policy only checks a weekend rule and a tool allow-list; nothing about user, arguments or data sensitivity | `opaPolicy.js:28-81` | H |
| T3 | Role logic uses string matches (`includes('alice')`, `includes('bob')`) | `mcp-server/src/auth.js:155`, `azureStorage.js:78-79` | C |
| T4 | Tool arguments unvalidated; values reach SQL by string interpolation | `bigqueryClient.js:129` | C |
| T5 | Tool outputs flow back into the LLM context with no trust boundary | pipeline Turn 3 | H |
| T6 | `Mail.Send` to an external address executes with no human approval | `index.js:819-960` | H |
| T7 | No per-request budgets (turns, calls, rows, bytes) | n/a | M |

### 5.4 Google Cloud

| # | Finding | Sev |
|---|---|---|
| G1 | Real identities are not used. Users are modelled as workload-pool subjects with direct project-level `bigquery.admin`/`dataViewer` (`terraform/gcp/main.tf:118-136`) | H |
| G2 | `roles/iam.workloadIdentityUser` bound to `principalSet://…/k8s-agent-pool/*` and a provider with no attribute condition (`main.tf:28-44, 111`, `setup-gcp-wif.sh:109,141`). The pool is no longer needed in the target design, so retire it | H |
| G3 | The STS call is malformed (invalid `access_boundary` parameter, non-JWT actor token, 2s timeout hiding failures) (`tokenExchange.js:303-322`) | H |
| G4 | The BigQuery client never uses a user credential. It uses `GCP_ACCESS_TOKEN`, then the Cloud Run service account's metadata token | C |
| G5 | The MCP server verifies a self-signed "Google STS" token; real STS tokens are opaque and cannot be verified this way (`gcp-mcp-server/src/auth.js`, `certs/google-sts-*.pem`) | C |
| G6 | BigQuery roles granted at project level, not dataset level | H |
| G7 | Audit-log access decided from a token claim rather than Google IAM (`bigqueryClient.js:247-257`) | H |
| G8 | Credential Access Boundary targets a nonexistent table (`audit_logs.access_audit`) and uses project ID where project number is required | M |

### 5.5 Azure

| # | Finding | Sev |
|---|---|---|
| Z1 | Orchestrator uses a client secret for OBO (`ENTRA_CLIENT_SECRET`) although it already holds a SPIFFE JWT-SVID | H |
| Z2 | The managed identity has `Storage Blob Data Contributor` on both containers (`azure/main.tf:61-72`); read tools need Reader | H |
| Z3 | The Storage call sends the MCP-audience token to blob storage (aud mismatch) and labels it "JIT user delegation"; no real user delegation key or SAS exists (`azureStorage.js:29-71, 108-110`) | H |
| Z4 | The sender check passes a token with no `azp` and no `act` (`mcp-server/src/auth.js:111`) | H |
| Z5 | Storage account network access open, shared key not disabled | M |
| Z6 | CI deploys with `AZURE_CREDENTIALS` (long-lived secret) and calls `foundry-deploy.sh`, which is not in the repo (`.github/workflows/deploy-mcp.yml`) | M |

### 5.6 Platform, mesh and observability

| # | Finding | Sev |
|---|---|---|
| P1 | Istio is installed with SPIRE certs but no `PeerAuthentication` (STRICT) or `AuthorizationPolicy` | H |
| P2 | No `NetworkPolicy`, egress control or pod hardening | M |
| P3 | MCP servers expose a REST bypass (`/api/tools/:name`) with weaker handling than `/mcp` | M |
| P4 | Logs print token contents and user identifiers; no tamper-evident audit sink | M |
| P5 | Tests assert behaviour against mocks and committed keys, so a green suite proves little about real enforcement | M |

## 6. Remediation plan

Each phase ends in a verifiable state. Phases 0-2 block everything else.

### Phase 0: Stop failing open (2-3 days)

**Status: implemented.** Notes on how, and what is deliberately left:
- `ALLOW_SIMULATION` (default off) is enforced by `shared/simulation.js`, vendored into each app by `scripts/sync-shared.sh`. Services that have no real path yet (orchestrator, GCP MCP) refuse to start without it; the others fail closed per request. The production guard keys off `DEPLOYMENT_ENV=production`, not `NODE_ENV`, because the images always set `NODE_ENV=production`.
- Demo keys come from `shared/demoKeys.js` (env, `.demo-keys/`, or generated in memory). `certs/*-key.pem` and `certs/*-cert.pem` were removed from the tree. **They still exist in git history**: the owner should rewrite history (for example `git filter-repo --path certs/azure-test-key.pem --path certs/google-sts-key.pem --invert-paths`) or treat them as compromised. They were demo keys; nothing is rotated because nothing real used them.
- `scripts/check-no-secrets.sh` (run by `scripts/test-all.sh`) fails the build if private keys or the known default secrets reappear.
- Remaining by design until later phases: the demo login in `web-frontend` (Phase 2), the Keycloak realm file with demo credentials (Phase 1), loose actor prefix checks (Phase 2), the metadata-server token fallback in the BigQuery client (Phase 4), and the `/api/tools/:name` REST path (Phase 7).

1. Make `ALLOW_SIMULATION=false` the default. When false, the orchestrator and MCP servers refuse to start with simulated SPIRE, HMAC tokens or committed keys. Simulation moves behind an explicit `demo` profile.
2. Delete the fallback chain in `tokenExchange.js`: no password grant, no client-credentials downgrade, no locally signed Entra/Google tokens. A failed exchange returns an error and halts the turn (I4, I5, G3).
3. Remove the `simulate_rogue_actor` branch from production code; move it to a test helper (I7).
4. Stop returning `rawToken`, SVID and full claims to the browser. Return a redacted lineage summary (I6).
5. Remove committed private keys and default secrets from the repo and history; rotate anything used outside a laptop (I8, I9).
6. Ignore `X-Delegated-Identity`; the user comes only from the verified token (A4).
7. Parameterize BigQuery queries (T4); make `aud` mandatory with exact-match comparison (A5).

### Phase 1: Identity seed and mapping (POC stand-in for the enterprise sync) (3-5 days)

**Status: implemented** (see [`poc-setup-guide.md`](./poc-setup-guide.md), section 5, for how to run it). What exists:
- `identity/users.yaml` (single source, no secrets), validated by `identity/lib/directory.js`, with the derived `identity/identity-map.json` generated by `scripts/identity-build-map.js` and checked for staleness in `test-all.sh`.
- `terraform/identity/{keycloak,entra,google}` plus a shared `modules/directory`. All four `terraform validate` cleanly against the pinned providers, and the module and Google root were exercised with `terraform plan` (including the placeholder-account guard and the offboard variable). The Keycloak and Entra roots could not be planned here because that needs live credentials; their first real apply is the remaining verification.
- `terraform/keycloak.tf` no longer imports a realm file or uses `admin/admin`; the admin password comes from `TF_VAR_keycloak_admin_password` (generated into the git-ignored `.env.keycloak` by `install-infra.sh`). `k8s/keycloak/keycloak-realm-configmap.yaml` (plaintext demo credentials) was deleted.
- `shared/identityMapping.js` (vendored into the orchestrator, GCP MCP and Azure MCP): fails closed on unverified, unknown, disabled or ambiguous identities, maps only by verified email, and exposes `googleAccountMatches` for the Phase 4 callback check. **It is not yet called from the request paths**; Phases 2-4 wire it in where the flows change.
- `scripts/identity-check.js` (offline by default, `--live` for Keycloak/Entra/BigQuery) and `scripts/identity-offboard.js` (dry-run by default; Terraform applies in all three roots, Keycloak session logout, grant-purge hook).
- Decision recorded: eligibility for an agent scope is modelled as a realm role per scope (granted through groups) plus Keycloak optional client scopes with consent required on the `web-frontend` client; the token carries `roles` and `groups` claims, and Phase 5 enforces roles ∩ consented scopes at exchange time.

Goal: the same test users, groups and roles exist in Keycloak, Entra and Google, defined once.

1. **Single source:** `identity/users.yaml` (users, groups, membership, per-cloud role mapping). No passwords in the repo.
2. **Keycloak** (Terraform Keycloak provider): realm, groups, users, clients, and consent-required optional scopes (`mcp:tool1`, `mcp:tool2`, `mcp:bigquery:query`, `mcp:bigquery:audit`, `Mail.Send`). Direct grants disabled. Remove the realm ConfigMap with plaintext credentials (I3).
3. **Entra** (`azuread` provider): users, groups, membership, app registrations for orchestrator and both MCPs with exposed API scopes, pre-authorized clients and admin consent. Storage roles assigned to **groups** (Z2).
4. **Google** (`google` provider): dataset-scoped BigQuery roles bound to the test users' Google emails or groups. Terraform cannot create Google accounts or OAuth test users; those are manual (see the setup guide).
5. **Identity-mapping function** (one module, used by orchestrator and MCP servers): verified Keycloak `sub` -> Entra identity and Google email. It fails closed on a missing mapping or an unverified email (I10).
6. **Consistency script:** checks that every user resolves in all three systems and that the mapping returns the expected identities.
7. **Offboard target:** disables a user in all three systems and triggers the token purge, so deprovisioning can be tested.

### Phase 2: Real identity foundation (1-2 weeks)

1. **User authentication:** replace `/api/login` with OIDC authorization code + PKCE against Keycloak through a server-side BFF session. No tokens in the browser (I1).
2. **Verify the user token** in the orchestrator: JWKS signature, `iss`, `aud=orchestrator`, `exp`, required scope. Reject on any failure (I2).
3. **Real SPIRE JWT-SVIDs** from the Workload API; refuse to start if the socket is absent (A1).
4. **Exact SPIFFE allow-list** per MCP server instead of prefix checks (A3).
5. **Token exchange at the IdP** (RFC 8693): subject = user token, audience = one MCP server, one tool scope, TTL 5 minutes or less. The orchestrator stops signing tokens (A2).
   - **Check before building (I11):** Keycloak's exchange does not natively take an `actor_token` or emit `act` as far as I know. Upgrade to Keycloak 26.2 or later (Standard Token Exchange, not the legacy preview feature), then emit `act` through a client-bound protocol mapper that reads the exchanging client's SPIFFE ID attribute. Multi-hop chains need a custom SPI. If that is too heavy for the POC, keep the chain as a signed, verified claim in a separately signed delegation token and document it as a POC stand-in.

### Phase 3: Azure (about 1 week)

1. Replace `ENTRA_CLIENT_SECRET` with a **client assertion** signed as the SPIFFE JWT-SVID, using the existing federated identity credential. This needs the SPIRE OIDC issuer to be publicly reachable (existing `scripts/publish-spire-oidc.sh`) (Z1).
2. **Entra sign-in:**
   - *POC stand-in:* interactive Entra auth code + PKCE at login, requesting `api://<orchestrator>/access_as_user`.
   - *Enterprise:* the same flow with `prompt=none`, silent through the federated domain.
   - Remove the ROPC/password fallback entirely.
3. The orchestrator performs OBO to the Azure MCP audience. The **Azure MCP performs a second OBO to `https://storage.azure.com`** so Azure RBAC decides, on the user's synced roles. Remove the "JIT user delegation" metadata theatre, or implement a real user delegation SAS (single blob, 60s, read-only) (Z3).
4. Replace `user_impersonation` with fine-grained delegated scopes (for example `Mcp.Storage.ReadApp1`, `Mcp.Storage.ReadApp2`); `Mail.Send` is a separate gated permission (A6).
5. Remove string-matched authorization and the "allow if no `azp`/`act`" clause (T3, Z4).
6. Storage hardening: disable shared key, restrict public network access, enable diagnostic logs (Z5). CI: GitHub OIDC instead of `AZURE_CREDENTIALS`; add or remove the missing `foundry-deploy.sh` (Z6).

### Phase 4: Google Cloud (1-2 weeks)

1. **Retire** the workload identity pool, provider, service-account impersonation binding and user principal grants in `terraform/gcp/main.tf` and `setup-gcp-wif.sh` (G1, G2).
2. **MCP-side OAuth client** (see section 4): OAuth web client with minimal scopes; `/oauth/google/start` and `/oauth/google/callback` on the GCP MCP; signed `state` bound to the user's `sub`; email-equality check against the identity-mapping function; PKCE.
3. **Grant vault:** per-user secret encrypted with a KMS key; the MCP's service account gets access scoped by an IAM condition on the secret name prefix; purge on logout/revoke/offboard.
4. **Authorization-required flow:** when no valid grant exists, the tool returns `authorization_required` with a link; the orchestrator surfaces it to the UI; after consent the call is retried.
5. **Use the user credential:** the BigQuery client uses only the user's access token. Remove the `GCP_ACCESS_TOKEN` and metadata-server fallbacks (G4). Delete `google-sts-*.pem` and the STS/CAB code (G3, G5, G8).
6. **IAM:** dataset-scoped `roles/bigquery.dataViewer` on the analytics dataset only; a separate dataset-scoped role (or authorized view) for `audit_logs` granted to a different group. Remove project-level and `bigquery.admin` grants for users (G6, G7).
7. **Agent boundary:** the user's synced access is the ceiling, so narrow what the agent can do: the OAuth scope, a tool allow-list with dataset/table/region checks, parameterized queries, row and byte caps, and per-action approval. Credential Access Boundary downscaling of a user's access token may be possible, but verify that before relying on it.
8. **Attribution:** set BigQuery job labels from the verified `act` chain (agent ID, correlation ID) and enable Data Access audit logs, since the token itself will not carry `act`.

### Phase 5: Consent, step-up and token handling (about 1 week)

1. Keycloak consent-required optional scopes drive the agent delegation consent; the exchange denies a scope the user has not consented to. Write the consent version to every audit record.
2. Implement `step_up_required` and `approval_required` as first-class orchestrator states and UI flows. Map Entra claims challenges, RFC 9470, `insufficient_scope`, and Google reauthentication errors onto them.
3. Action-bound approval for mail, writes and audit access.
4. Offboarding and revoke handlers purge stored grants and sessions.

### Phase 6: Agent controls (1-2 weeks, parallel with phases 3-4)

1. **Real policy engine:** run OPA from the `.rego` as the single source of truth and delete the JS reimplementation (T1). Input: verified user, group, actor SPIFFE ID, tool, validated arguments, target resource, time, risk tier. Default deny.
2. **Tool contracts:** JSON-Schema validation of arguments; allow-lists for container/file and dataset/table/columns/region; parameterized queries only; row and byte caps (T2, T4, T7).
3. **Untrusted outputs:** quarantine tool results before they re-enter the planner; tool output must not influence tool or recipient selection (T5).
4. **Per-request budgets** (turns, tool calls, rows, tokens, wall-clock) and per-user rate limits.
5. **Replace the simulator with a real model** behind a fixed tool interface once phases 2-4 land; keep the simulator for deterministic tests only.

### Phase 7: Platform, observability, verification (ongoing)

1. Istio `PeerAuthentication` STRICT and `AuthorizationPolicy` allowing only `frontend -> orchestrator` and `orchestrator -> MCP` by SPIFFE principal (P1). `NetworkPolicy` and egress allow-lists (P2).
2. Pod hardening (non-root, read-only root FS, dropped capabilities, resource limits); secrets from the cluster secret store, not ConfigMaps or env literals.
3. Remove `/api/tools/:name` or put it behind the same verifier; health endpoints return status only (P3).
4. Structured audit events (user, agent, tool, resource, decision, consent version, correlation ID) written to an append-only sink; tokens never logged (P4).
5. Negative tests (P5): wrong `iss`, wrong or missing `aud`, expired, `alg:none`/HS256, tampered or missing `act`, forged delegated header, mismatched Google email on callback, SQL injection in arguments, prompt-injected tool result, unconsented scope, revoked grant, offboarded user. One gated end-to-end test per cloud.

## 7. Acceptance criteria

- No code path produces a token the cloud or an MCP server accepts without a successful call to the real IdP or cloud. With simulation disabled and the IdP unreachable, the system returns errors, not tokens.
- A forged user token, a forged `X-Delegated-Identity`, an unlisted SPIFFE ID, or a Google callback whose email does not match the mapped user is rejected.
- Removing an app-layer role check does not widen access: Azure RBAC and Google IAM still deny the user.
- Each exchanged token has exactly one audience, one tool scope, and a lifetime of 5 minutes or less.
- Browser responses contain no bearer tokens.
- The only persisted credential is the per-user Google grant at the GCP MCP, and it is deleted on logout, revoke and offboard.
- Tool calls that send mail or write data require an explicit approval event.
- The seed produces the same user set in Keycloak, Entra and Google, and the consistency script passes.
- The test suite includes the negative cases in Phase 7 and CI runs them.

## 8. Decisions

Resolved:
- **IdP:** Keycloak is the enterprise IdP stand-in; Entra and Google are downstream resource IdPs.
- **Google model:** the agent acts as the user's own Google identity via a per-user OAuth grant held by the GCP MCP. No Workforce Federation.
- **Identity sync:** out of scope in production; Phase 1 provisions it for the POC.

Still open:
- **D1: Stored refresh token or sealed online token for Google?** The stored grant (default here) supports background jobs; the sealed online token stores nothing but is interactive-only.
- **D2: Keycloak upgrade.** Moving from 24.0.4 to 26.2+ is recommended for standard token exchange. Confirm it is acceptable for the POC.
- **D3: Simulation profile.** Keep it? If yes, make it a separate profile that cannot start in a production-labelled namespace.
- **D4: Approval UX** for high-impact tools: inline confirmation or out-of-band.

## 9. Order and effort

| Phase | Effort | Depends on |
|---|---|---|
| 0 Stop failing open | 2-3 days | none |
| 1 Identity seed and mapping | 3-5 days | setup guide steps done |
| 2 Identity foundation | 1-2 weeks | 1, D2 |
| 3 Azure | about 1 week | 2 |
| 4 Google Cloud | 1-2 weeks | 2, D1 |
| 5 Consent, step-up, tokens | about 1 week | 2-4 |
| 6 Agent controls | 1-2 weeks | 2 (parallel with 3-4) |
| 7 Platform and verification | ongoing | each phase adds its own tests |
