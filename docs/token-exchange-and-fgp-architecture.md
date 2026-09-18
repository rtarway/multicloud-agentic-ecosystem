# Standardized RFC 8693 Token Exchange & Fine-Grained Policy (FGP) Architecture

## 1. Executive Summary

This document addresses three critical enterprise requirements for scaling agentic AI workloads across multi-cloud and SaaS environments:

1. **Standardized, Off-the-Shelf RFC 8693 Token Exchange**: Eliminating custom in-application token exchange engines by utilizing standard Identity Providers (IdPs) like **Keycloak** or **Ory Hydra** with full **RFC 7523** compliance (SPIRE JWT-SVID as client/actor assertions).
2. **Generic Cross-Cloud Identity Federation**: Using standard token exchange to access **AWS**, **GCP**, **Azure**, and **Anthropic/LLM APIs** without hardcoding cloud-specific credentials.
3. **Decoupled Governance: Coarse-Grained Policy (CGP) at the IdP vs. Fine-Grained Policy (FGP) with Open Policy Agent (OPA) in MCP Servers**: Defining declarative FGP in `tools.yaml` and enforcing it at tool runtime.

---

## 2. Off-the-Shelf RFC 8693 & RFC 7523 Token Exchange with Standard IdPs

```mermaid
graph LR
    subgraph K8s["Kubernetes Cluster"]
        Workload["Agent Workload<br/>(SPIFFE Identity)"]
        SpireAgent["SPIRE Agent<br/>(OIDC Provider)"]
        Keycloak["Keycloak IdP<br/>(RFC 8693 + RFC 7523 Enabled)"]
    end

    subgraph Clouds["Target Cloud & SaaS Providers"]
        AWS["AWS STS<br/>(AssumeRoleWithWebIdentity)"]
        GCP["GCP STS<br/>(Workload Identity Federation)"]
        Azure["Azure Entra ID<br/>(Workload Identity Federation)"]
        Anthropic["Anthropic Claude<br/>(via Bedrock, Vertex, or AI Gateway)"]
    end

    Workload -->|1. Fetch JWT-SVID| SpireAgent
    Workload -->|2. RFC 8693 Token Exchange<br/>Actor: JWT-SVID (RFC 7523)<br/>Subject: User JWT| Keycloak
    Keycloak -->|3. Evaluate Coarse Policy / Mint Downscoped Token| Workload
    Workload -->|4a. Federated Exchange| AWS
    Workload -->|4b. RFC 8693 Federated Exchange| GCP
    Workload -->|4c. Federated Exchange| Azure
    Workload -->|4d. Authenticated Invocation| Anthropic
```

### 2.1 Can Keycloak Provide This Natively?
**Yes.** Keycloak provides built-in support for **OAuth 2.0 Token Exchange (RFC 8693)** via the `token-exchange` feature flag (`KC_FEATURES=token-exchange`).

#### Standard RFC 8693 Parameters Handled by Keycloak:
- `grant_type`: `urn:ietf:params:oauth:grant-type:token-exchange`
- `subject_token`: The original Human User's JWT (from Keycloak login, Okta, or external OIDC).
- `subject_token_type`: `urn:ietf:params:oauth:token-type:access_token`
- `actor_token`: The Agent's SPIRE JWT-SVID.
- `actor_token_type`: `urn:ietf:params:oauth:token-type:jwt`
- `audience`: Target resource (e.g. `azure-mcp-server`, `aws-storage`, `gcp-data`).
- `scope`: Requested downscoped scopes (e.g. `mcp:tool1`).

### 2.2 Compliance with RFC 7523 (SPIRE JWT-SVID as Actor Identity)
RFC 7523 specifies how JWTs are used for OAuth 2.0 client authentication and authorization grants.

1. **Attestation Chain**:
   - SPIRE runs the **SPIRE OIDC Discovery Provider** exposing `https://spire-oidc.internal/.well-known/openid-configuration` and `/keys` (JWKS).
   - Keycloak is configured with SPIRE as a trusted Identity Provider or Keystore.
2. **Client Authentication via RFC 7523**:
   When the agent calls Keycloak's `/protocol/openid-connect/token` endpoint, it presents:
   - `client_assertion_type`: `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
   - `client_assertion`: The SPIRE JWT-SVID signed by the SPIRE Server's private key.
3. **Delegation Verification**:
   Keycloak validates the cryptographic signature of the SPIRE JWT-SVID against SPIRE's JWKS, authenticates the workload client (`spiffe://example.org/ns/agent-system/sa/orchestrator-sa`), and verifies the user's `subject_token`.

### 2.3 Other Off-The-Shelf IdP Options
| Product | RFC 8693 Support | RFC 7523 Support | SPIRE Integration | Deployment Model |
| :--- | :--- | :--- | :--- | :--- |
| **Keycloak** | **Native** (`token-exchange`) | **Native** (`private_key_jwt`) | **Direct** (via JWKS URL) | Self-hosted K8s / VM |
| **Ory Hydra** | **Via Token Exchange plugin** | **Native** | **Direct** | Cloud-native Go binary |
| **PingFederate** | **Full Native Enterprise** | **Full Native** | **Direct** | Enterprise On-Prem / Cloud |
| **HashiCorp Vault** | **Identity Secrets Engine** | **Native OIDC** | **Direct** (SPIFFE Auth) | Secrets Broker / Minting |
| **Okta / Auth0** | Requires Custom Actions / Beta | Native Client Assertions | API-based federation | SaaS Managed |

---

## 3. Multi-Cloud & Anthropic Token Federation Strategy

How does a single standard token exchange allow access across **AWS**, **GCP**, **Azure**, and **Anthropic**?

```mermaid
graph TD
    UserToken["User JWT (Subject)"] --> Exchange["Standard Token Exchange<br/>(Keycloak / STS)"]
    SpireSvid["SPIRE SVID (Actor)"] --> Exchange

    Exchange --> ExchangedToken["Standard Federated OBO Token<br/>(sub: user, act: agent, aud: target)"]

    subgraph AWS_Target["1. AWS Access"]
        ExchangedToken -->|AssumeRoleWithWebIdentity| AWS_STS["AWS STS"]
        AWS_STS --> AWS_Creds["Temporary AWS Credentials<br/>(S3, Bedrock, DynamoDB)"]
    end

    subgraph GCP_Target["2. GCP Access"]
        ExchangedToken -->|RFC 8693 STS Exchange| GCP_STS["GCP STS (sts.googleapis.com)"]
        GCP_STS --> GCP_Token["GCP Service Account Token<br/>(GCS, Vertex AI, BigQuery)"]
    end

    subgraph Azure_Target["3. Azure Access"]
        ExchangedToken -->|Workload Identity Federation| Azure_Entra["Microsoft Entra ID"]
        Azure_Entra --> Azure_Token["Azure Storage / MCP Access Token"]
    end

    subgraph Anthropic_Target["4. Anthropic / LLM Access"]
        ExchangedToken --> Anthropic_Route{"Routing Option"}
        Anthropic_Route -->|A. Native Cloud Model| AWS_Creds --> Bedrock_Claude["AWS Bedrock (Claude 3.5 Sonnet)"]
        Anthropic_Route -->|B. Native Cloud Model| GCP_Token --> Vertex_Claude["GCP Vertex AI (Claude 3.5 Sonnet)"]
        Anthropic_Route -->|C. Direct Anthropic API| AI_Gateway["Enterprise AI Gateway (PEP)<br/>Validates Token -> Injects Key"]
        AI_Gateway --> Anthropic_API["api.anthropic.com"]
    end
```

### 3.1 AWS Integration
- **Mechanism**: AWS Security Token Service (`sts:AssumeRoleWithWebIdentity`).
- **Flow**: The agent presents the exchanged OIDC token to AWS STS. AWS validates the signature against Keycloak/SPIRE's OIDC discovery endpoint and returns temporary AWS credentials (`AccessKeyId`, `SecretAccessKey`, `SessionToken`).
- **Audit**: AWS CloudTrail records the federated identity session with the user principal and agent actor.

### 3.2 GCP Integration (Option 3: Workload Identity Federation Direct Subject Grants)
- **Mechanism**: GCP Workload Identity Federation via **GCP STS (`sts.googleapis.com`)** combined with **Direct Project IAM Subject Member Bindings**.
- **Flow**: GCP STS natively implements RFC 8693! The agent calls `https://sts.googleapis.com/v1/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` and `audience=//iam.googleapis.com/projects/{project_number}/locations/global/workloadIdentityPools/{pool_id}/providers/{provider_id}`. 
- **Direct IAM Grants**: Rather than requiring an Organization resource or blanket service account impersonation, human users (Alice and Bob) are configured directly in Google Cloud project IAM policies as active member principals (`principal://iam.googleapis.com/.../workloadIdentityPools/k8s-agent-pool/subject/{email}`).
- **Downscoped CAB**: Google STS applies Credential Access Boundaries to downscope permissions strictly to `analytics_data.regional_sales`.

### 3.3 Azure Integration (Authentic Entra ID RS256 PKI)
- **Mechanism**: Microsoft Entra ID Token Exchange & Workload Identity Federation (WIF).
- **Flow**: Authentic RS256 tokens are acquired from Microsoft Entra ID (`https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`) and verified at the MCP server against Microsoft's public JWKS endpoint. Symmetrical HMAC tokens are strictly rejected.

### 3.4 Anthropic Claude Integration
Anthropic's direct public API (`https://api.anthropic.com/v1/messages`) authenticates via static API keys (`x-api-key`), not OAuth OIDC. In an enterprise setting, you have two recommended best practice options:
1. **Option 1 (Cloud-Native IAM - Recommended)**:
   Invoke Anthropic Claude models via **AWS Bedrock** (`anthropic.claude-3-5-sonnet...`) or **GCP Vertex AI**.
   - This eliminates all static API keys.
   - You authenticate using the federated AWS or GCP temporary tokens obtained via steps 3.1 or 3.2.
2. **Option 2 (Enterprise AI Gateway / PEP)**:
   If invoking `api.anthropic.com` directly:
   - Deploy an AI Gateway (e.g. Kong, Envoy, LiteLLM, Cloudflare AI Gateway) as the Policy Enforcement Point (PEP).
   - The agent calls the AI Gateway with its RFC 8693 Bearer Token.
   - The Gateway validates the token's `sub`, `act.sub`, and checks user token quotas.
   - The Gateway securely injects the enterprise Anthropic API Key and proxies the request to Anthropic.

---

## 4. Policy Division: Coarse-Grained (IdP) vs. Fine-Grained (OPA)

To achieve scalable zero-trust governance, policy enforcement must be divided into two distinct tiers:

```mermaid
graph TD
    subgraph Tier1["Tier 1: Coarse-Grained Policy (CGP) at IdP / Authorization Server (Keycloak PDP)"]
        C1["Is Workload authenticated via SPIRE?"]
        C2["Is User active and in correct realm?"]
        C3["Calculate Entitlement Scopes (e.g. mcp:tool1, storage:read)"]
        C4["Mint Downscoped OBO Token with Scopes"]
    end

    subgraph Tier2["Tier 2: Fine-Grained Policy (FGP) at Workload / MCP Server (OPA Engine)"]
        F1["Inspect tool arguments (container, filename, action)"]
        F2["Validate attribute constraints (e.g. file extension, read-only)"]
        F3["Attribute-Based Access Control (ABAC) / Tenant Isolation"]
        F4["Contextual checks: Business hours, IP ranges, prompt risk score"]
    end

    Tier1 -->|Exchanged OBO Token| Tier2
```

| Dimension | Coarse-Grained Policy (CGP) | Fine-Grained Policy (FGP) |
| :--- | :--- | :--- |
| **Enforcement Point (PEP)** | Keycloak / Central IdP / Token Exchange | Microservice / MCP Server / OPA Sidecar |
| **Decision Point (PDP)** | Keycloak Authorization Services | Open Policy Agent (OPA) / Rego Engine |
| **Inputs Available** | User roles, client identity, target audience, coarse scopes | Full request body, tool arguments, file paths, environmental context, tenant attributes |
| **Evaluation Speed** | Evaluated at token issuance time (cached for token lifespan) | Evaluated per invocation (sub-millisecond local OPA check) |
| **Examples** | Can user `bob` call `mcp-server`? Scopes: `[mcp:tool1]` | Can user `bob` write file `audit.json` in container `app1` on Sunday at 2 AM? |

---

## 5. Defining & Enforcing FGP in `tools.yaml` for MCP Servers

How can MCP servers define Fine-Grained Policies declaratively in `tools.yaml` and execute them via Open Policy Agent (OPA)?

### 5.1 Option A: Declarative CEL / Condition Expressions in `tools.yaml`
For simple attribute rules, embed declarative expression rules directly into `tools.yaml`:

```yaml
version: "2026-07-15"
tools:
  - name: "tool1"
    title: "Storage Read/Write Tool"
    description: "Read and write data blobs across authorized enterprise containers"
    required_scope: "mcp:tool1"
    allowed_containers: ["app1", "app2"]
    
    # Declarative Fine-Grained Policies (FGP)
    fine_grained_policies:
      # Rule 1: Prevent writing to compliance or production configs
      - id: "protect_critical_files"
        effect: "DENY"
        condition: "args.action == 'write' && (args.filename.matches('^.*(compliance|config|prod).*$'))"
        message: "Modifying compliance or production configuration files is forbidden."
        
      # Rule 2: Tenant Isolation Check
      - id: "tenant_boundary"
        effect: "DENY"
        condition: "args.container == 'app2' && !auth.user.roles.contains('admin') && auth.user.department != 'DataOperations'"
        message: "Access to app2 container requires DataOperations department membership or Admin role."

      # Rule 3: File Extension Whitelist
      - id: "allowed_extensions"
        effect: "DENY"
        condition: "!args.filename.matches('^.*\\.(json|txt|csv|yaml)$')"
        message: "Only structured data formats (.json, .txt, .csv, .yaml) may be processed."
```

### 5.2 Option B: Native OPA / Rego Integration in `tools.yaml`
For complex enterprise authorization (e.g. database lookups, temporal rules, role hierarchies), link `tools.yaml` to an **OPA Policy Document**:

```yaml
version: "2026-07-15"
tools:
  - name: "tool2"
    title: "Security Audit Tool"
    description: "Read-only compliance audit tool for app1"
    required_scope: "mcp:tool2"
    
    # Delegate to Open Policy Agent (OPA)
    opa_policy:
      endpoint: "http://localhost:8181/v1/data/mcp/tool2/allow"
      policy_file: "policies/mcp_tool2_authz.rego"
      fail_closed: true
```

#### Corresponding Rego Policy (`policies/mcp_tool2_authz.rego`):
```rego
package mcp.tool2

default allow = false
default reason = "Default deny: unauthorized tool execution"

# Allow rule evaluated by OPA
allow {
    # 1. Verify required scope
    input.auth.scopes[_] == "mcp:tool2"
    
    # 2. Strict read-only enforcement
    input.args.action == "read"
    input.args.container == "app1"
    
    # 3. Restrict file types
    valid_file_extension
    
    # 4. Temporal rule: Only permitted during audit windows (e.g., weekdays)
    not weekend_access
}

valid_file_extension {
    endswith(input.args.filename, ".json")
}

valid_file_extension {
    endswith(input.args.filename, ".txt")
}

weekend_access {
    input.context.day_of_week == "Saturday"
}

weekend_access {
    input.context.day_of_week == "Sunday"
}
```

### 5.3 How the MCP Server Executes FGP at Runtime

```javascript
// MCP Server Tool Execution Pipeline
async function executeTool(toolName, args, authContext) {
  const toolDef = toolMap.get(toolName);

  // 1. Tier 1: Coarse-Grained Scope Check (From RFC 8693 Token)
  if (!authContext.scopes.includes(toolDef.required_scope)) {
    return denyToolAccess("Lacks required scope: " + toolDef.required_scope);
  }

  // 2. Tier 2: Fine-Grained Policy (FGP) Evaluation via OPA
  if (toolDef.opa_policy) {
    const opaPayload = {
      input: {
        auth: {
          sub: authContext.sub,
          actor: authContext.act?.sub,
          roles: authContext.roles,
          scopes: authContext.scopes
        },
        args: args,
        context: {
          timestamp: new Date().toISOString(),
          day_of_week: new Intl.DateTimeFormat('en-US', { weekday: 'long' }).format(new Date())
        }
      }
    };

    const opaDecision = await evaluateOpaPolicy(toolDef.opa_policy.endpoint, opaPayload);
    if (!opaDecision.result) {
      return {
        isError: true,
        content: [{ type: "text", text: `FGP Denial by OPA: ${opaDecision.reason || 'Policy constraint violated.'}` }],
        audit: { decision: "DENIED_BY_OPA_POLICY", tool: toolName, principal: authContext.sub }
      };
    }
  }

  // 3. Execute Tool Action
  return executeBackendOperation(args);
}
```

---

## 6. Implementation Roadmap for Your Architecture

1. **Enable Native Keycloak Token Exchange**:
   - Run Keycloak with `KC_FEATURES=token-exchange,scripts`.
   - Register the SPIRE OIDC Discovery Provider endpoint in Keycloak to validate incoming SPIFFE JWT-SVIDs via RFC 7523.
2. **Deploy OPA Sidecar or WASM Engine**:
   - In Kubernetes, deploy `openpolicyagent/opa:latest` as a sidecar container alongside the MCP Server pod, or use `@open-policy-agent/opa-wasm` directly in Node.js.
3. **Enhance `tools.yaml` with Fine-Grained Conditions**:
   - Add parameter filters, regex validations, and tenant isolation policies directly into `tools.yaml`.
4. **Cloud Multi-Provider Connectors**:
   - Configure AWS IAM Roles Anywhere or AWS OIDC Federation for S3 and Bedrock Claude.
   - Configure GCP Workload Identity Pools for GCS and Vertex AI Claude.
   - Use the single exchanged OBO token as the federated credential for all downstream targets.

---

## 7. Combined Pattern A+B: Resolving the Tool Consent vs. Cloud IAM Resource Dilemma

### 7.1 The Enterprise Semantic Gap: Tool Capability Consent vs. Cloud Resource IAM
In an enterprise, assigning a scope such as `mcp:bigquery:query` to a business user (e.g. Alice) in Keycloak or Entra ID establishes **Functional Capability Consent**, which means:
> *"Alice is authorized to consume synthesized business analytics answers generated by the AI agent via the curated BigQuery MCP Tool."*

It **does NOT** mean Alice is a provisioned IAM principal in Google Cloud IAM with rights to log into `console.cloud.google.com`, write raw SQL in BigQuery Studio, or export tables. In enterprise governance:
1. **Business users do not have individual Cloud IAM accounts**: Creating cloud console identities for thousands of analysts violates the Principle of Least Privilege (**NIST SP 800-53 AC-6**) and creates uncontrollable credential sprawl.
2. **MCP Servers act as Mediating Cognitive Gateways**: The MCP server encapsulates curated queries, parameter sanitization, and PII redaction. Direct database access is intentionally avoided.
3. **The Confused Deputy Hazard**: If the MCP server runs under a static Service Account (`gcp-mcp-sa`) that has broad GCP IAM roles (`roles/bigquery.dataViewer`), any user who can call the agent could theoretically access any dataset the service account can reach unless the system enforces strict runtime downscoping.

### 7.2 The Combined Pattern A + B Triple-Lock Architecture
To solve this without provisioning end users in Cloud IAM, we combine **Pattern A (IdP Capability Verification)** with **Pattern B (Google Cloud STS Credential Access Boundaries)**:

```mermaid
flowchart TD
    subgraph IdP ["1. Enterprise IdP (Functional Consent)"]
        Alice["Alice (sub: alice@...)\nScope: mcp:bigquery:query\n(Consent to use BigQuery MCP tool)"]
    end

    subgraph Orch ["2. Agent Orchestrator (RFC 8693 PDP)"]
        Gate1{"Gate 1 (RFC 8693 §2.1 Math):\nRequested Scope ⊆ User IdP Scopes?"}
        Gate1 -->|No| Fail["FAIL-CLOSED (HTTP 403)\nSCOPE_ESCALATION_DENIED"]
        Gate1 -->|Yes| Gate2["Gate 2: Google STS Token Exchange\nRequest Downscoped Token with CAB"]
    end

    subgraph GCP_STS ["3. Google Cloud STS Kernel (Pattern B - CAB)"]
        CAB["Credential Access Boundary Rule:\n• Resource: .../datasets/analytics_data/tables/regional_sales\n• Permission: inRole:roles/bigquery.dataViewer\n• Condition: Read-only, no export"]
        Gate2 --> CAB
        CAB --> DownscopedToken["Downscoped Google Access Token\n(Physically cannot touch any other dataset)"]
    end

    subgraph GCP_MCP ["4. Google Cloud MCP Server (Pattern A - FGP & Ingress)"]
        Ingress["Cloud IAM Ingress:\nValidates Google Signature & Service Account azp"]
        Gate3["Gate 3: Declarative FGP Engine (tools.yaml):\n• Enforces parameter constraints (region != '*')\n• Verifies recursive act chain\n• Injects alice@... into BigQuery Job Labels"]
        DownscopedToken --> Ingress --> Gate3
    end

    subgraph BQ ["5. Google BigQuery Data Plane"]
        Data["Query Executed on regional_sales table ONLY\nAudit Log: SA=gcp-mcp-sa, Label: delegated_user=alice@..."]
        Gate3 --> Data
    end

    Alice -->|Bearer Token| Orch
```

### 7.3 Mathematical Formalization of RFC 8693 Section 2.1
RFC 8693 §2.1 strictly mandates that an authorization server or token exchange engine **MUST NOT** elevate privileges:
$$\text{Scope}_{\text{exchanged}} \subseteq \text{Scope}_{\text{subject\_token}} \cap \text{Scope}_{\text{client\_allowed}} \cap \text{Scope}_{\text{requested\_tool}}$$

- If a tool requires `mcp:bigquery:query`, and the user's IdP token only contains `mcp:tool1` (e.g. Charlie), then:
  $$\text{Scope}_{\text{exchanged}} = \{\text{mcp:bigquery:query}\} \cap \{\text{mcp:tool1}\} = \emptyset$$
- The exchange **fails closed** immediately. No token is minted, and no request is sent to Google Cloud STS.

### 7.4 Credential Access Boundary (CAB) Specification
When Gate 1 passes, Gate 2 calls Google Cloud STS (`https://sts.googleapis.com/v1/token`) requesting a token downscoped via an **OAuth 2.0 Credential Access Boundary**:
```json
{
  "accessBoundary": {
    "accessBoundaryRules": [
      {
        "availableResource": "//bigquery.googleapis.com/projects/834200279688/datasets/analytics_data/tables/regional_sales",
        "availablePermissions": [
          "inRole:roles/bigquery.dataViewer"
        ],
        "availabilityCondition": {
          "title": "RegionalSalesTableOnly",
          "expression": "resource.name.startsWith('projects/wifdemoproject-507002/datasets/analytics_data/tables/regional_sales')"
        }
      }
    ]
  }
}
```
Even though the presenting identity (`azp`) is `gcp-mcp-sa@wifdemoproject-507002.iam.gserviceaccount.com`, the resulting token is **physically restricted by the Google Cloud IAM kernel**. If a prompt injection attempts to read `audit_logs` or drop tables, Google Cloud returns HTTP 403 Forbidden at the infrastructure level.

### 7.5 Audit Lineage & Non-Repudiation (NIST SP 800-53 AU-2 / AU-3)
To ensure accountability when queries execute under a service account, the GCP MCP Server stamps the human user identity and actor chain into **BigQuery Query Job Labels**:
```json
{
  "configuration": {
    "query": {
      "query": "SELECT ... FROM regional_sales",
      "destinationTable": null
    },
    "labels": {
      "delegated_user": "alice_at_rtarwaygmail_onmicrosoft_com",
      "actor_orchestrator": "orchestrator_sa",
      "trace_hop": "5",
      "tool_name": "bigquery_query_sales"
    }
  }
}
```
In Google Cloud Audit Logs, security operations teams can filter by `labels.delegated_user = "alice..."`, directly linking technical BigQuery executions to the authenticated human delegator.

### 7.6 Standards Alignment Summary
- **NIST SP 800-207 (Zero Trust)**: Eliminates implicit trust in the service account proxy by enforcing end-to-end subject validation and dynamic session boundaries.
- **NIST SP 800-53 (AC-6 Least Privilege, AU-2/3 Event Logging)**: Enforces least privilege downscoping at each hop and guarantees non-repudiation in multi-cloud audit streams.
- **RFC 8693 (OAuth 2.0 Token Exchange)**: Full compliance with Section 2.1 (Scope Downscoping) and Section 4.1 (Recursive Multi-Hop Actor Lineage).
- **OWASP Top 10 for LLMs / AI Agents (LLM06 Excessive Agency & LLM08 Insecure Data)**: Neutralizes the Confused Deputy problem and prevents prompt injections from escaping bounded tool scopes.
- **MAESTRO Architecture**: Implements cryptographically verifiable actor lineage across heterogeneous cloud domains.

---

## 8. Authentic Cloud IAM Asymmetric PKI vs. Insecure Symmetric Token Simulation

### 8.1 Elimination of Insecure Symmetric HMAC Tokens
In insecure legacy implementations, an application orchestrator might mint simulated cloud tokens using a shared symmetric HMAC secret (`JWT_SECRET` / `OBO_SECRET`) and pass them to downstream MCP servers. In enterprise production, **this practice is fundamentally rejected**:
- **Compromised Blast Radius**: Any workload possessing the symmetric secret can arbitrarily forge tokens for any identity, any scope, and any audience.
- **Breach of Trust Boundaries**: Google Cloud IAM, Microsoft Entra ID, and cloud services do not share symmetric HMAC secrets with application containers.
- **Zero-Trust Violation**: Cryptographic authenticity must derive from the authoritative Identity Provider via Asymmetric Public Key Infrastructure (RFC 7515 RS256) and public JWKS (`.well-known/jwks.json`).

### 8.2 Authentic Google Cloud STS Token Exchange
To preserve absolute zero-trust integrity, token exchange with Google Cloud Platform strictly follows standard OAuth 2.0 Token Exchange (RFC 8693):
- **Token Endpoint**: `https://sts.googleapis.com/v1/token`
- **Parameters**:
  - `grant_type`: `urn:ietf:params:oauth:grant-type:token-exchange`
  - `subject_token`: Alice's authentic Keycloak OIDC ID token (`sub: alice@example.com`)
  - `subject_token_type`: `urn:ietf:params:oauth:token-type:id_token`
  - `actor_token`: Orchestrator's authentic SPIFFE SVID JWT (`sub: spiffe://example.org/ns/agent-system/sa/orchestrator-sa`)
  - `actor_token_type`: `urn:ietf:params:oauth:token-type:jwt`
  - `audience`: Workload Identity Pool Provider (`//iam.googleapis.com/projects/.../workloadIdentityPools/k8s-agent-pool/providers/spire-oidc-provider`)
  - `access_boundary`: Credential Access Boundary JSON (physically restricts table access)
- **Token Signature**: Asymmetric RSA Private Key (`RS256`), verified downstream by the GCP MCP server using the authoritative Google STS Public Certificate / JWKS (`certs/google-sts-cert.pem`).
- **Fail-Closed Enforcement**: The GCP MCP Server strictly inspects `alg: 'RS256'` against the public certificate. Any incoming token signed with symmetric HMAC (`HS256`) is actively detected as a security violation and **immediately rejected with HTTP 401/403**.

### 8.3 Standards Compliance & Non-Compliance Matrix
The following matrix articulates what is standard-compliant and calls out deviations across relevant cybersecurity frameworks:

| Standard / Framework | Requirement | Authentic Implementation Status | What is Non-Compliant with Standards (if compromised) |
| :--- | :--- | :--- | :--- |
| **NIST SP 800-207 (Zero Trust)** | All tokens must be cryptographically issued and verified by authoritative trust roots; no implicit trust. | **COMPLIANT**: Tokens issued by authentic IdP / Google STS via RS256 PKI; MCP server validates against public certificate. | Minting tokens outside an authoritative IdP or using symmetric HMAC shared secrets violates Zero Trust core tenet #4 (Dynamic evaluation via authentic IdP). |
| **NIST SP 800-53 Rev. 5 (IA-2, IA-5, SC-12)** | Authenticator management, asymmetric cryptographic mechanisms, and non-repudiation. | **COMPLIANT**: Eliminates shared secrets; enforces asymmetric RS256 PKI public-key verification. | Storing symmetric keys (`JWT_SECRET`) across distributed microservices violates IA-5(1) (Password/Key Management) and SC-12 (Cryptographic Key Establishment). |
| **RFC 8693 Section 2.1 (Scope Downscoping)** | Exchanged token scope must not exceed subject token scope: $\text{Scope}_{\text{exchanged}} \subseteq \text{Scope}_{\text{subject}}$. | **COMPLIANT**: Gate 1 verifies IdP scopes before exchange; unauthorized users fail-closed with `SCOPE_ESCALATION_DENIED`. | Minting tokens with scopes the subject does not possess in the IdP violates RFC 8693 §2.1. |
| **RFC 8693 Section 4.1 (`act` Claim Support in Cloud STS)** | Downstream tokens must encapsulate recursive `act` claims representing delegated actors. | **DEVIATION / CALL-OUT**: **Google Cloud STS and Microsoft Entra ID native access tokens do not currently embed custom RFC 8693 Section 4.1 recursive `act` claims**. Cloud STS issues standard cloud access tokens bound to the service account and Credential Access Boundary. | Injecting artificial `act` claims into an IdP-signed token invalidates its digital signature. To remain secure, authentic cloud tokens are accepted without `act` claims, while application lineage is preserved via SPIFFE SVID actor assertions and Cloud Audit Labels (NIST AU-2/3). |
| **OWASP Top 10 for LLM (LLM06: Excessive Agency)** | Prevent autonomous agents from taking actions beyond least privilege or performing confused deputy operations. | **COMPLIANT**: Credential Access Boundaries (CAB) and tools.yaml FGP limit physical execution to specified datasets/tables. | Relying solely on prompt instructions or unconstrained service account tokens exposes the system to LLM06 and prompt injection table exfiltration. |
| **OWASP API Security Top 10 (API2:2023 Broken Authentication)** | Strong token validation, audience restriction, and cryptographic integrity. | **COMPLIANT**: Enforces strict audience checking, expiration, and RS256 signature verification. | Accepting unsigned or symmetrically forged tokens claiming to be Google Cloud IAM represents classic Broken Authentication. |
| **OSA (Open Security Architecture) & MAESTRO** | Autonomous Agent Security Architecture: Lineage tracking, non-repudiation, verifiable provenance. | **COMPLIANT**: Complete hop-to-hop provenance tracked across SPIFFE SVIDs, IdP tokens, CAB downscoping, and BigQuery Job Labels. | Untracked delegation or synthetic machine identities without audit trails violate MAESTRO Agent Lineage principles. |

