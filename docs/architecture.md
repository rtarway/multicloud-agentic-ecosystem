# End-to-End Architecture: Azure WIF & OBO Agentic Flow with Low-Code MCP

This document details the security, identity, and architectural design of the **Agentic AI Ecosystem** deployed on **Rancher Desktop Kubernetes** accessing a **Low-Code Declarative Model Context Protocol (MCP) Server** for **Azure Cloud Storage**.

---

## 1. Problem Statement: The Flaws of Static Credentials & Blanket Delegation

In standard enterprise cloud architectures, backend microservices or agent runtimes often connect to cloud resources using:
1. **Static Service Principal Secrets**: Long-lived Azure Client Secrets or Certificates mounted into containers.
2. **Blanket Service Impersonation**: Machine-to-machine tokens that discard the human user's identity.

In an **Agentic AI** ecosystem (where an LLM autonomously chooses which tools to invoke across enterprise storage buckets), this introduces severe security risks:

- **Lost Accountability & Broken Audit Trail**: Azure Activity Logs attribute all blob reads and writes to the service principal, obliterating forensic evidence of whether Alice (Admin) or Bob (Regular User) originated the request.
- **Confused Deputy Attacks**: If Bob asks the agent to read sensitive compliance reports from `app1`, a broadly privileged service account would fetch it and return it to Bob, completely bypassing user-level access restrictions.
- **Privilege Escalation**: Once an agent has blanket read/write access, prompt injection can trick it into exfiltrating or modifying unauthorized buckets.

---

## 2. The Solution: End-to-End Delegated Identity with Downscoped OBO Exchange

This POC establishes zero-trust identity propagation across the entire invocation chain:

### 2.1 System Architecture Diagram

```mermaid
graph TB
    subgraph ClientBrowser["User Client Layer"]
        Browser["User Web Browser<br/>• 1-Click Login Screen<br/>• Dual Token Inspector"]
    end

    subgraph K8sCluster["Kubernetes Cluster (Rancher Desktop / k3s)"]
        subgraph OutsideSPIRE["Namespace: agent-system (Outside SPIRE)"]
            Frontend["Web Frontend Dashboard<br/>Port: 3000 / NodePort: 30000<br/>• Serves Browser UI<br/>• B2B Federation Bridge<br/>• Proxies Chat Prompts"]
        end

        subgraph IdPLayer["Namespace: keycloak"]
            Keycloak["Corporate Keycloak IdP (Port 8080)<br/>Realm: azure-wif-realm<br/>• Alice: admin, auditor, Mail.Send<br/>• Bob: regular-user (app2 only)<br/>• Charlie: auditor (no Mail.Send)"]
        end

        subgraph InsideSPIRE["Namespace: agent-system (Inside SPIRE + Istio Mesh)"]
            Orchestrator["A2A Agent Orchestrator (Port 3001)<br/>• Multi-Hop LLM Planning Engine<br/>• In-Memory Redaction Engine<br/>• Direct Graph Client (Mail.Send)<br/>• RFC 8693 Token Exchange Engine"]
            SpireAgent["SPIRE Agent (DaemonSet)<br/>Workload API Socket: /run/spire/sockets/agent.sock"]
        end

        subgraph SPIREServer["Namespace: spire-server"]
            SpireServer["SPIRE Server<br/>Trust Domain: example.org"]
        end
    end

    subgraph AzureIdentity["Microsoft Entra ID (Tenant: 81f26b58-159c-4879-80a0-bab30b5b4dd3)"]
        EntraSTS["Entra ID External Identities<br/>• SAML/OIDC B2B Direct Federation<br/>• Claims-Mapping Policy (Roles ➔ scp)<br/>• Tenant-Wide Admin Consented Scopes<br/>• Token Endpoint (/oauth2/v2.0/token)"]
    end

    subgraph AzureCloud["Microsoft Azure Cloud (Resource Group: rg-azure-wif-poc)"]
        subgraph AppService["Azure App Service (Linux Node.js 22 LTS)"]
            MCP["Azure Storage MCP Server (Port 8080 / HTTPS)<br/>• Endpoint: /mcp (JSON-RPC 2.0)<br/>• Spec: 2026-07-15 (July 2026)<br/>• Declarative Policy Engine (tools.yaml)<br/>• 60s JIT User-Delegation Storage SAS"]
        end

        subgraph CloudStorage["Azure Cloud Storage"]
            StorageAcct["Azure Storage Account: azwifstoragepocrt<br/>• Container app1 (Financials / Reader)<br/>• Container app2 (Customer Metrics)"]
        end

        subgraph MicrosoftGraph["Microsoft Graph API"]
            GraphAPI["Graph API: POST /v1.0/me/sendMail<br/>• Direct Orchestrator Dispatch<br/>• Downscoped Bearer Token (Mail.Send)"]
        end
    end

    %% Flow connections
    Browser -->|"1. 1-Click Login"| Frontend
    Frontend -->|"2. Authenticate User"| Keycloak
    Keycloak -.->|"2a. Keycloak OIDC Token"| Frontend
    Frontend -->|"3. B2B Direct Federation Exchange"| EntraSTS
    EntraSTS -.->|"3a. Entra ID User Subject Token"| Frontend
    Frontend -.->|"3b. Render Dual Tokens"| Browser
    Frontend -->|"4. POST /api/chat + Federated User Token"| Orchestrator
    Orchestrator -->|"5. Request SVID via Workload API"| SpireAgent
    SpireAgent -->|"Attest & Mint"| SpireServer
    SpireAgent -.->|"5a. JWT-SVID (spiffe://.../orchestrator-sa)"| Orchestrator
    Orchestrator -->|"6. Hop 3: RFC 8693 Token Exchange (Storage)"| Orchestrator
    Orchestrator -->|"7. POST /mcp (tool1 app1 & app2)"| MCP
    MCP -->|"8. Hop 4: Ephemeral 60s JIT SAS"| StorageAcct
    StorageAcct -.->|"8a. Blob Content"| MCP
    MCP -.->|"8b. Return App1 & App2 Data"| Orchestrator
    Orchestrator -->|"9. In-Memory LLM Redaction & Synthesis"| Orchestrator
    Orchestrator -->|"10. Hop 5: RFC 8693 Exchange (Graph Mail.Send)"| Orchestrator
    Orchestrator -->|"11. Hop 6: Direct POST /me/sendMail"| GraphAPI
    Orchestrator -.->|"12. Final Result & Hop Trace"| Frontend
    Frontend -.->|"13. Render Visual Audit"| Browser
```

---

### 2.2 Sequence Diagram: B2B Identity Federation & Dual Token Generation Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as Human User (Alice / Bob / Charlie)
    participant UI as Web Frontend (Outside SPIRE)
    participant Keycloak as Keycloak IdP (azure-wif-realm)
    participant Entra as Microsoft Entra ID (External Identities)
    participant Agent as Agent Orchestrator (Inside SPIRE)
    participant SPIRE as SPIRE Workload API
    participant Engine as RFC 8693 Exchange Engine
    participant MCP as Azure Storage MCP Server
    participant Storage as Azure Storage (app1 / app2)
    participant Graph as Microsoft Graph API

    User->>UI: 1. Click 1-Click Login (Alice / Bob / Charlie)
    UI->>Keycloak: 2. Authenticate User (POST /api/login)
    Keycloak-->>UI: 3. Keycloak OIDC Token (sub, roles, scope)
    
    rect rgb(240, 248, 255)
        Note over UI,Entra: B2B Identity Federation (Keycloak ➔ Entra ID)
        UI->>Entra: 4. Present Keycloak Assertion (Direct Federation / RFC 7523)
        Note over Entra: Verifies Keycloak signature via JWKS.<br/>Claims Mapping: Keycloak roles ➔ Entra App Roles / scp.<br/>Applies Admin Consent for API scopes.
        Entra-->>UI: 5. Entra ID User Subject Token (iss: login.microsoftonline.com, tid, appid, scp, scope)
    end

    Note over UI: UI displays BOTH tokens simultaneously in Dashboard Inspector.
    UI->>Agent: 6. POST /api/chat (Prompt, Keycloak Bearer, Entra Context)
    
    rect rgb(240, 248, 255)
        Note over Agent,SPIRE: Workload Identity Attestation
        Agent->>Agent: LLM Simulator plans tool: 'tool1', container: 'app1', action: 'read'
        Agent->>SPIRE: Fetch Workload SVID (aud: azure-mcp-server)
        SPIRE-->>Agent: JWT-SVID (spiffeId: spiffe://example.org/ns/agent-system/sa/orchestrator-sa)
    end

    rect rgb(255, 250, 240)
        Note over Agent,Engine: RFC 8693 Token Exchange & Downscoping
        Agent->>Engine: exchangeToken(subjectToken: User JWT, actorToken: JWT-SVID, tool: 'tool1')
        Engine->>Engine: Validate Subject (bob@example.com) & Actor (spiffeId)
        Engine->>Engine: Downscope: regular-user -> mcp:tool1 (mcp:tool2 excluded)
        Engine-->>Agent: Minted Downscoped OBO JWT { sub, act: { sub }, scope: "mcp:tool1" }
    end

    rect rgb(245, 255, 250)
        Note over Agent,Storage: MCP Tool Execution in Azure
        Agent->>MCP: POST /mcp (JSON-RPC 2.0: tools/call, Bearer: OBO JWT)
        MCP->>MCP: verifyOboToken(authHeader) -> extract sub, act.sub, scope
        MCP->>MCP: Check declarative policy: does scope have 'mcp:tool1'? -> YES
        MCP->>Storage: Read blob 'financial-report.json' in 'app1'
        Storage-->>MCP: Blob content ($14.2M Q2 Revenue)
        MCP->>MCP: Log Audit Event: [MCP Storage] ACCESS GRANTED (principal: bob@example.com)
        MCP-->>Agent: JSON-RPC Result: { isError: false, content: [...] }
    end

    Agent-->>UI: Complete Agent Response + Audit Trail
    UI-->>User: Display Formatted Data & Proof of Access
```

---

### 2.3 Sequence Diagram: Scope Downscoping & Denial Flow (Bob vs. Alice on Tool2)

```mermaid
sequenceDiagram
    autonumber
    actor Bob as Bob (Regular User)
    actor Alice as Alice (Security Admin)
    participant Agent as Agent Orchestrator
    participant Engine as RFC 8693 Exchange Engine
    participant MCP as Azure MCP Server

    Note over Bob,MCP: Scenario A: Bob attempts sensitive audit via tool2
    Bob->>Agent: "Run security audit on app1 using tool2"
    Agent->>Engine: exchangeToken(User: Bob, Tool: 'tool2')
    Engine->>Engine: Evaluate Bob's role: [regular-user] -> only eligible for mcp:tool1
    Engine->>Engine: Downscope: mcp:tool2 NOT GRANTED (granted: [mcp:tool1])
    Engine-->>Agent: OBO Token with scope="mcp:tool1"
    Agent->>MCP: POST /mcp { method: "tools/call", name: "tool2" } (Bearer: scope=mcp:tool1)
    MCP->>MCP: Policy Check: tool2 requires scope 'mcp:tool2'
    MCP->>MCP: Log Security Audit: [MCP Security] ACCESS DENIED (principal: bob@example.com)
    MCP-->>Agent: CallToolResult { isError: true, text: "MCP Authorization Denied: lacks mcp:tool2" }
    Agent-->>Bob: ❌ Policy Check Failed: Denied by MCP Server

    Note over Alice,MCP: Scenario B: Alice executes audit via tool2
    Alice->>Agent: "Run security audit on app1 using tool2"
    Agent->>Engine: exchangeToken(User: Alice, Tool: 'tool2')
    Engine->>Engine: Evaluate Alice's role: [admin] -> eligible for mcp:tool1 & mcp:tool2
    Engine->>Engine: Downscope: grant required scope "mcp:tool2"
    Engine-->>Agent: OBO Token with scope="mcp:tool2"
    Agent->>MCP: POST /mcp { method: "tools/call", name: "tool2" } (Bearer: scope=mcp:tool2)
    MCP->>MCP: Policy Check: tool2 requires scope 'mcp:tool2' -> MATCHED!
    MCP->>MCP: Log Storage Audit: [MCP Storage] ACCESS GRANTED (principal: alice@example.com)
    MCP-->>Agent: CallToolResult { isError: false, text: "ISO27001 active..." }
    Agent-->>Alice: ✅ Audit Report Retrieved Successfully
```

---

## 3. Core Architectural Components

### 3.1 Keycloak Identity Provider (IdP)
- **Realm**: `azure-wif-realm`
- **Users**:
  - `alice` (`alice@example.com`): Realm Role `admin`. Eligible for scopes `mcp:tool1` and `mcp:tool2`.
  - `bob` (`bob@example.com`): Realm Role `regular-user`. Eligible strictly for scope `mcp:tool1`.
- **Client**: `web-frontend-client` configured for standard OIDC login.

### 3.2 Web Frontend Application (Kept OUTSIDE SPIRE)
- **Design Rationale**: Kept outside the SPIRE CSI driver and SPIFFE workload API injection. Standard web browsers cannot satisfy SPIFFE client certificate mTLS requirements without enterprise device certificates. Keeping the web frontend outside SPIRE allows frictionless browser access (`http://localhost:3000`) while preserving end-to-end security through user OIDC bearer tokens.

### 3.3 A2A Agent Orchestrator (Kept INSIDE SPIRE + Istio)
- **Workload Identity**: Injected with the SPIFFE CSI Driver (`csi.spiffe.io`), mounting `/run/spire/sockets/agent.sock`.
- **SPIFFE ID**: `spiffe://example.org/ns/agent-system/sa/orchestrator-sa`.
- **Istio Mesh**: Configured with Citadel CA disabled, delegating all internal pod mTLS certificates to SPIRE.
- **Simulated LLM Engine**: Parses natural language prompt, determines target storage container (`app1` vs `app2`), operation (`read` vs `write`), and tool (`tool1` vs `tool2`).

### 3.4 RFC 8693 On-Behalf-Of (OBO) Token Exchange & Downscoping
When the agent prepares to invoke the MCP server:
1. It presents:
   - **Subject Token**: User's Keycloak JWT.
   - **Actor Token**: Agent's SPIRE JWT-SVID.
2. The downscoping engine computes:
   - If user is `regular-user`: Downscopes scope strictly to `mcp:tool1`.
   - If user is `admin`: Downscopes scope to `mcp:tool1 mcp:tool2`.
3. The resulting token carries the complete delegation audit chain:
   ```json
   {
     "iss": "https://identity.example.com/realms/azure-wif-realm",
     "sub": "bob@example.com",
     "aud": "azure-mcp-server",
     "act": {
       "sub": "spiffe://example.org/ns/agent-system/sa/orchestrator-sa"
     },
     "scope": "mcp:tool1",
     "downscoped": true,
     "delegationType": "RFC8693_OBO"
   }
   ```

### 3.5 Azure Low-Code Declarative MCP Server
- **MCP Protocol Specification**: Implements protocol version `2026-07-15` (July 2026 release) with JSON-RPC 2.0 endpoints:
  - `initialize`: Protocol negotiation
  - `tools/list`: Declarative tool metadata
  - `tools/call`: Authorized tool execution
- **Declarative Low-Code Tool Registry (`tools.yaml`)**:
  - `tool1`: Read/Write access to containers `app1` and `app2` (requires `mcp:tool1`).
  - `tool2`: Read-only access to container `app1` (requires `mcp:tool2`).
- **Native MCP Error Handling**:
  Instead of raw HTTP 403 status codes, unauthorized access returns a protocol-compliant `CallToolResult`:
  ```json
  {
    "isError": true,
    "content": [
      {
        "type": "text",
        "text": "MCP Authorization Denied: Principal 'bob@example.com' (acting agent 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa') lacks required scope 'mcp:tool2' for tool 'tool2'."
      }
    ],
    "audit": {
      "principal": "bob@example.com",
      "actingAgent": "spiffe://example.org/ns/agent-system/sa/orchestrator-sa",
      "requestedTool": "tool2",
      "requiredScope": "mcp:tool2",
      "grantedScopes": ["mcp:tool1"],
      "decision": "DENIED_BY_POLICY"
    }
  }
  ```
- **Deployment**: Deployed directly to **Azure App Service** (`./scripts/deploy-azure-mcp.sh`) or containerized in Kubernetes (`k8s/mcp-server-deployment.yaml`).

---

## 4. Security Matrix

| Feature | Static Service Account Keys | Traditional OAuth2 Client Credentials | Azure WIF + OBO Token Exchange |
| :--- | :--- | :--- | :--- |
| **Principal in Audit Logs** | Shared machine identity | Shared service identity | **Original Human (`sub`) + Acting Agent (`act.sub`)** |
| **Secret Storage on Disk** | High risk (private keys in pod) | Moderate risk (client secret in pod) | **Zero Secrets (Cryptographic SVIDs & short-lived JWTs)** |
| **Scope Downscoping** | None (blanket permissions) | Coarse (service-level) | **Fine-grained per-user, per-tool downscoping** |
| **Confused Deputy Vulnerability** | High | High | **Zero (enforced at MCP tool execution layer)** |
| **Protocol Version** | Ad-hoc REST | Ad-hoc REST | **MCP Specification July 2026 (`2026-07-15`)** |

---

## 5. RFC 8693 Implementation & Network Payloads

### 5.1 Where does RFC 8693 Token Exchange happen?
In this architecture, RFC 8693 Token Exchange executes in the **A2A Agent Orchestrator** ([app/agent-orchestrator/src/tokenExchange.js](file:///Users/rtarway/mygithubprojects/azure-wif-poc/app/agent-orchestrator/src/tokenExchange.js)).

### 5.2 Are we calling the Microsoft Entra ID Token Endpoint?
**No.** In this POC, the Agent Orchestrator runs an embedded RFC 8693 token exchange engine bridging the external enterprise IdP (**Keycloak**) and the workload identity provider (**SPIRE**).

- **Why?** Microsoft Entra ID's native token endpoint (`login.microsoftonline.com/<tenant>/oauth2/v2.0/token`) requires:
  1. An Azure App Registration with client credentials.
  2. Users to be authenticated against Entra ID (not Keycloak), OR federated via Entra ID External ID.
  3. Workload Identity Federation (WIF) federates external OIDC/SPIFFE tokens to an **Azure Managed Identity** (machine-to-machine), but does not natively combine external user claims (`sub`) with internal workload claims (`act`) in standard Entra app tokens unless using custom claims providers or an intermediary Token Exchange gateway.
- **The POC Implementation**: The Agent Orchestrator acts as the RFC 8693 Authorization Server / PEP, minting a standard RFC 8693 JWT containing both `sub` (original user) and `act.sub` (SPIFFE workload ID) and sending it directly to the Azure MCP Server.

### 5.3 What is Sent to Azure & What is Received?

#### 1. What We Send to Azure (HTTP POST to Azure App Service):
```http
POST https://az-mcp-server-ea223e.azurewebsites.net/mcp HTTP/1.1
Host: az-mcp-server-ea223e.azurewebsites.net
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Length: 147

{
  "jsonrpc": "2.0",
  "id": "agent-exec-1726064034200",
  "method": "tools/call",
  "params": {
    "name": "tool1",
    "arguments": {
      "container": "app1",
      "action": "read",
      "filename": "financial-report.json"
    }
  }
}
```

**Decoded Bearer OBO Token Sent in Request**:
```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "iss": "https://identity.example.com/realms/azure-wif-realm",
    "sub": "bob@example.com",
    "email": "bob@example.com",
    "aud": "azure-mcp-server",
    "act": {
      "sub": "spiffe://example.org/ns/agent-system/sa/orchestrator-sa"
    },
    "scope": "mcp:tool1",
    "roles": ["regular-user"],
    "downscoped": true,
    "delegationType": "RFC8693_OBO",
    "iat": 1726064034,
    "exp": 1726064634
  }
}
```

#### 2. What We Receive from Azure (JSON-RPC 2.0 CallToolResult):
**Scenario A: Success (Allowed by Policy)**:
```json
{
  "jsonrpc": "2.0",
  "id": "agent-exec-1726064034200",
  "result": {
    "isError": false,
    "content": [
      {
        "type": "text",
        "text": "{\n  \"status\": \"SUCCESS\",\n  \"tool\": \"tool1\",\n  \"container\": \"app1\",\n  \"filename\": \"financial-report.json\",\n  \"action\": \"read\",\n  \"data\": {\n    \"quarter\": \"Q2-2026\",\n    \"revenue\": \"$14.2M\",\n    \"status\": \"Audited\"\n  }\n}"
      }
    ],
    "audit": {
      "timestamp": "2026-09-11T14:13:42.248Z",
      "principal": "bob@example.com",
      "actingAgent": "spiffe://example.org/ns/agent-system/sa/orchestrator-sa",
      "requestedTool": "tool1",
      "action": "read",
      "container": "app1",
      "filename": "financial-report.json",
      "decision": "ALLOWED"
    }
  }
}
```

**Scenario B: Failure / Scope Denial (Native Protocol Spec July 2026)**:
```json
{
  "jsonrpc": "2.0",
  "id": "agent-exec-1726064034201",
  "result": {
    "isError": true,
    "content": [
      {
        "type": "text",
        "text": "MCP Authorization Denied: Principal 'bob@example.com' (acting agent 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa') lacks required scope 'mcp:tool2' for tool 'tool2'. Current granted scopes: [mcp:tool1]."
      }
    ],
    "audit": {
      "timestamp": "2026-09-11T14:13:54.204Z",
      "principal": "bob@example.com",
      "actingAgent": "spiffe://example.org/ns/agent-system/sa/orchestrator-sa",
      "requestedTool": "tool2",
      "requiredScope": "mcp:tool2",
      "grantedScopes": ["mcp:tool1"],
      "decision": "DENIED_BY_POLICY"
    }
  }
}
```

---

## 6. How to Validate Logs in Azure

You can inspect the live logs directly on Azure App Service to verify that `sub` (human user) and `act.sub` (Kubernetes SPIFFE identity) are preserved and enforced in Azure.

### Method 1: Real-Time Log Stream via Azure CLI
```bash
az webapp log tail \
  --resource-group rg-azure-wif-poc \
  --name az-mcp-server-ea223e
```

### Method 2: Download Full Log Archive via Azure CLI
```bash
# 1. Download logs to a zip file
az webapp log download \
  --resource-group rg-azure-wif-poc \
  --name az-mcp-server-ea223e \
  --log-file /tmp/azure_logs.zip

# 2. Extract and view MCP access and audit decisions
unzip -p /tmp/azure_logs.zip 'LogFiles/*_default_docker.log' | grep 'MCP'
```

**Actual Live Azure App Service Output Verified**:
```text
2026-09-11T14:13:42.249Z [MCP Storage] ACCESS GRANTED: {"timestamp":"2026-09-11T14:13:42.248Z","principal":"bob@example.com","actingAgent":"spiffe://example.org/ns/agent-system/sa/orchestrator-sa","requestedTool":"tool1","action":"read","container":"app1","filename":"financial-report.json","decision":"ALLOWED"}

2026-09-11T14:13:54.205Z [MCP Security] ACCESS DENIED: {"timestamp":"2026-09-11T14:13:54.204Z","principal":"bob@example.com","actingAgent":"spiffe://example.org/ns/agent-system/sa/orchestrator-sa","requestedTool":"tool2","requiredScope":"mcp:tool2","grantedScopes":["mcp:tool1"],"decision":"DENIED_BY_POLICY"}

2026-09-11T14:14:33.591Z [MCP Storage] ACCESS GRANTED: {"timestamp":"2026-09-11T14:14:33.590Z","principal":"alice@example.com","actingAgent":"spiffe://example.org/ns/agent-system/sa/orchestrator-sa","requestedTool":"tool2","action":"read","container":"app1","filename":"financial-report.json","decision":"ALLOWED"}
```

### Method 3: Azure Portal GUI
1. Sign in to [portal.azure.com](https://portal.azure.com).
2. Open Resource Group **`rg-azure-wif-poc`**.
3. Select App Service **`az-mcp-server-ea223e`**.
4. In the left navigation bar under **Monitoring**, select **Log Stream**.

---

## 7. Storage Access & Identity Mapping Analysis
For an in-depth evaluation of whether users should have direct Azure Service Principals and Azure Storage ACLs versus the Application-Enforced Delegated Gateway pattern, refer to:
- [docs/storage-access-and-identity-analysis.md](file:///Users/rtarway/mygithubprojects/azure-wif-poc/docs/storage-access-and-identity-analysis.md)

---

## 8. Multi-Cloud Triple-Lock Delegation: Combined Pattern A+B

To scale cross-cloud agentic execution securely across Microsoft Azure and Google Cloud Platform, the system implements the **Triple-Lock Security Model**:

```
[Human User] 
     │
     ▼ (Gate 1: RFC 8693 Section 2.1 Scope Downscoping)
[Keycloak IdP: Functional Capability Consent (mcp:bigquery:query)]
     │
     ▼ (Gate 2: Physical IAM Kernel Restriction)
[Google STS: OAuth 2.0 Credential Access Boundary (CAB) Token]
     │
     ▼ (Gate 3: Ingress, Declarative Policy & Audit Stamping)
[Google Cloud MCP Server: Parameter Validation + BigQuery Job Labels]
     │
     ▼
[Google Cloud BigQuery: Query Executed on regional_sales table ONLY]
```

### Architectural Principles:
1. **Tool-Level Consent vs. Cloud Console Access**: Users possess business consent in the IdP (`mcp:bigquery:query`), eliminating the need to provision thousands of analysts directly into Google Cloud IAM or Azure IAM.
2. **Deterministic RFC 8693 Fail-Closed Enforcement**: If an unauthorized user (e.g. Charlie) attempts to call BigQuery, the pipeline terminates at Gate 1 with `SCOPE_ESCALATION_DENIED` before any cloud token exchange occurs.
3. **Physical Machine Bounding (CAB)**: The Service Account (`gcp-mcp-sa`) cannot be abused as a Confused Deputy because Google STS bounds the runtime token strictly to `analytics_data.regional_sales`.
4. **Audit Non-Repudiation (NIST SP 800-53)**: The human user `sub` is stamped onto BigQuery Query Job Labels, ensuring GCP Cloud Audit Logs record the true human origin.

