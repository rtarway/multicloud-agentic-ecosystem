# Microsoft Entra ID Direct Federation & Multi-Cloud Agentic Architecture

## 1. Executive Summary

In enterprise Agentic AI systems, authorization must balance two competing requirements:
1. **Centralized Enterprise Identity**: Human users must be managed in the corporate Identity Provider (**Keycloak**), where credentials, directory groups, and Multi-Factor Authentication (MFA) reside.
2. **Cloud Resource Governance**: Cloud services (Azure Storage, Cosmos DB, Microsoft Graph, AWS S3, GCP BigQuery) must enforce fine-grained access based on the **human user's delegated permissions**, avoiding over-privileged service accounts or unverified headers.

This document formalizes **Approach 2: Direct Workforce & Workload Federation with Native On-Behalf-Of (OBO)**, providing end-to-end architecture diagrams, token flows, dual-layer policy enforcement models, and multi-cloud extension patterns across Azure, GCP, and AWS.

---

## 2. End-to-End User Experience (UX Flow)

Bob (`bob@example.com`) logs into **Keycloak only**. He **never** has a password in Microsoft Entra ID, and **never** enters credentials twice.

```mermaid
sequenceDiagram
    autonumber
    actor Bob as Bob (Human User)
    participant Browser as Web Browser / Client App
    participant Entra as Microsoft Entra ID (login.microsoftonline.com)
    participant KC as Corporate Keycloak (Identity Authority)
    participant Agent as Agent Orchestrator (Kubernetes)

    Bob->>Browser: 1. Navigates to Application & clicks "Log In"
    Browser->>Entra: 2. Requests Authorization (domain_hint=example.com)
    Note over Entra: Home Realm Discovery (HRD):<br/>Recognizes @example.com is federated to Keycloak
    Entra-->>Browser: 3. Seamless Redirect (302) to Keycloak
    Note over Browser,KC: 4. User enters credentials strictly on Keycloak
    Bob->>KC: Enters corporate username, password & MFA
    KC-->>Browser: 5. Redirects back with signed SAML / OIDC assertion
    Browser->>Entra: 6. Submits Keycloak assertion
    Note over Entra: Entra verifies Keycloak cryptographic signature.<br/>Mints authentic Entra ID User Token (sub = Bob's Entra OID).
    Entra-->>Browser: 7. Returns Entra User Access Token
    Browser->>Agent: 8. Chat Prompt + Entra User Token
```

### Key UX Highlights:
- **Zero Entra Passwords**: Passwords and credentials never touch Microsoft Entra ID.
- **Single Sign-On (SSO)**: If Bob already has an active session with Keycloak, the browser silently bounces through Keycloak and returns to the app in milliseconds without prompting.
- **Delegated Consent**: The first time Bob uses the AI Agent, Entra ID presents a standard OAuth consent dialog (*"Agent Orchestrator would like permission to read storage files on your behalf"*), which Bob accepts once.

---

## 3. Cryptographic Token Flow & Delegation (Azure Native OBO)

This sequence illustrates the cryptographic separation between the **Human Identity** (Keycloak via Entra Federation) and the **Workload Identity** (Kubernetes SPIFFE/SPIRE):

```mermaid
sequenceDiagram
    autonumber
    actor Bob as Human User (Keycloak: bob@example.com)
    participant Orch as Agent Orchestrator (Kubernetes Pod)
    participant Spire as SPIRE Workload API
    participant Entra as Microsoft Entra ID Token Endpoint
    participant MCP as Azure MCP Server (Azure App Service)
    participant Storage as Azure Blob Storage / Microsoft Graph

    Bob->>Orch: 1. Prompt + Entra User Access Token (sub: Bob's Entra OID)
    Orch->>Spire: 2. Request Workload JWT-SVID for audience api://AzureADTokenExchange
    Spire-->>Orch: 3. Cryptographic JWT-SVID (spiffe://example.org/ns/agent-system/sa/orchestrator-sa)

    Note over Orch,Entra: 4. Native Entra ID On-Behalf-Of (OBO) Exchange
    Orch->>Entra: POST /oauth2/v2.0/token<br/>grant_type = urn:ietf:params:oauth:grant-type:jwt-bearer<br/>client_id = a23206e1-2dda-4854-aac7-0536d2da2c4c (k8s-agent-orchestrator)<br/>client_assertion_type = urn:ietf:params:oauth:client-assertion-type:jwt-bearer<br/>client_assertion = <SPIRE_JWT_SVID><br/>assertion = <Bob_Entra_User_Token><br/>scope = api://d5850aa0-a667-41c3-8dd0-16f2dee4da25/user_impersonation
    Note over Entra: Entra verifies SPIRE SVID via WIF.<br/>Entra verifies Bob's user token & consent.<br/>Entra mints Downstream Delegated Token:<br/>- sub = Bob's Entra OID<br/>- appid = k8s-agent-orchestrator<br/>- aud = api://azure-mcp-server<br/>- scp = user_impersonation, mcp:tool1
    Entra-->>Orch: 5. Delegated Downscoped Access Token

    Note over Orch,MCP: 6. Invoke Entra-Protected MCP Server
    Orch->>MCP: POST /mcp (Authorization: Bearer <Delegated Token>)
    Note over MCP: MCP validates token against Microsoft JWKS.<br/>Evaluates tool RBAC & tools.yaml FGP.
    MCP->>Storage: 7. Calls Storage / Graph with Delegated Bearer Token
    Note over Storage: Storage evaluates Bob's Azure RBAC.<br/>Permits read if Bob has Storage Blob Data Reader.
    Storage-->>MCP: 8. Blob Data / Graph Resource
    MCP-->>Orch: 9. MCP Tool Result
    Orch-->>Bob: 10. Synthesized Answer
```

---

## 4. Dual-Layer Policy Enforcement Model

Authorization is enforced at two distinct, complementary boundaries:

```mermaid
flowchart TD
    User["Human User (Bob)"] -->|Prompt + Delegated Token| Agent["Agent Orchestrator"]
    Agent -->|OPA Pre-Flight Check| OPA{"Orchestrator OPA FGP<br/>- Weekend restriction?<br/>- Prompt injection guard?"}
    OPA -->|Denied| DenyOPA["HTTP 200: FAILED_ORCHESTRATOR_FGP"]
    OPA -->|Passed| MCPGateway["Azure MCP Server"]

    subgraph Layer1["Layer 1: MCP Tool & Semantic Governance (Application Layer)"]
        direction TB
        ToolRBAC{"Tool-Level RBAC<br/>Token has required scope/role?<br/>(e.g., lacks 'mcp:tool2')"}
        FGPCheck{"tools.yaml In-Process FGP<br/>- compliance.txt immutable?<br/>- File extension allowed?"}
    end

    subgraph Layer2["Layer 2: Cloud Native IAM (Cloud Data Plane)"]
        direction TB
        CloudRBAC{"Azure Storage / Graph IAM<br/>Does Bob's Entra OID have<br/>'Storage Blob Data Reader'?"}
    end

    MCPGateway --> ToolRBAC
    ToolRBAC -->|No| DenyTool["MCP Protocol Error: isError=true<br/>'DENIED_BY_POLICY'<br/>(Zero Cloud Calls Made)"]
    ToolRBAC -->|Yes| FGPCheck
    FGPCheck -->|No| DenyFGP["MCP Protocol Error: isError=true<br/>'DENIED_BY_FGP'"]
    FGPCheck -->|Yes| CloudRBAC
    CloudRBAC -->|No| DenyCloud["Azure Cloud HTTP 403 Forbidden<br/>(Enforced by Azure Storage Engine)"]
    CloudRBAC -->|Yes| Success["Data Access Succeeded<br/>(Audit: Principal = Bob, Agent = Orchestrator)"]
```

### Responsibility Matrix:

| Policy Concern | Layer 1: MCP Tool Governance | Layer 2: Cloud Native IAM |
| :--- | :--- | :--- |
| **Tool Execution Permission** | **Enforced**: Only authorized tools can be triggered (`mcp:tool1` vs `mcp:tool2`). | N/A: Cloud has no concept of AI tools. |
| **Semantic & File-Level Rules** | **Enforced**: In-process `tools.yaml` blocks tampering with `compliance.txt` or `.exe` files. | Coarse: Cloud RBAC grants broad container access. |
| **Data Plane Access Control** | Pre-filtered: Rejects unauthorized requests early. | **Enforced**: Azure Storage cryptographically ensures Bob has role assignments. |
| **Confused Deputy Prevention** | Mitigated by checking caller `appid` and `sub`. | **Completely Prevented**: Storage only honors Bob's signed token. |
| **Audit Trail Location** | Application / App Service logs (`principal`, `actingAgent`, `decision`). | Azure Storage Analytics, Log Analytics, Microsoft Sentinel (`Caller: Bob's OID`). |

---

## 5. Multi-Cloud Architecture (Azure, GCP, AWS)

This architecture is completely cloud-agnostic. The enterprise maintains **one central Keycloak IdP** and **one Kubernetes SPIRE infrastructure**, federating out to each cloud's federation gateway:

```mermaid
flowchart TD
    Human["Human User (Bob / Alice)"] -->|Signs into Central IdP| KC["Corporate Keycloak IdP"]

    subgraph K8s["Kubernetes Cluster (Any Cloud / On-Prem)"]
        Spire["SPIRE Server"]
        Agent["Agent Orchestrator"]
        Spire -->|Cryptographic SVID| Agent
    end

    KC -->|SAML / OIDC Federation| CloudGateways{"Cloud Workforce Identity Gateways"}

    subgraph Azure["Microsoft Azure"]
        Entra["Microsoft Entra ID B2B Direct Federation"]
        AzureMCP["Azure MCP Server (App Service / ACA)"]
        AzureRes["Storage / Graph / Cosmos DB"]
        Entra --> AzureMCP --> AzureRes
    end

    subgraph GCP["Google Cloud Platform"]
        GCPWIF["GCP Workforce & Workload STS"]
        GCPMCP["GCP MCP Server (Cloud Run / GKE)"]
        GCPRes["Cloud Storage / BigQuery"]
        GCPWIF --> GCPMCP --> GCPRes
    end

    subgraph AWS["Amazon Web Services"]
        AWSSSO["AWS IAM Identity Center + Roles Anywhere"]
        AWSMCP["AWS MCP Server (ECS / Lambda)"]
        AWSRes["S3 / DynamoDB"]
        AWSSSO --> AWSMCP --> AWSRes
    end

    CloudGateways --> Entra
    CloudGateways --> GCPWIF
    CloudGateways --> AWSSSO

    Agent -->|Azure Entra OBO Token| AzureMCP
    Agent -->|GCP STS RFC 8693 Token| GCPMCP
    Agent -->|AWS SigV4 Tagged Session| AWSMCP
```

### Multi-Cloud Mapping:

| Capability | Azure Implementation | GCP Implementation | AWS Implementation |
| :--- | :--- | :--- | :--- |
| **Workforce Federation** | **Entra B2B Direct Federation** (SAML/OIDC) | **GCP Workforce Identity Federation** | **AWS IAM Identity Center** |
| **Workload Federation** | **Azure WIF (RFC 7523)** | **GCP Workload Identity Federation** | **AWS IAM Roles Anywhere / STS** |
| **Delegated User Exchange** | Entra ID OBO Grant (`grant_type=jwt-bearer`) | GCP STS Token Exchange (RFC 8693) | AWS STS `AssumeRole` with Session Tags |
| **Data Plane IAM** | Azure Storage / Graph RBAC | Cloud Storage / BigQuery IAM Conditions | S3 Bucket Policy / DynamoDB IAM |
| **Tool Governance** | Declarative MCP (`tools.yaml`) | Declarative MCP (`tools.yaml`) | Declarative MCP (`tools.yaml`) |

---

## 6. Setup Guide: Configuring Federation between Keycloak & Microsoft Entra ID

There are two methods to establish federation between your Keycloak instance and Microsoft Entra ID:

### Method A: Entra External Identities (SAML 2.0 Direct Federation) - Recommended for B2B

In this pattern, Microsoft Entra ID acts as the Relying Party and delegates authentication for `@example.com` to Keycloak via SAML 2.0.

#### 1. In Keycloak:
1. Navigate to realm `azure-wif-realm` ➔ **Clients** ➔ **Create Client**:
   - **Client type**: `SAML`
   - **Client ID**: `https://login.microsoftonline.com/81f26b58-159c-4879-80a0-bab30b5b4dd3/federation`
   - **Name**: `Microsoft Entra Direct Federation`
2. Configure Client Settings:
   - **Sign Assertions**: `ON`
   - **Sign Documents**: `ON`
   - **Signature Algorithm**: `RSA_SHA256`
   - **Master SAML Processing URL**: `https://login.microsoftonline.com/common/federation/externalfederationauth`
3. Add Protocol Mappers:
   - Map `email` to SAML Attribute: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`
   - Map `username` to SAML NameID: `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
4. Export the SAML Signing Certificate:
   - Realm Settings ➔ **Keys** ➔ Certificate under `RS256` (download as `keycloak-saml.cer`).

#### 2. In Microsoft Entra ID:
1. Open **Azure Portal** ➔ **Microsoft Entra ID** ➔ **External Identities** ➔ **All identity providers**.
2. Click **+ New SAML/WS-Fed IdP**:
   - **Identity provider protocol**: `SAML`
   - **Domain name**: `example.com` (or your partner email domain)
   - **Issuer URI**: `http://<keycloak-host>:8080/realms/azure-wif-realm`
   - **Passive sign-in endpoint**: `http://<keycloak-host>:8080/realms/azure-wif-realm/protocol/saml`
   - **Certificate**: Upload `keycloak-saml.cer`
3. Click **Save**.

---

### Method B: Keycloak Identity Brokering with Microsoft Entra ID

In this pattern, Keycloak acts as the Relying Party, allowing users to sign in with their Microsoft Entra account or brokering identity tokens.

#### 1. In Microsoft Entra ID:
1. Navigate to **App registrations** ➔ **New registration**:
   - **Name**: `keycloak-identity-broker`
   - **Redirect URI**: `Web` ➔ `http://localhost:8080/realms/azure-wif-realm/broker/microsoft/endpoint`
2. Create Client Secret:
   - **Certificates & secrets** ➔ **New client secret**.
3. Expose API Permissions:
   - `User.Read`, `offline_access`.

#### 2. In Keycloak:
1. Open **Identity Providers** ➔ **Add provider...** ➔ **Microsoft** (or **OpenID Connect v1.0**).
2. Enter:
   - **Client ID**: `<ENTRA_APP_ID>`
   - **Client Secret**: `<ENTRA_CLIENT_SECRET>`
   - **Default Scopes**: `openid profile email offline_access`
3. When Bob visits the application, clicking "Sign in with Corporate SSO" delegates to Entra ID, returning an authentic Entra User Token.
