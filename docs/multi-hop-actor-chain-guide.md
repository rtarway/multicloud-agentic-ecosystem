# Multi-Hop Actor Delegation & Provenance Architecture Guide
### RFC 8693 &bull; NIST SP 800-207 Zero Trust &bull; OWASP Top 10 for Agentic AI &bull; MAESTRO Framework

---

## 1. Executive Summary

Autonomous and semi-autonomous multi-agent AI ecosystems require interacting across multiple services, tool runtimes, and cloud boundaries (Azure, Google Cloud Platform, AWS, on-premise Kubernetes). When an agent orchestrator receives a prompt from a human user, plans a workflow with an LLM, invokes an Azure MCP Tool, and then recursively invokes a GCP BigQuery MCP Tool, standard OAuth 2.0 bearer tokens suffer from the **Ambient Authority Problem** and **Impersonation Vulnerabilities**:
- If the agent swaps its identity entirely for a service account, the downstream service loses visibility into the original human caller (`sub`), breaking compliance and auditability.
- If the agent merely forwards the user's raw IdP token, downstream tools receive excessive privileges (ambient authority), violating least privilege.
- If multiple agents and tools invoke each other sequentially across multiple turns, intermediate steps become opaque unless cryptographic provenance is stamped onto the delegated token.

This guide details the design, specification, and implementation of **RFC 8693 Section 4.1 Recursive Actor Chains (`act`)** for multi-hop agentic workflows, grounded in **NIST SP 800-207 Zero Trust**, **NIST AI RMF**, **OWASP Top 10 for Agentic AI**, and the **MAESTRO Framework**.

---

## 2. Standards Alignment & Threat Modeling

### 2.1 RFC 8693 Section 4.1 Specification
RFC 8693 §4.1 specifies the `act` (actor) claim:
> *"The `act` (actor) claim provides a means within a JWT to express that delegation has occurred and identify the acting party to whom authority has been delegated."*

When multiple hops or turns of delegation occur:
> *"To represent chained delegation, the actor claim value MAY itself contain an `act` claim representing the party that delegated authority to the actor."*

```json
{
  "sub": "alice@example.com",
  "act": {
    "sub": "spiffe://example.org/ns/agent-system/sa/orchestrator-sa",
    "act": {
      "sub": "urn:agent:reasoning-engine:gemini-planner",
      "act": {
        "sub": "spiffe://example.org/ns/azure/sa/azure-mcp-server"
      }
    }
  }
}
```
In this recursive structure:
1. **Root `sub`**: Unconditionally preserves the human principal (`alice@example.com`).
2. **Immediate Actor (`act.sub`)**: Identifies the presenting client/agent (`orchestrator-sa`).
3. **Turn 1 Reasoning Actor (`act.act.sub`)**: Identifies the cognitive planner or reasoning node.
4. **Prior Hop Provenance (`act.act.act.sub`)**: Identifies the previously executed tool or microservice in the pipeline.

### 2.2 NIST SP 800-207 Zero Trust Architecture Alignment
NIST SP 800-207 mandates:
- **Tenet 1 (All data sources and computing services are resources)**: Both Azure Storage and GCP BigQuery are distinct resources requiring separate cryptographic credentials.
- **Tenet 3 (Access to resources is determined on a per-session basis)**: Tokens must be ephemeral and downscoped strictly to the exact tool call requested.
- **Tenet 6 (Dynamic and strictly enforced access control)**: Contextual evaluation of role, tenant, tool name, and caller chain before granting tool execution.
- **Tenet 7 (Continuous monitoring and auditability)**: The entire actor chain is logged in BigQuery audit logs and Azure audit streams, associating every SQL query or blob operation with both the human caller and each executing agent node.

### 2.3 OWASP Top 10 for LLMs and Agentic AI Mitigations
| OWASP Risk | Threat Description | Architectural Mitigation in POC |
| :--- | :--- | :--- |
| **LLM06: Excessive Agency** | Agent possesses broad, ambient credentials to write/delete across cloud resources. | Strict RFC 8693 downscoping: token requested for GCP BigQuery contains only `mcp:bigquery:query`, unable to call admin APIs or write to Azure Storage. |
| **LLM08: Broken Authorization** | Attacker tricks agent into executing tools against unauthorized resources or users. | Multi-tier validation: Orchestrator OPA engine validates user role (`admin` vs `regular-user`), MCP server re-verifies `sub` and `act` chain before executing declarative tools. |
| **LLM01: Prompt Injection** | Malicious prompt induces agent to exfiltrate cross-cloud data. | PII redaction & sanitization layer (`redactAndSynthesizeMultiCloud`) filters sensitive customer identifiers before cross-cloud transfer. |

### 2.4 MAESTRO Framework for Agentic AI
The MAESTRO Framework (Multi-Agent Evaluation, Security, Traceability, and Orchestration) establishes requirements for agent accountability:
1. **Provenance Traceability**: Every intermediate plan and tool output must be cryptographically linked to the originating prompt and user identity.
2. **Deterministic Delegation**: Agents cannot delegate permissions they do not possess.
3. **Multi-Turn State Auditing**: When Turn 1 (Azure) feeds data into Turn 2 (GCP), Turn 2's token must reflect Turn 1's provenance so the downstream BigQuery engine knows the data originated from an external tool.

---

## 3. Multi-Hop Workflow Architecture

```
                                    +-------------------------------------------------------------+
                                    |                         HUMAN USER                          |
                                    |                   alice@example.com (Admin)                 |
                                    +------------------------------+------------------------------+
                                                                   | 1. Keycloak OIDC JWT
                                                                   v
                                    +-------------------------------------------------------------+
                                    |                 AGENT ORCHESTRATOR SERVICE                  |
                                    |    spiffe://example.org/ns/agent-system/sa/orchestrator-sa   |
                                    +------------------------------+------------------------------+
                                                                   |
                                    +------------------------------+------------------------------+
                                    | 2. Turn 1: LLM Reasoning Engine (gemini-planner)             |
                                    |    Decision: Call Azure Tool 1 (Read App1 Customer Data)    |
                                    +------------------------------+------------------------------+
                                                                   |
                                                                   | 3. RFC 8693 Token Exchange:
                                                                   |    sub: alice@example.com
                                                                   |    act.sub: orchestrator-sa
                                                                   |    scope: mcp:tool1
                                                                   v
                                    +-------------------------------------------------------------+
                                    |                  AZURE STORAGE MCP SERVER                   |
                                    |    spiffe://example.org/ns/azure/sa/azure-mcp-server        |
                                    |    - Validates scope mcp:tool1                              |
                                    |    - Executes JIT User-Delegation read on 'app1'            |
                                    +------------------------------+------------------------------+
                                                                   | 4. Turn 1 Result (Encrypted)
                                                                   v
                                    +-------------------------------------------------------------+
                                    |                 AGENT ORCHESTRATOR SERVICE                  |
                                    | 5. Turn 2: LLM Multi-Cloud Reconciliation                   |
                                    |    Decision: Call GCP BigQuery Sales Table (region: US)     |
                                    +------------------------------+------------------------------+
                                                                   |
                                                                   | 6. RFC 8693 Recursive Exchange:
                                                                   |    sub: alice@example.com
                                                                   |    act.sub: orchestrator-sa
                                                                   |    act.act.sub: urn:agent:gemini-planner
                                                                   |    act.act.act.sub: azure-mcp-server
                                                                   |    scope: mcp:bigquery:query
                                                                   v
                                    +-------------------------------------------------------------+
                                    |                   GCP BIGQUERY MCP SERVER                   |
                                    |    spiffe://example.org/ns/gcp/sa/gcp-mcp-server            |
                                    |    - Verifies recursive act chain provenance                |
                                    |    - Validates FGP parameters (no wildcard SQL)             |
                                    |    - Executes BigQuery query on analytics_data.sales_summary|
                                    +------------------------------+------------------------------+
                                                                   | 7. Turn 2 Result
                                                                   v
                                    +-------------------------------------------------------------+
                                    | 8. Turn 3: Synthesis & PII Redaction                        |
                                    |    - Mask credit cards, emails, SSNs                        |
                                    |    - Return unified cross-cloud report to Web Frontend      |
                                    +-------------------------------------------------------------+
```

---

## 4. Cryptographic Token Payloads Across the Multi-Hop Chain

### Turn 1: Azure Storage Tool Execution
The orchestrator downscopes the Keycloak token for Azure:
```json
{
  "iss": "http://keycloak:8080/realms/azure-wif-realm",
  "aud": "urn:mcp:server:azure-storage",
  "sub": "alice@example.com",
  "exp": 1773400000,
  "iat": 1773396400,
  "scope": "mcp:tool1",
  "act": {
    "sub": "spiffe://example.org/ns/agent-system/sa/orchestrator-sa"
  },
  "roles": ["admin"],
  "tenant_id": "tenant-az-corp"
}
```

### Turn 2: GCP BigQuery Multi-Hop Execution
When the LLM finishes analyzing the Azure result and issues a multi-hop call to GCP BigQuery, the orchestrator constructs the recursive actor chain:
```json
{
  "iss": "http://keycloak:8080/realms/azure-wif-realm",
  "aud": "urn:mcp:server:gcp-bigquery",
  "sub": "alice@example.com",
  "exp": 1773400000,
  "iat": 1773396400,
  "scope": "mcp:bigquery:query",
  "act": {
    "sub": "spiffe://example.org/ns/agent-system/sa/orchestrator-sa",
    "act": {
      "sub": "urn:agent:reasoning-engine:gemini-planner",
      "act": {
        "sub": "spiffe://example.org/ns/azure/sa/azure-mcp-server"
      }
    }
  },
  "roles": ["admin"],
  "project_id": "poc-gcp-wif-project"
}
```

---

## 5. Verification & Security Invariants

1. **Sub Invariant**:
   Under no circumstances may an intermediate agent or tool replace `sub` with its own machine identity. If `sub` is altered, downstream systems cannot perform identity-based row-level security (RLS) or compliance auditing.
2. **Actor Whitelisting**:
   The downstream MCP server enforces that all nodes within `act` belong to approved agent identity patterns (`spiffe://example.org/ns/*` or `urn:agent:*`).
3. **Turn-Based Revocation**:
   Each hop produces an ephemeral token with short TTL (300 seconds). A token created for Turn 1 cannot be reused in Turn 2 because its audience (`aud`) and scopes (`scope`) are cryptographically bound to Azure and rejected by GCP.
4. **FGP Wildcard Sanitization**:
   Wildcard SQL queries (e.g., `SELECT * FROM ...`) are rejected by the Declarative Engine, enforcing that agents specify explicit columns (`SELECT region, total_sales FROM ...`) to prevent accidental bulk exfiltration.
