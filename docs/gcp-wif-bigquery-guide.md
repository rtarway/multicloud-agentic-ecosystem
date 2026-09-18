# Google Cloud Workload Identity Federation & BigQuery MCP Guide
### Secret-Free GCP Authentication &bull; RFC 8693 Token Exchange &bull; Declarative BigQuery Tools

---

## 1. Overview

This guide explains how the Agentic Ecosystem accesses Google Cloud Platform (GCP) resources—specifically **BigQuery** datasets—without long-lived service account keys, using **Workload Identity Federation (WIF)** and **RFC 8693 Security Token Service (STS)** token exchange.

---

## 2. Google Cloud Workload Identity Federation Architecture (Option 3: Direct Subject IAM Grants)

In standard GCP architectures, external systems often misuse exported JSON service account keys or get blocked by the requirement for Google Workspace/Cloud Identity organizations. In contrast, this solution implements **Option 3: Project-Level Workload Identity Federation with Direct Subject IAM Grants**:

1. **OIDC Federation via SPIRE / Keycloak**: The project-level GCP Workload Identity Pool (`k8s-agent-pool`) trusts tokens signed by the local SPIRE OIDC issuer or Keycloak IdP (`spire-oidc-provider`).
2. **Direct Project IAM Subject Member Bindings**:
   - Instead of blanket service account impersonation or requiring an Organization resource, human users (Alice and Bob) are configured directly in Google Cloud IAM as active member principals:
     - `principal://iam.googleapis.com/projects/834200279688/locations/global/workloadIdentityPools/k8s-agent-pool/subject/alice@rtarwaygmail.onmicrosoft.com`
     - `principal://iam.googleapis.com/projects/834200279688/locations/global/workloadIdentityPools/k8s-agent-pool/subject/bob@rtarwaygmail.onmicrosoft.com`
   - Alice holds `roles/bigquery.admin` and `roles/bigquery.dataViewer`.
   - Bob holds `roles/bigquery.dataViewer` (blocked from admin/audit).
   - Charlie holds zero Google Cloud IAM grants (fail-closed Gate 1).
3. **GCP STS Token Exchange (`urn:ietf:params:oauth:grant-type:token-exchange`)**:
   - The agent exchanges an incoming OIDC token for a federated Google STS access token with audience `//iam.googleapis.com/projects/834200279688/locations/global/workloadIdentityPools/k8s-agent-pool/providers/spire-oidc-provider`.
4. **Downscoped Credential Access Boundaries (CAB)**:
   - Restricts the token to specific BigQuery datasets (`analytics_data` or `audit_logs`).
   - Prevents the token from being used across unintended Google APIs.
5. **Authentic RS256 PKI (No Symmetric HMAC)**:
   - Tokens presented to `gcp-mcp-server` are verified using asymmetric RFC 7515 RS256 PKI against Google STS public keys. Insecure symmetric HMAC tokens (`HS256`) are strictly rejected.

```text
[Human User: Alice / Bob / Charlie]
       │
       │ (1. IdP OIDC Token with sub: user@email)
       ▼
[Agent Orchestrator: spiffe://.../orchestrator-sa]
       │
       │ (2. RFC 8693 Token Exchange + CAB Downscoping)
       ▼
[Google Cloud STS: sts.googleapis.com]
  Audience: //iam.googleapis.com/projects/834200279688/locations/global/workloadIdentityPools/k8s-agent-pool/providers/spire-oidc-provider
       │
       │ (3. Evaluates Direct Subject IAM Grants on Project)
       ▼
[Google Cloud IAM Member Policy]
  ├── Alice: roles/bigquery.admin & roles/bigquery.dataViewer
  ├── Bob:   roles/bigquery.dataViewer ONLY
  └── Charlie: ZERO GRANTS (Denied at Gate 1)
       │
       │ (4. Downscoped RS256 Bearer Token)
       ▼
[BigQuery MCP Server: port 8081]
  - Verifies RS256 PKI Signature
  - Enforces Declarative FGP (tools.yaml: blocks SELECT *)
       │
       │ (5. Authorized BigQuery API Query)
       ▼
[Google Cloud BigQuery Engine]
  ├── analytics_data.regional_sales (Alice & Bob: Read Allowed)
  └── audit_logs.access_audit       (Alice: Admin Allowed | Bob: HTTP 403 Denied)
```

---

## 3. Declarative BigQuery MCP Server (July 2026 Spec)

The GCP MCP Server (`app/gcp-mcp-server`) implements Model Context Protocol version `2026-07-15`.
Its tools and fine-grained parameter policies are declared in `tools.yaml`:

```yaml
schema_version: "2026-07-15"
server_name: "gcp-bigquery-mcp-server"
description: "Declarative MCP Server for Google Cloud BigQuery Analytics and Audit"

tools:
  - name: "bigquery_query_sales"
    description: "Executes analytical queries on sales datasets in BigQuery"
    required_scope: "mcp:bigquery:query"
    parameters:
      type: "object"
      properties:
        dataset:
          type: "string"
          allowed_values: ["analytics_data"]
        table:
          type: "string"
          allowed_values: ["regional_sales"]
        query:
          type: "string"
          disallowed_patterns:
            - "(?i)select\\s+\\*" # FGP: Prevents wildcards
            - "(?i)drop\\s+table"
            - "(?i)delete\\s+from"
      required: ["dataset", "table", "query"]

  - name: "bigquery_audit_compliance"
    description: "Queries compliance and multi-cloud audit logs in BigQuery"
    required_scope: "mcp:bigquery:audit"
    required_roles: ["admin"]
    parameters:
      type: "object"
      properties:
        dataset:
          type: "string"
          allowed_values: ["audit_logs"]
        time_window_hours:
          type: "integer"
          minimum: 1
          maximum: 720
      required: ["dataset", "time_window_hours"]
```

### Key Security Guardrails:
1. **Fine-Grained Parameter (FGP) Wildcard Blocking**:
   Any query attempting `SELECT *` is rejected with native MCP protocol error `{ isError: true }`, ensuring agents query only explicit columns.
2. **Dataset Isolation**:
   The sales query tool is strictly constrained to the `analytics_data` dataset.
3. **Role-Gated Compliance Auditing**:
   The `bigquery_audit_compliance` tool enforces that the presenting user possesses the `admin` role in their identity token.

---

## 4. Terraform Infrastructure Provisioning (`terraform/gcp/`)

The `terraform/gcp/` module configures the Workload Identity Pool, Provider, BigQuery Datasets, and Direct Subject IAM Member grants:

```hcl
# 1. Project Workload Identity Pool
resource "google_iam_workload_identity_pool" "agent_pool" {
  workload_identity_pool_id = "k8s-agent-pool"
  display_name              = "Agent WIF Pool"
}

# 2. OIDC Provider bound to SPIRE / Keycloak
resource "google_iam_workload_identity_pool_provider" "spire_provider" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.agent_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "spire-oidc-provider"
  attribute_mapping = {
    "google.subject"      = "assertion.sub"
    "attribute.spiffe_id" = "assertion.sub"
    "attribute.aud"       = "assertion.aud"
  }
  oidc {
    issuer_uri = var.oidc_issuer_url
  }
}

# 3. Direct Project IAM Subject Member Bindings for Alice & Bob
resource "google_project_iam_member" "alice_bq_admin" {
  project = var.gcp_project_id
  role    = "roles/bigquery.admin"
  member  = "principal://iam.googleapis.com/projects/${var.gcp_project_number}/locations/global/workloadIdentityPools/${var.workload_identity_pool_id}/subject/alice@rtarwaygmail.onmicrosoft.com"
}

resource "google_project_iam_member" "alice_bq_viewer" {
  project = var.gcp_project_id
  role    = "roles/bigquery.dataViewer"
  member  = "principal://iam.googleapis.com/projects/${var.gcp_project_number}/locations/global/workloadIdentityPools/${var.workload_identity_pool_id}/subject/alice@rtarwaygmail.onmicrosoft.com"
}

resource "google_project_iam_member" "bob_bq_viewer" {
  project = var.gcp_project_id
  role    = "roles/bigquery.dataViewer"
  member  = "principal://iam.googleapis.com/projects/${var.gcp_project_number}/locations/global/workloadIdentityPools/${var.workload_identity_pool_id}/subject/bob@rtarwaygmail.onmicrosoft.com"
}
```

---

## 5. End-to-End Verification

You can verify the GCP WIF and BigQuery MCP integration using:

```bash
# Run unit and integration tests for GCP MCP server
npm run test:gcp-mcp

# Run the unified verification suite across all 4 microservices
./scripts/test-all.sh

# Run the CLI multi-cloud demo
./scripts/run-demo.sh
```

---

## 6. Audit Lineage & Job Labeling (NIST SP 800-53 AU-2 / AU-3)

When agentic operations run against BigQuery under a delegated Service Account (`gcp-mcp-sa`), Cloud Audit Logs attribute the operation to the Service Account. To satisfy enterprise compliance and non-repudiation:

1. **Job Configuration Labels**: Every BigQuery query job configuration is tagged with metadata:
   ```json
   {
     "labels": {
       "delegated_user": "alice_at_rtarwaygmail_onmicrosoft_com",
       "actor_orchestrator": "orchestrator_sa",
       "trace_hop": "5",
       "tool_name": "bigquery_query_sales"
     }
   }
   ```
2. **Cloud Audit Log Correlation**: In GCP Cloud Logging, queries can be filtered by:
   ```text
   resource.type="bigquery_project"
   protoPayload.serviceData.jobCompletedEvent.job.jobConfiguration.labels.delegated_user="alice_at_rtarwaygmail_onmicrosoft_com"
   ```
   This bridges the gap between machine execution and human user accountability.
