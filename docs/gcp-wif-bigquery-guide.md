# Google Cloud Workload Identity Federation & BigQuery MCP Guide
### Secret-Free GCP Authentication &bull; RFC 8693 Token Exchange &bull; Declarative BigQuery Tools

---

## 1. Overview

This guide explains how the Agentic Ecosystem accesses Google Cloud Platform (GCP) resources—specifically **BigQuery** datasets—without long-lived service account keys, using **Workload Identity Federation (WIF)** and **RFC 8693 Security Token Service (STS)** token exchange.

---

## 2. Google Cloud Workload Identity Federation Architecture

In standard GCP architectures, external systems often misuse exported JSON service account keys. In contrast, this solution implements:
1. **OIDC Federation via SPIRE / Keycloak**: GCP Workload Identity Pool trusts tokens signed by the local SPIRE OIDC issuer or Keycloak IdP.
2. **GCP STS Token Exchange (`urn:ietf:params:oauth:grant-type:token-exchange`)**:
   - The agent exchanges an incoming OIDC token for a federated Google STS access token.
   - The token exchange specifies `requested_token_type=urn:ietf:params:oauth:token-type:access_token`.
3. **Downscoped Credential Access Boundaries (CAB)**:
   - Restricts the token to specific BigQuery datasets (`analytics_data` or `audit_logs`).
   - Prevents the token from being used across unintended Google APIs (e.g. Compute Engine, Cloud Storage).
4. **Service Account Impersonation**:
   - The federated identity impersonates `gcp-mcp-sa@<project-id>.iam.gserviceaccount.com` which has BigQuery Data Viewer / Job User roles.

```text
[Agent Orchestrator]
       │
       │ (1. RFC 8693 Token Exchange with Keycloak / SPIRE JWT)
       ▼
[Google Cloud STS: sts.googleapis.com]
       │
       │ (2. Returns Federated GCP STS Token)
       ▼
[Google Cloud IAM Service Account Credentials API: iamcredentials.googleapis.com]
       │
       │ (3. Generates Downscoped Access Token with BigQuery Scopes)
       ▼
[BigQuery MCP Server: port 8081]
       │
       │ (4. tools/call with Bearer OBO JWT preserving sub & act chain)
       ▼
[Google Cloud BigQuery Engine]
       ├── analytics_data.sales_summary
       └── audit_logs.access_audit
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
          allowed_values: ["sales_summary", "regional_metrics"]
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

## 4. Terraform Infrastructure Provisioning

The `terraform/gcp/` module configures the Workload Identity Pool, Provider, and Datasets:

```hcl
# Workload Identity Pool
resource "google_iam_workload_identity_pool" "agent_pool" {
  workload_identity_pool_id = "agent-orchestrator-pool"
  display_name              = "Agent Orchestrator Workload Identity Pool"
}

# OIDC Provider bound to SPIRE / Keycloak
resource "google_iam_workload_identity_pool_provider" "spire_provider" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.agent_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "spire-oidc-provider"
  attribute_mapping = {
    "google.subject" = "assertion.sub"
    "attribute.act"  = "assertion.act.sub"
    "attribute.role" = "assertion.roles"
  }
  oidc {
    issuer_uri = var.oidc_issuer_url
  }
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
