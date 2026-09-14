# Low-Code Declarative MCP Server Guide

This guide explains how tools, schemas, and security policies are defined declaratively without imperative boilerplate in `tools.yaml` and served via the **Model Context Protocol (MCP)** JSON-RPC 2.0 interface.

---

## 1. Low-Code Declarative Tool Registry (`tools.yaml`)

Rather than writing imperative HTTP routers, manual JSON schema validators, and custom authorization checks for every tool, tools are declared in `app/mcp-server/tools.yaml`:

```yaml
version: "2026-07-15"
tools:
  - name: "tool1"
    title: "Storage Read/Write Tool for App1 and App2"
    description: "Allows reading and writing blobs in Azure Storage containers app1 and app2. Permitted for regular users and administrators with mcp:tool1 scope."
    required_scope: "mcp:tool1"
    target_backend: "azure_storage"
    allowed_containers:
      - "app1"
      - "app2"
    allowed_actions:
      - "read"
      - "write"
    inputSchema:
      type: "object"
      properties:
        container:
          type: "string"
          enum: ["app1", "app2"]
          description: "Target Azure Blob Storage container"
        action:
          type: "string"
          enum: ["read", "write"]
          description: "Storage action to perform"
        filename:
          type: "string"
          description: "Name of the blob file"
        content:
          type: "string"
          description: "Data content to write (required if action is write)"
      required:
        - "container"
        - "action"
        - "filename"

  - name: "tool2"
    title: "Auditing & Read-Only Tool for App1"
    description: "Provides read-only access strictly to the app1 container for system audits and management. Restricted to administrators with mcp:tool2 scope."
    required_scope: "mcp:tool2"
    target_backend: "azure_storage"
    allowed_containers:
      - "app1"
    allowed_actions:
      - "read"
    inputSchema:
      type: "object"
      properties:
        container:
          type: "string"
          enum: ["app1"]
          description: "Target Azure Blob Storage container (app1 only)"
        action:
          type: "string"
          enum: ["read"]
          description: "Storage action (strictly read)"
        filename:
          type: "string"
          description: "Name of the blob file to read"
      required:
        - "container"
        - "action"
        - "filename"
```

### Adding a New Tool (Low-Code Experience)
To add a new tool (e.g. `tool3` for analytics):
1. Append an entry to `tools.yaml` defining `name`, `required_scope`, `allowed_containers`, and `inputSchema`.
2. The MCP declarative engine (`declarativeEngine.js`) automatically:
   - Registers `tool3` in the `tools/list` endpoint.
   - Enforces schema types and required properties.
   - Evaluates caller scopes from the RFC 8693 token.
   - Rejects unauthorized calls with native MCP error messages.

---

## 2. Declarative Fine-Grained Policy (FGP) Enforcement

In addition to coarse OAuth scopes, `tools.yaml` defines in-process fine-grained safety guardrails:

```yaml
    fine_grained_policies:
      - id: "prevent_audit_tampering"
        description: "Prevents modifying compliance or audit files"
        effect: "DENY"
        condition: "args.action == 'write' && (args.filename.includes('compliance') || args.filename.includes('audit'))"
        message: "Fine-Grained Policy Denial: Compliance and audit records are immutable and cannot be overwritten."
      - id: "restricted_extensions"
        description: "Enforce allowed data file extensions"
        effect: "DENY"
        condition: "!args.filename.endsWith('.json') && !args.filename.endsWith('.txt') && !args.filename.endsWith('.yaml')"
        message: "Fine-Grained Policy Denial: Only .json, .txt, and .yaml files are permitted."
```

---

## 3. Deployment Options

The declarative MCP Server can be deployed in two standard production modes:

### Option A: Azure App Service (Linux Web App)
Deploy with zero account keys using JIT User-Delegation to Azure Storage:
```bash
./scripts/deploy-azure-mcp.sh
```

### Option B: Local / Hybrid Kubernetes
Deploy as a containerized microservice alongside your agent mesh:
```bash
kubectl apply -f k8s/mcp-server-deployment.yaml
```
