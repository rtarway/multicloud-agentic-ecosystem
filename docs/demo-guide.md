# Step-by-Step Presenter & Demo Guide

This guide details how to demonstrate the Azure WIF + Agentic MCP POC both interactively through the Web Frontend UI and automatically via the command line.

---

## ⚡ Option 1: Instant CLI Demo (Zero Cloud Credentials Needed)

To execute the complete end-to-end flow with pre-configured test scenarios:

```bash
./scripts/run-demo.sh
```

### What You Will Observe:
1. **Scenario 1: Bob (Regular User) writes to app2 using tool1**
   - User logged in as `bob@example.com` (Role: `regular-user`).
   - Token exchanged with SPIRE Agent identity (`spiffe://.../orchestrator-sa`).
   - Downscoped scope: `mcp:tool1`.
   - Result: **SUCCESS** (Blob written to container `app2`).

2. **Scenario 2: Bob (Regular User) attempts to audit app1 using tool2**
   - User prompt asks to audit app1 records with `tool2`.
   - Token exchange attempts downscoping; Bob only has `mcp:tool1`.
   - Azure MCP Server inspects scopes.
   - Result: **DENIED (Native MCP Protocol Error)**:
     ```text
     MCP Authorization Denied: Principal 'bob@example.com' (acting agent 'spiffe://...') lacks required scope 'mcp:tool2' for tool 'tool2'. Current granted scopes: [mcp:tool1].
     ```
   - Audit trail captures `principal: bob@example.com`, `actingAgent: spiffe://...`, and decision `DENIED_BY_POLICY`.

3. **Scenario 3: Alice (Security Admin) audits app1 using tool2**
   - User logged in as `alice@example.com` (Role: `admin`).
   - Exchanged token carries downscoped scope: `mcp:tool2`.
   - Result: **SUCCESS** (Compliance report read from container `app1`).

---

## 🌐 Option 2: Interactive Web UI Walkthrough

### 1. Provision Infrastructure on Rancher Desktop
```bash
./scripts/install-infra.sh
```

### 2. Access the Web Dashboard
Open your browser at:
```text
http://localhost:3000
```
> **Notice**: The web frontend is kept **outside SPIRE**, allowing direct browser access without SPIFFE client cert requirements.

### 3. Interactive Walkthrough Steps:
1. **Login as Bob (Regular User)**:
   - Click the **Bob (Regular)** button.
   - Observe the user badge update to `Regular User` with allowed scope `mcp:tool1`.
2. **Execute Permitted Operation**:
   - Click **Scenario A**: "Write new deployment status report to app2".
   - Click **Submit Prompt to Agent Orchestrator**.
   - Observe the live 4-step token chain:
     - Step 1: Bob's Keycloak token.
     - Step 2: Agent's SPIRE workload identity SVID.
     - Step 3: RFC 8693 Downscoped token showing `sub: bob@example.com` and `act: { sub: spiffe://... }`.
     - Step 4: Azure MCP Server executes `tool1`, showing green **ALLOWED** status.
3. **Execute Restricted Operation**:
   - Click **Scenario C**: "Audit app1 compliance records with tool2".
   - Click **Submit Prompt to Agent Orchestrator**.
   - Observe Step 4 turn red:
     - Native MCP error payload received (`isError: true`).
     - Clear diagnostic message explaining the scope violation.
4. **Switch to Alice (Admin)**:
   - Click **Alice (Admin)** button.
   - Click **Scenario C** again and submit.
   - Observe Step 4 turn green: Alice has `mcp:tool2` scope, so `tool2` audit execution succeeds!

---

## 🧪 Option 3: Run Full Automated Verification Suite
```bash
./scripts/test-all.sh
```
Executes all 17 automated tests across:
- `mcp-server` (Protocol version 2026-07-15, declarative engine, tool1, tool2, scope authorization)
- `agent-orchestrator` (LLM simulation, SPIRE workload API, RFC 8693 token exchange)
- `web-frontend` (Direct browser routing, Keycloak proxying)
