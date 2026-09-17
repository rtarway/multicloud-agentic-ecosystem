// Unit & Integration Tests for A2A Agent Orchestrator
// Uses Node.js native test runner (node:test, node:assert)

const { test, describe, before } = require('node:test');
const assert = require('node:assert');
const { Readable, Writable } = require('stream');
const llmSimulator = require('../src/llmSimulator');
const tokenExchange = require('../src/tokenExchange');
const jwtUtil = require('../src/jwtUtil');
const app = require('../src/index');

const KEYCLOAK_SECRET = 'demo-obo-token-secret-key-2026';

function mintKeycloakToken({ sub, email, roles, scope }) {
  return jwtUtil.sign(
    {
      sub,
      email: email || sub,
      preferred_username: sub.split('@')[0],
      roles: roles || ['regular-user'],
      scope: scope || ''
    },
    KEYCLOAK_SECRET,
    { expiresInSeconds: 3600 }
  );
}

function invokeApp(appInstance, { method = 'POST', url = '/api/agent/chat', headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const req = new Readable();
    req._read = () => {};
    req.method = method;
    req.url = url;

    const normalizedHeaders = {};
    for (const [k, v] of Object.entries(headers)) {
      normalizedHeaders[k.toLowerCase()] = v;
    }

    const data = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : '';
    req.headers = {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(data).toString(),
      ...normalizedHeaders
    };

    let responseData = '';
    const res = new Writable();
    res.statusCode = 200;
    res._headers = {};
    res.setHeader = (k, v) => { res._headers[k.toLowerCase()] = v; };
    res.getHeader = (k) => res._headers[k.toLowerCase()];
    res._write = (chunk, enc, cb) => {
      responseData += chunk.toString();
      cb();
    };
    res.writeHead = (code, headers = {}) => {
      res.statusCode = code;
      Object.assign(res._headers, headers);
    };
    res.end = (chunk) => {
      if (chunk) responseData += chunk.toString();
      try {
        resolve({ statusCode: res.statusCode, body: JSON.parse(responseData) });
      } catch {
        resolve({ statusCode: res.statusCode, body: responseData });
      }
    };

    appInstance.handle(req, res, reject);

    process.nextTick(() => {
      if (data) req.push(data);
      req.push(null);
    });
  });
}

describe('A2A Agent Orchestrator & Token Exchange Tests', () => {
  before(() => {
    // Inject mock MCP dispatcher into app.locals to test end-to-end routing without external sockets
    app.locals.mcpDispatcher = async (toolName, toolArgs, oboToken, delegatedUser, correlationId) => {
      const decoded = jwtUtil.decode(oboToken) || {};
      const scopes = (decoded.scope || '').split(' ');
      const userRoles = delegatedUser?.roles || decoded.roles || [];

      // Cloud IAM RBAC: Bob has no role on container app1
      if (toolName === 'tool1' && toolArgs.container === 'app1' && !userRoles.includes('admin') && !userRoles.includes('Storage Blob Data Reader') && !decoded.sub?.includes('alice')) {
        return {
          isError: true,
          cloudIAMDecision: 'DENIED_BY_AZURE_STORAGE_IAM',
          content: [
            {
              type: 'text',
              text: `Azure Storage Cloud IAM Access Denied (HTTP 403): Principal '${decoded.sub}' lacks required Azure Storage RBAC role ('Storage Blob Data Reader') on container 'app1'.`
            }
          ],
          audit: {
            principal: decoded.sub,
            actingAgent: decoded.act?.sub,
            decision: 'DENIED_BY_AZURE_STORAGE_IAM'
          }
        };
      }

      if (toolName === 'tool2' && !scopes.includes('mcp:tool2')) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `MCP Authorization Denied: Principal '${decoded.sub}' lacks required scope 'mcp:tool2' for tool2.`
            }
          ],
          audit: {
            principal: decoded.sub,
            actingAgent: decoded.act?.sub,
            decision: 'DENIED_BY_POLICY'
          }
        };
      }

      if (toolName === 'send_email_graph') {
        if (!scopes.includes('Mail.Send')) {
          return {
            isError: true,
            content: [{ type: 'text', text: "MCP Authorization Denied: lacks required scope 'Mail.Send'" }],
            audit: { principal: decoded.sub, decision: 'DENIED_BY_POLICY' }
          };
        }
        if (toolArgs.recipient !== 'rtarway@gmail.com') {
          return {
            isError: true,
            content: [{ type: 'text', text: 'Fine-Grained Policy Denial: Email recipient is restricted strictly to rtarway@gmail.com.' }],
            audit: { principal: decoded.sub, decision: 'DENIED_BY_FGP' }
          };
        }
        return {
          isError: false,
          content: [{ type: 'text', text: JSON.stringify({ graphApiStatus: 202, deliveredTo: toolArgs.recipient }) }],
          audit: { principal: decoded.sub, recipient: toolArgs.recipient, decision: 'ALLOWED' }
        };
      }

      return {
        isError: false,
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'SUCCESS',
              tool: toolName,
              container: toolArgs.container,
              filename: toolArgs.filename,
              action: toolArgs.action,
              data: { content: '$14.2M Q2 Revenue (Audited)' }
            })
          }
        ],
        audit: {
          principal: decoded.sub,
          actingAgent: decoded.act?.sub,
          decision: 'ALLOWED'
        }
      };
    };

    // Inject mock GCP MCP dispatcher into app.locals to test multi-cloud routing
    app.locals.gcpMcpDispatcher = async (toolName, toolArgs, oboToken, delegatedUser, correlationId) => {
      const decoded = jwtUtil.decode(oboToken) || {};
      const scopes = (decoded.scope || '').split(' ');

      if (toolName === 'bigquery_audit_compliance' && !scopes.includes('mcp:bigquery:audit')) {
        return {
          isError: true,
          content: [{ type: 'text', text: `MCP Authorization Denied: Principal '${decoded.sub}' lacks required scope 'mcp:bigquery:audit'.` }],
          audit: {
            principal: decoded.sub,
            actingAgent: decoded.act?.sub,
            actorChain: decoded.actorChain,
            requestedTool: toolName,
            requiredScope: 'mcp:bigquery:audit',
            decision: 'DENIED_BY_POLICY'
          }
        };
      }

      return {
        isError: false,
        content: [{
          type: 'text',
          text: JSON.stringify({
            status: 'SUCCESS',
            tool: toolName,
            backend: 'gcp_bigquery',
            data: {
              dataset: 'analytics_data',
              table: 'regional_sales',
              totalRevenue: '$14,250,000',
              activeAccounts: 18420
            },
            audit: {
              userPrincipal: decoded.sub,
              actingAgent: decoded.act?.sub,
              actorChain: decoded.actorChain
            }
          })
        }],
        audit: {
          principal: decoded.sub,
          actingAgent: decoded.act?.sub,
          actorChain: decoded.actorChain,
          requestedTool: toolName,
          targetBackend: 'gcp_bigquery',
          decision: 'ALLOWED'
        }
      };
    };
  });

  test('LLM Simulator accurately plans tool, container, and operation', () => {
    // 1. Read app1
    const plan1 = llmSimulator.plan('Read the quarterly financial report from app1', { sub: 'bob@example.com' });
    assert.strictEqual(plan1.plannedTool, 'tool1');
    assert.strictEqual(plan1.arguments.container, 'app1');
    assert.strictEqual(plan1.arguments.action, 'read');

    // 2. Write app2
    const plan2 = llmSimulator.plan('Update customer retention metrics in app2', { sub: 'bob@example.com' });
    assert.strictEqual(plan2.plannedTool, 'tool1');
    assert.strictEqual(plan2.arguments.container, 'app2');
    assert.strictEqual(plan2.arguments.action, 'write');
    assert.ok(plan2.arguments.content);

    // 3. Tool2 Audit
    const plan3 = llmSimulator.plan('Audit app1 compliance records with tool2', { sub: 'alice@example.com' });
    assert.strictEqual(plan3.plannedTool, 'tool2');
    assert.strictEqual(plan3.arguments.container, 'app1');
    assert.strictEqual(plan3.arguments.action, 'read');
  });

  test('RFC 8693 Token Exchange downscopes scopes for Regular User (Bob)', async () => {
    const bobKeycloakToken = mintKeycloakToken({
      sub: 'bob@example.com',
      roles: ['regular-user']
    });

    const exchangeResult = await tokenExchange.exchangeToken({
      userToken: bobKeycloakToken,
      agentSvid: { spiffeId: 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa' },
      requestedTool: 'tool1'
    });

    assert.strictEqual(exchangeResult.claims.sub, 'bob@example.com');
    assert.strictEqual(exchangeResult.claims.act.sub, 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa');
    assert.strictEqual(exchangeResult.claims.scope, 'mcp:tool1');
    assert.strictEqual(exchangeResult.audit.grantedScopes.includes('mcp:tool2'), false);
  });

  test('RFC 8693 Token Exchange allows tool2 scope for Administrator (Alice)', async () => {
    const aliceKeycloakToken = mintKeycloakToken({
      sub: 'alice@example.com',
      roles: ['admin']
    });

    const exchangeResult = await tokenExchange.exchangeToken({
      userToken: aliceKeycloakToken,
      agentSvid: { spiffeId: 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa' },
      requestedTool: 'tool2'
    });

    assert.strictEqual(exchangeResult.claims.sub, 'alice@example.com');
    assert.strictEqual(exchangeResult.claims.act.sub, 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa');
    assert.strictEqual(exchangeResult.claims.scope, 'mcp:tool2');
  });

  test('Orchestrator OPA FGP: Denies execution when weekend policy is triggered', async () => {
    const bobToken = mintKeycloakToken({ sub: 'bob@example.com', roles: ['regular-user'] });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${bobToken}` },
      body: {
        prompt: 'Write update to app2 container',
        context: { simulate_weekend: true }
      }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'FAILED_ORCHESTRATOR_FGP');
    assert.strictEqual(res.body.opaPolicy.allowed, false);
    assert.ok(res.body.opaPolicy.reason.includes('prohibited on weekends'));
    assert.strictEqual(res.body.mcpResponse.isError, true);
  });

  test('End-to-End Chat: Bob successfully calls tool1 on app1/app2', async () => {
    const bobToken = mintKeycloakToken({ sub: 'bob@example.com', roles: ['regular-user'] });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${bobToken}` },
      body: { prompt: 'Write update to app2 container' }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'COMPLETED_SUCCESSFULLY');
    assert.strictEqual(res.body.oboExchange.subject, 'bob@example.com');
    assert.strictEqual(res.body.oboExchange.actor, 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa');
    assert.strictEqual(res.body.mcpResponse.isError, false);
  });

  test('End-to-End Chat: Bob fails tool2 with MCP Authorization Denied', async () => {
    const bobToken = mintKeycloakToken({ sub: 'bob@example.com', roles: ['regular-user'] });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${bobToken}` },
      body: { prompt: 'Audit app1 compliance using tool2' }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'FAILED_POLICY_CHECK');
    assert.strictEqual(res.body.mcpResponse.isError, true);
    assert.ok(res.body.mcpResponse.content[0].text.includes("lacks required scope 'mcp:tool2'"));
    assert.strictEqual(res.body.mcpResponse.audit.decision, 'DENIED_BY_POLICY');
  });

  test('End-to-End Chat: Alice successfully executes tool2 on app1', async () => {
    const aliceToken = mintKeycloakToken({ sub: 'alice@example.com', roles: ['admin'] });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${aliceToken}` },
      body: { prompt: 'Audit app1 compliance using tool2' }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'COMPLETED_SUCCESSFULLY');
    assert.strictEqual(res.body.oboExchange.subject, 'alice@example.com');
    assert.strictEqual(res.body.mcpResponse.isError, false);
    assert.strictEqual(res.body.mcpResponse.audit.decision, 'ALLOWED');
  });

  test('Multi-Hop Pipeline: Alice executes App1 -> App2 -> Redact -> Graph Email to rtarway@gmail.com', async () => {
    const aliceToken = mintKeycloakToken({
      sub: 'alice@example.com',
      roles: ['admin', 'Storage Blob Data Reader', 'Mail.Send']
    });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${aliceToken}` },
      body: { prompt: 'Read app1 and app2, redact sensitive info, and email summary via Graph API to rtarway@gmail.com' }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'COMPLETED_SUCCESSFULLY');
    assert.strictEqual(res.body.multiHopExecution.completed, true);
    assert.strictEqual(res.body.multiHopExecution.totalSteps, 4);
    assert.strictEqual(res.body.multiHopExecution.executedSteps, 4);
    assert.ok(res.body.multiHopExecution.redactionSummary.redactionsPerformed.length > 0);
    assert.strictEqual(res.body.multiHopExecution.steps[3].tool, 'microsoft_graph_direct');
    assert.strictEqual(res.body.multiHopExecution.steps[3].recipient, 'rtarway@gmail.com');
    assert.strictEqual(res.body.multiHopExecution.steps[3].status, 'SUCCESS');
    assert.strictEqual(res.body.conversationalTurns.length, 4);
    assert.strictEqual(res.body.conversationalTurns[0].intent, 'FETCH_APP1_DATA');
    assert.strictEqual(res.body.conversationalTurns[1].intent, 'FETCH_APP2_DATA');
    assert.strictEqual(res.body.conversationalTurns[2].intent, 'REDACT_AND_SYNTHESIZE');
    assert.strictEqual(res.body.conversationalTurns[3].intent, 'DISPATCH_GRAPH_EMAIL');
    assert.strictEqual(res.body.conversationalTurns[3].invokedTarget.includes('Microsoft Graph API'), true);
    assert.ok(res.body.hopToHop.hop5_graphToken);
    assert.strictEqual(res.body.hopToHop.hop5_graphToken.aud, 'https://graph.microsoft.com');
    assert.deepStrictEqual(res.body.hopToHop.hop5_graphToken.scope, ['Mail.Send']);
    assert.ok(res.body.hopToHop.hop6_graphExecution);
    assert.strictEqual(res.body.hopToHop.hop6_graphExecution.recipient, 'rtarway@gmail.com');
    assert.strictEqual(res.body.hopToHop.hop6_graphExecution.invokedDirectlyBy.includes('Azure Storage MCP Server Bypassed'), true);
  });

  test('Multi-Hop Pipeline: Bob is denied on App1 due to Cloud IAM Storage RBAC policy', async () => {
    const bobToken = mintKeycloakToken({
      sub: 'bob@example.com',
      roles: ['regular-user', 'Storage Blob Data Contributor'] // No app1 role, no Mail.Send
    });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${bobToken}` },
      body: { prompt: 'Read app1 and app2, redact sensitive info, and email summary via Graph API to rtarway@gmail.com' }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'FAILED_POLICY_CHECK');
    assert.strictEqual(res.body.multiHopExecution.completed, false);
    assert.strictEqual(res.body.multiHopExecution.executedSteps, 1);
    assert.strictEqual(res.body.multiHopExecution.steps[0].status, 'DENIED_BY_AZURE_STORAGE_IAM');
    assert.strictEqual(res.body.mcpResponse.cloudIAMDecision, 'DENIED_BY_AZURE_STORAGE_IAM');
  });

  test('Multi-Hop Pipeline: FGP denies sending email to unauthorized recipient', async () => {
    const aliceToken = mintKeycloakToken({
      sub: 'alice@example.com',
      roles: ['admin', 'Storage Blob Data Reader', 'Mail.Send']
    });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${aliceToken}` },
      body: { prompt: 'Read app1 and app2, redact sensitive info, and email summary via Graph API to attacker@evil.com' }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'FAILED_POLICY_CHECK');
    assert.strictEqual(res.body.multiHopExecution.completed, false);
    assert.strictEqual(res.body.multiHopExecution.steps[3].status, 'DENIED_BY_FGP');
    assert.ok(res.body.mcpResponse.content[0].text.includes('Fine-Grained Policy Denial'));
  });

  test('Multi-Hop Pipeline: Alice without Mail.Send is permitted on App1/App2 but denied at Step 4 (No email sent)', async () => {
    const aliceNoMailToken = mintKeycloakToken({
      sub: 'alice@example.com',
      roles: ['admin', 'auditor', 'Storage Blob Data Reader'],
      scope: 'mcp:tool1 mcp:tool2' // Notice NO Mail.Send scope!
    });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${aliceNoMailToken}` },
      body: { prompt: 'Read app1 and app2, redact sensitive info, and email summary via Graph API to rtarway@gmail.com' }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'FAILED_POLICY_CHECK');
    assert.strictEqual(res.body.multiHopExecution.completed, false);
    assert.strictEqual(res.body.multiHopExecution.executedSteps, 4);
    // Step 1: Storage read on app1 succeeded
    assert.strictEqual(res.body.multiHopExecution.steps[0].status, 'SUCCESS');
    // Step 2: Storage read on app2 succeeded
    assert.strictEqual(res.body.multiHopExecution.steps[1].status, 'SUCCESS');
    // Step 3: LLM Redaction succeeded
    assert.strictEqual(res.body.multiHopExecution.steps[2].status, 'SUCCESS');
    // Step 4: Microsoft Graph Email was strictly DENIED
    assert.strictEqual(res.body.multiHopExecution.steps[3].status, 'DENIED_BY_POLICY');
    assert.ok(res.body.mcpResponse.content[0].text.includes('lacks required Microsoft Graph scope \'Mail.Send\''));
  });

  test('Multi-Hop Cross-Cloud Pipeline: Alice executes Azure Storage -> GCP BigQuery -> Cross-Cloud Redaction', async () => {
    const aliceToken = mintKeycloakToken({
      sub: 'alice@example.com',
      roles: ['admin', 'BigQuery.Admin'],
      scope: 'mcp:tool1 mcp:tool2 mcp:bigquery:query mcp:bigquery:audit'
    });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${aliceToken}` },
      body: { prompt: 'Correlate Azure financial report from app1 with GCP BigQuery regional sales telemetry' }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'COMPLETED_SUCCESSFULLY');
    assert.strictEqual(res.body.plan.planType, 'CROSS_CLOUD_PIPELINE');
    assert.strictEqual(res.body.multiHopExecution.completed, true);
    assert.strictEqual(res.body.multiHopExecution.totalSteps, 3);

    // Turn 1: Azure Storage
    assert.strictEqual(res.body.multiHopExecution.steps[0].cloud, 'Azure');
    assert.strictEqual(res.body.multiHopExecution.steps[0].status, 'SUCCESS');

    // Turn 2: GCP BigQuery with recursive RFC 8693 actor chain
    assert.strictEqual(res.body.multiHopExecution.steps[1].cloud, 'GCP');
    assert.strictEqual(res.body.multiHopExecution.steps[1].status, 'SUCCESS');

    // Turn 3: In-Memory LLM Redaction & Synthesis
    assert.strictEqual(res.body.multiHopExecution.steps[2].status, 'SUCCESS');
    assert.ok(res.body.multiHopExecution.redactionSummary.redactionsPerformed.length > 0);

    // Verify Multi-Hop Delegated Actor Chain in Token
    const gcpTokenClaims = res.body.hopToHop.hop5_gcpMultiHopToken;
    assert.strictEqual(gcpTokenClaims.sub, 'alice@example.com'); // Human Subject preserved!
    assert.strictEqual(gcpTokenClaims.act.sub, 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa');
    assert.strictEqual(gcpTokenClaims.act.act.sub, 'urn:agent:reasoning-engine:gemini-planner');
    assert.strictEqual(gcpTokenClaims.act.act.act.sub, 'spiffe://example.org/ns/azure/sa/azure-mcp-server');
    assert.ok(gcpTokenClaims.rawToken);
    assert.ok(gcpTokenClaims.decodedToken.payload.iss === 'https://sts.googleapis.com' || gcpTokenClaims.decodedToken.payload.iss === 'https://accounts.google.com');
    assert.notStrictEqual(gcpTokenClaims.decodedToken.payload.iss, 'https://identity.example.com/realms/azure-wif-realm');
    assert.ok(gcpTokenClaims.issuer.includes('Google Cloud IAM'));
    assert.strictEqual(gcpTokenClaims.tokenType, 'Google Cloud IAM / RFC 8693 Delegated Token');

    // Verify Unified Hop-to-Hop Tokens Presented
    assert.ok(res.body.hopToHop.hop1_userToken.rawToken);
    assert.ok(res.body.hopToHop.hop2_agentIdentity.rawToken);
    assert.ok(res.body.hopToHop.hop3_rfc8693Token.rawToken);
    assert.ok(res.body.hopToHop.hop3_azureToken.rawToken);
    assert.ok(res.body.hopToHop.hop4_storageDelegation.rawToken);
    assert.ok(res.body.hopToHop.hop4_azureExecution.rawToken);
    assert.ok(res.body.hopToHop.hop6_gcpExecution.rawToken);

    // Verify conversational turns contain tokens presented
    assert.strictEqual(res.body.conversationalTurns.length, 3);
    assert.ok(res.body.conversationalTurns[0].tokenExchange.token);
    assert.ok(res.body.conversationalTurns[1].tokenExchange.token);
  });

  test('GCP Single-Step: Bob executes bigquery_query_sales (Allowed)', async () => {
    const bobToken = mintKeycloakToken({
      sub: 'bob@example.com',
      roles: ['regular-user'],
      scope: 'mcp:tool1 mcp:bigquery:query'
    });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${bobToken}` },
      body: { prompt: 'Query BigQuery sales in north-america' }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'COMPLETED_SUCCESSFULLY');
    assert.strictEqual(res.body.plan.cloud, 'GCP');
    assert.strictEqual(res.body.plan.plannedTool, 'bigquery_query_sales');
    assert.strictEqual(res.body.mcpResponse.isError, false);
    assert.strictEqual(res.body.hopToHop.hop3_rfc8693Token.cloud, 'GCP');
    assert.strictEqual(res.body.hopToHop.hop3_rfc8693Token.sub, 'bob@example.com');
  });

  test('GCP Single-Step: Bob fails bigquery_audit_compliance (Scope Denied by Policy)', async () => {
    const bobToken = mintKeycloakToken({
      sub: 'bob@example.com',
      roles: ['regular-user'],
      scope: 'mcp:tool1 mcp:bigquery:query' // Note: lacks mcp:bigquery:audit
    });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${bobToken}` },
      body: { prompt: 'Run BigQuery audit compliance query' }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'FAILED_POLICY_CHECK');
    assert.strictEqual(res.body.mcpResponse.isError, true);
    assert.strictEqual(res.body.mcpResponse.audit.decision, 'DENIED_BY_POLICY');
    assert.strictEqual(res.body.mcpResponse.audit.requiredScope, 'mcp:bigquery:audit');
  });

  test('GCP Single-Step: Alice successfully executes bigquery_audit_compliance (Admin Allowed)', async () => {
    const aliceToken = mintKeycloakToken({
      sub: 'alice@example.com',
      roles: ['admin', 'BigQuery.Admin'],
      scope: 'mcp:tool1 mcp:tool2 mcp:bigquery:query mcp:bigquery:audit'
    });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${aliceToken}` },
      body: { prompt: 'Run BigQuery audit compliance query' }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'COMPLETED_SUCCESSFULLY');
    assert.strictEqual(res.body.mcpResponse.isError, false);
    assert.strictEqual(res.body.mcpResponse.audit.decision, 'ALLOWED');
    assert.strictEqual(res.body.mcpResponse.audit.principal, 'alice@example.com');
  });

  test('Gate 1 RFC 8693 Section 2.1: Charlie (lacks mcp:bigquery:query in IdP) is blocked with SCOPE_ESCALATION_DENIED', async () => {
    const charlieToken = mintKeycloakToken({
      sub: 'charlie@example.com',
      roles: ['auditor', 'Storage Blob Data Reader'],
      scope: 'mcp:tool1 mcp:tool2' // Strictly lacks mcp:bigquery:query!
    });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${charlieToken}` },
      body: { prompt: 'Query BigQuery sales in north-america' }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'FAILED_POLICY_CHECK');
    assert.strictEqual(res.body.code, 'SCOPE_ESCALATION_DENIED');
    assert.ok((res.body.error || res.body.mcpResponse?.content?.[0]?.text || '').includes('lacks required scope'));
  });

  test('Multi-Hop Pipeline with Gate 1: Charlie is blocked at Turn 2 BigQuery (SCOPE_ESCALATION_DENIED)', async () => {
    const charlieToken = mintKeycloakToken({
      sub: 'charlie@example.com',
      roles: ['auditor', 'Storage Blob Data Reader'],
      scope: 'mcp:tool1 mcp:tool2' // Strictly lacks mcp:bigquery:query!
    });

    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/agent/chat',
      headers: { Authorization: `Bearer ${charlieToken}` },
      body: { prompt: 'Correlate Azure financial report from app1 with GCP BigQuery regional sales telemetry' }
    });

    assert.strictEqual(res.statusCode, 200);
    // Turn 1 (Azure Storage) succeeded
    assert.strictEqual(res.body.multiHopExecution.steps[0].status, 'SUCCESS');
    // Turn 2 (BigQuery) halted due to Gate 1 Scope Escalation Denial
    assert.strictEqual(res.body.multiHopExecution.steps[1].status, 'SCOPE_ESCALATION_DENIED');
    assert.strictEqual(res.body.hopToHop.hop5_gcpMultiHopToken.status, 'DENIED_BY_POLICY');
    assert.strictEqual(res.body.hopToHop.hop5_gcpMultiHopToken.code, 'SCOPE_ESCALATION_DENIED');
  });
});

