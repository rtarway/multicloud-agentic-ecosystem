#!/usr/bin/env bash
# ==============================================================================
# scripts/run-demo.sh
# End-to-end CLI demonstration runner for Multi-Cloud Agentic Ecosystem (Azure + GCP)
# Validates Alice (Admin) vs Bob (Regular User) with RFC 8693 Multi-Hop Delegated Actor Chains
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================="
echo " Multi-Cloud Agentic Ecosystem: End-to-End CLI Demo"
echo " (Azure Storage WIF + GCP BigQuery WIF + RFC 8693 Multi-Hop Chains)"
echo "================================================================="

node -e "
const http = require('http');
const mcpApp = require('${ROOT_DIR}/app/mcp-server/src/index');
const gcpMcpApp = require('${ROOT_DIR}/app/gcp-mcp-server/src/index');
const agentApp = require('${ROOT_DIR}/app/agent-orchestrator/src/index');
const frontendApp = require('${ROOT_DIR}/app/web-frontend/src/index');
const jwtUtil = require('${ROOT_DIR}/app/agent-orchestrator/src/jwtUtil');

const SECRET = 'demo-obo-token-secret-key-2026';

// Direct in-process wiring for instant, clean CLI demonstration
agentApp.locals.mcpDispatcher = async (name, args, token) => {
  const auth = require('${ROOT_DIR}/app/mcp-server/src/auth').verifyOboToken('Bearer ' + token);
  const engine = new (require('${ROOT_DIR}/app/mcp-server/src/declarativeEngine'))();
  return await engine.executeTool(name, args, auth);
};

agentApp.locals.gcpMcpDispatcher = async (name, args, token) => {
  const auth = require('${ROOT_DIR}/app/gcp-mcp-server/src/auth').verifyGcpOboToken('Bearer ' + token);
  const engine = new (require('${ROOT_DIR}/app/gcp-mcp-server/src/declarativeEngine'))();
  return await engine.executeTool(name, args, auth);
};

frontendApp.locals.agentDispatcher = async (prompt, token) => {
  const plan = require('${ROOT_DIR}/app/agent-orchestrator/src/llmSimulator').plan(prompt, { sub: 'caller' });
  const svid = await require('${ROOT_DIR}/app/agent-orchestrator/src/spireClient').fetchJwtSvid();
  const exchange = await require('${ROOT_DIR}/app/agent-orchestrator/src/tokenExchange').exchangeToken({
    userToken: token,
    agentSvid: svid,
    requestedTool: plan.plannedTool
  });

  const isGcp = plan.cloud === 'GCP' || (plan.plannedTool && plan.plannedTool.startsWith('bigquery_'));
  const mcpRes = isGcp
    ? await agentApp.locals.gcpMcpDispatcher(plan.plannedTool, plan.arguments, exchange.exchangedToken)
    : await agentApp.locals.mcpDispatcher(plan.plannedTool, plan.arguments, exchange.exchangedToken);

  return {
    prompt,
    oboExchange: {
      subject: exchange.claims.sub,
      actor: exchange.claims.act.sub,
      scopes: exchange.claims.scope,
      actorChain: exchange.claims.actorChain
    },
    plan,
    mcpResponse: mcpRes
  };
};

function makeKeycloakToken(sub, roles, scopes) {
  return jwtUtil.sign({
    sub,
    email: sub,
    roles,
    scope: scopes.join(' ')
  }, SECRET, { expiresInSeconds: 3600 });
}

async function runScenario(title, userEmail, roles, scopes, prompt) {
  console.log('\n-------------------------------------------------------------');
  console.log('>>> SCENARIO:', title);
  console.log('-------------------------------------------------------------');
  console.log('1. User Authenticated via Keycloak:');
  console.log('   * Principal:    ', userEmail);
  console.log('   * Realm Roles:  ', roles.join(', '));
  console.log('   * Granted Scope:', scopes.join(', '));

  const userToken = makeKeycloakToken(userEmail, roles, scopes);
  const result = await frontendApp.locals.agentDispatcher(prompt, userToken);

  console.log('2. Simulated LLM Planning:');
  console.log('   * User Prompt:   \"' + prompt + '\"');
  console.log('   * Target Cloud: ', result.plan.cloud || 'Azure');
  console.log('   * Selected Tool:', result.plan.plannedTool);

  console.log('3. RFC 8693 Downscoped OBO Token Exchange:');
  console.log('   * Subject (sub):', result.oboExchange.subject);
  console.log('   * Actor (act):  ', result.oboExchange.actor);
  console.log('   * Scope:        ', result.oboExchange.scopes);
  if (result.oboExchange.actorChain) {
    console.log('   * Actor Lineage:', result.oboExchange.actorChain.join(' -> '));
  }

  console.log('4. MCP Execution:');
  const isErr = result.mcpResponse.isError;
  if (!isErr) {
    console.log('   * Status:        SUCCESS (Allowed by Policy)');
    console.log('   * MCP Content:  ', result.mcpResponse.content[0].text.slice(0, 180) + '...');
  } else {
    console.log('   * Status:        DENIED (Native MCP Protocol Error)');
    console.log('   * Error Message:', result.mcpResponse.content[0].text);
  }
}

async function main() {
  // Azure Scenarios
  await runScenario(
    'Scenario A: Bob (Regular User) - Write status update to Azure app2 (Tool1)',
    'bob@example.com',
    ['regular-user'],
    ['mcp:tool1'],
    'Write new deployment status update to app2'
  );

  await runScenario(
    'Scenario B: Bob (Regular User) - Attempt sensitive audit on Azure app1 (Tool2)',
    'bob@example.com',
    ['regular-user'],
    ['mcp:tool1'],
    'Audit compliance records in app1 using tool2'
  );

  await runScenario(
    'Scenario C: Alice (Admin) - Execute audit on Azure app1 (Tool2)',
    'alice@example.com',
    ['admin'],
    ['mcp:tool1', 'mcp:tool2'],
    'Audit compliance records in app1 using tool2'
  );

  // GCP BigQuery Scenarios
  await runScenario(
    'Scenario D: Bob (Regular User) - Query GCP BigQuery regional sales telemetry',
    'bob@example.com',
    ['regular-user'],
    ['mcp:tool1', 'mcp:bigquery:query'],
    'Query BigQuery sales in north-america'
  );

  await runScenario(
    'Scenario E: Bob (Regular User) - Attempt BigQuery audit compliance (Tool Denied)',
    'bob@example.com',
    ['regular-user'],
    ['mcp:tool1', 'mcp:bigquery:query'],
    'Run BigQuery audit compliance query'
  );

  await runScenario(
    'Scenario F: Alice (Admin) - Execute BigQuery audit compliance (Allowed)',
    'alice@example.com',
    ['admin', 'BigQuery.Admin'],
    ['mcp:tool1', 'mcp:tool2', 'mcp:bigquery:query', 'mcp:bigquery:audit'],
    'Run BigQuery audit compliance query'
  );

  console.log('\n=============================================================');
  console.log('>>> SCENARIO G: Multi-Hop Cross-Cloud Autonomous Pipeline');
  console.log('    (Azure Storage -> LLM Turn 2 -> GCP BigQuery -> Redaction)');
  console.log('=============================================================');

  const aliceToken = makeKeycloakToken('alice@example.com', ['admin', 'BigQuery.Admin'], ['mcp:tool1', 'mcp:tool2', 'mcp:bigquery:query', 'mcp:bigquery:audit']);
  
  // Direct invoke of orchestrator chat
  const prompt = 'Correlate Azure financial report from app1 with GCP BigQuery regional sales telemetry';
  const svid = await require('${ROOT_DIR}/app/agent-orchestrator/src/spireClient').fetchJwtSvid();
  const plan = require('${ROOT_DIR}/app/agent-orchestrator/src/llmSimulator').plan(prompt, { sub: 'alice@example.com' });

  console.log('1. User Initiates Intent: \"' + prompt + '\"');
  console.log('   * Principal (sub): alice@example.com');
  console.log('   * Plan Type:      ' + plan.planType);
  console.log('   * Total Steps:    ' + plan.steps.length);

  console.log('\n2. Turn 1 (Azure Storage Query):');
  const t1Exchange = await require('${ROOT_DIR}/app/agent-orchestrator/src/tokenExchange').exchangeToken({
    userToken: aliceToken,
    agentSvid: svid,
    requestedTool: 'tool1',
    turn: 1
  });
  const t1Res = await agentApp.locals.mcpDispatcher('tool1', plan.steps[0].arguments, t1Exchange.exchangedToken);
  console.log('   * Token 1 Audience: ' + t1Exchange.claims.aud);
  console.log('   * Token 1 Scope:    ' + t1Exchange.claims.scope);
  console.log('   * Result:           ' + (t1Res.isError ? 'FAILED' : 'SUCCESS (HTTP 200)'));

  console.log('\n3. Turn 2 (GCP BigQuery Query with RFC 8693 Recursive Actor Chain):');
  const t2Exchange = await require('${ROOT_DIR}/app/agent-orchestrator/src/tokenExchange').exchangeToken({
    userToken: aliceToken,
    agentSvid: svid,
    requestedTool: 'bigquery_query_sales',
    priorHops: [{ tool: 'tool1', targetResource: '/app1/financial-report.json', status: 'SUCCESS' }],
    turn: 2
  });
  const t2Res = await agentApp.locals.gcpMcpDispatcher('bigquery_query_sales', plan.steps[1].arguments, t2Exchange.exchangedToken);
  console.log('   * Token 2 Audience: ' + t2Exchange.claims.aud);
  console.log('   * Token 2 Scope:    ' + t2Exchange.claims.scope);
  console.log('   * Subject (sub):    ' + t2Exchange.claims.sub + ' (Preserved Human User)');
  console.log('   * Recursive Actor Chain:');
  console.log('       [Outer act.sub] ' + t2Exchange.claims.act.sub + ' (Immediate Orchestrator)');
  console.log('       [Inner act.sub] ' + t2Exchange.claims.act.act.sub + ' (Cognitive Reasoner)');
  console.log('       [Prior act.sub] ' + t2Exchange.claims.act.act.act.sub + ' (Azure MCP Server)');
  console.log('   * Result:           ' + (t2Res.isError ? 'FAILED' : 'SUCCESS (HTTP 200 via GCP BigQuery)'));

  console.log('\n4. Turn 3 (Cross-Cloud LLM Redaction & Synthesis):');
  const redaction = require('${ROOT_DIR}/app/agent-orchestrator/src/llmSimulator').redactAndSynthesizeMultiCloud(
    t1Res.content[0].text,
    t2Res.content[0].text,
    { sub: 'alice@example.com' }
  );
  console.log('   * Redactions Applied: ' + redaction.redactionsPerformed.length);
  console.log('   * Executive Summary Output:\n');
  console.log(redaction.redactedReport);
}

main().catch(err => {
  console.error('Demo error:', err);
  process.exit(1);
});
"
