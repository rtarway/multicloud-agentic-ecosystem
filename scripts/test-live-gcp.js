#!/usr/bin/env node
// ==============================================================================
// Live Google Cloud BigQuery & RFC 8693 MCP Verification Runner (Node.js)
// ==============================================================================
// Tests the GCP BigQuery MCP Server directly against live Google Cloud APIs:
// 1. Validates Google Cloud credentials / OAuth token
// 2. Dispatches MCP requests with RFC 8693 recursive actor chains
// 3. Observes query execution, row fetching, and BigQuery Job IDs
// 4. Tests Fine-Grained Parameter (FGP) wildcard enforcement
// ==============================================================================

const path = require('path');
const fs = require('fs');

const rootDir = path.resolve(__dirname, '..');
const envFile = path.join(rootDir, '.env.gcp');

// 1. Load .env.gcp if present
if (fs.existsSync(envFile)) {
  const lines = fs.readFileSync(envFile, 'utf8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
      const [k, ...v] = trimmed.split('=');
      process.env[k.trim()] = v.join('=').trim();
    }
  }
}

const gcpProjectId = process.argv[2] || process.env.GCP_PROJECT_ID || 'gcp-wif-agent-poc';
const gcpAccessToken = process.env.GCP_ACCESS_TOKEN || '';
const isLiveMode = Boolean(process.env.GCP_LIVE_MODE === 'true' && gcpAccessToken);

process.env.GCP_PROJECT_ID = gcpProjectId;
if (isLiveMode) {
  process.env.GCP_LIVE_MODE = 'true';
  process.env.GCP_ACCESS_TOKEN = gcpAccessToken;
}

console.log('=================================================================');
console.log(' 🚀 Google Cloud BigQuery & RFC 8693 MCP Verification Runner');
console.log('=================================================================');
console.log(` Target Project:    ${gcpProjectId}`);
console.log(` Execution Mode:    ${isLiveMode ? '🌐 LIVE_GOOGLE_CLOUD' : '🧪 HERMETIC_SIMULATION (No live GCP token detected)'}`);
if (!isLiveMode) {
  console.log(` 💡 Note: To run against live Google Cloud:`);
  console.log(`    export GCP_LIVE_MODE=true`);
  console.log(`    export GCP_ACCESS_TOKEN=$(gcloud auth print-access-token)`);
  console.log(`    export GCP_PROJECT_ID=your-actual-gcp-project`);
}
console.log('=================================================================\n');

// 2. Load Express App in-process
const app = require(path.join(rootDir, 'app/gcp-mcp-server/src/index.js'));
const jwtUtil = require(path.join(rootDir, 'app/gcp-mcp-server/src/jwtUtil'));

function callMcp(body, bearerToken) {
  return new Promise((resolve) => {
    let capturedStatus = 200;
    let capturedHeaders = {};

    const req = {
      method: 'POST',
      url: '/mcp',
      headers: {
        'content-type': 'application/json',
        'authorization': `Bearer ${bearerToken}`
      },
      body,
      socket: { remoteAddress: '127.0.0.1' },
      connection: { remoteAddress: '127.0.0.1' }
    };

    const res = {
      status(s) {
        capturedStatus = s;
        return this;
      },
      setHeader(k, v) {
        capturedHeaders[k] = v;
        return this;
      },
      json(data) {
        resolve({
          statusCode: capturedStatus,
          data
        });
      },
      send(data) {
        try {
          resolve({ statusCode: capturedStatus, data: JSON.parse(data) });
        } catch {
          resolve({ statusCode: capturedStatus, data });
        }
      }
    };

    app.handle(req, res);
  });
}

async function run() {
  try {
    // Generate Alice RFC 8693 Multi-Hop Token
    const aliceToken = jwtUtil.sign(
      {
        iss: 'https://accounts.google.com',
        aud: 'urn:mcp:server:gcp-bigquery',
        sub: 'alice@example.com',
        roles: ['admin', 'mcp:bigquery:query', 'mcp:bigquery:audit'],
        scope: 'mcp:bigquery:query mcp:bigquery:audit',
        act: {
          sub: 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
          act: {
            sub: 'urn:agent:reasoning-engine:gemini-planner',
            act: {
              sub: 'spiffe://example.org/ns/azure/sa/azure-mcp-server'
            }
          }
        }
      },
      'test-secret',
      { expiresInSeconds: 3600 }
    );

    // =========================================================================
    // TEST 1: Permitted BigQuery Query
    // =========================================================================
    console.log('=================================================================');
    console.log(' 🧪 TEST 1: Execute BigQuery Sales Query (Allowed Region: north-america)');
    console.log('=================================================================');
    console.log('  RFC 8693 Principal:  alice@example.com');
    console.log('  Recursive Lineage:   [orchestrator-sa -> gemini-planner -> azure-mcp-server]');

    const res1 = await callMcp(
      {
        jsonrpc: '2.0',
        id: 'test-1',
        method: 'tools/call',
        params: {
          name: 'bigquery_query_sales',
          arguments: {
            quarter: 'Q2-2026',
            region: 'north-america',
            metric: 'revenue_breakdown'
          }
        }
      },
      aliceToken
    );

    console.log('\n  HTTP Status:', res1.statusCode);
    const content1 = res1.data.result?.content?.[0]?.text;
    const parsed1 = content1 ? JSON.parse(content1) : res1.data;
    const bqData1 = parsed1.data || parsed1;
    console.log('  BigQuery Job ID:   ', bqData1.queryJobId);
    console.log('  Execution Mode:    ', bqData1.executionMode);
    console.log('  Dataset & Table:   ', `${bqData1.dataset}.${bqData1.table}`);
    console.log('  Bytes Processed:   ', bqData1.totalBytesProcessed);
    console.log('  Retrieved Data:    ', JSON.stringify(bqData1.rows?.[0]?.data, null, 2));
    console.log('  Verified Lineage:  ', JSON.stringify(bqData1.rows?.[0]?.verifiedLineage, null, 2));

    // =========================================================================
    // TEST 2: Fine-Grained Parameter (FGP) Wildcard Blocking
    // =========================================================================
    console.log('\n=================================================================');
    console.log(' 🧪 TEST 2: Fine-Grained Parameter Policy Enforcement (Wildcard Region)');
    console.log('=================================================================');
    console.log("  Attempting wildcard query with region='*'");

    const res2 = await callMcp(
      {
        jsonrpc: '2.0',
        id: 'test-2',
        method: 'tools/call',
        params: {
          name: 'bigquery_query_sales',
          arguments: {
            quarter: 'Q2-2026',
            region: '*',
            metric: 'revenue_breakdown'
          }
        }
      },
      aliceToken
    );

    console.log('\n  HTTP Status:       ', res2.statusCode);
    console.log('  MCP isError flag:  ', res2.data.result?.isError);
    console.log('  Protocol Error:    ', res2.data.result?.content?.[0]?.text);
    if (res2.data.result?.isError) {
      console.log('  ✅ SUCCESS: Wildcard query was blocked by Declarative Engine before execution!');
    }

    // =========================================================================
    // TEST 3: Admin BigQuery Audit Logs
    // =========================================================================
    console.log('\n=================================================================');
    console.log(' 🧪 TEST 3: Admin BigQuery Compliance Audit (dataset: audit_logs)');
    console.log('=================================================================');

    const res3 = await callMcp(
      {
        jsonrpc: '2.0',
        id: 'test-3',
        method: 'tools/call',
        params: {
          name: 'bigquery_audit_compliance',
          arguments: {
            dataset: 'audit_logs',
            timeRange: 'last_24h'
          }
        }
      },
      aliceToken
    );

    const content3 = res3.data.result?.content?.[0]?.text;
    const parsed3 = content3 ? JSON.parse(content3) : res3.data;
    const bqData3 = parsed3.data || parsed3;
    console.log('\n  Audit Job ID:      ', bqData3.queryJobId);
    console.log('  Events Retrieved:  ', bqData3.rowCount);
    console.log('  First Event Sample:', JSON.stringify(bqData3.auditEvents?.[0], null, 2));


    console.log('\n=================================================================');
    console.log(' 🎯 Google Cloud Console Observation Links:');
    console.log('=================================================================');
    console.log(` 1. BigQuery Console:`);
    console.log(`    https://console.cloud.google.com/bigquery?project=${gcpProjectId}`);
    console.log(` 2. IAM Audit Logs:`);
    console.log(`    https://console.cloud.google.com/logs/viewer?project=${gcpProjectId}`);
    console.log('=================================================================\n');

    process.exit(0);
  } catch (err) {
    console.error('❌ Test failed with error:', err);
    process.exit(1);
  }
}

run();
