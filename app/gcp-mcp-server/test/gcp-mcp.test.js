const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../src/index');
const jwtUtil = require('../src/jwtUtil');

const fs = require('fs');
const path = require('path');

const googleStsPrivateKey = fs.readFileSync(path.resolve(__dirname, '../../../certs/google-sts-key.pem'), 'utf8');
const JWT_SECRET = process.env.JWT_SECRET || 'demo-obo-token-secret-key-2026';

function mockRequest(method, url, headers = {}, body = {}) {
  return new Promise((resolve) => {
    let capturedStatus = 200;
    let capturedHeaders = {};

    const req = {
      method,
      url,
      headers: {
        'content-type': 'application/json',
        ...headers
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
          status: capturedStatus,
          headers: capturedHeaders,
          body: data
        });
      },
      send(data) {
        try {
          resolve({ status: capturedStatus, headers: capturedHeaders, body: JSON.parse(data) });
        } catch {
          resolve({ status: capturedStatus, headers: capturedHeaders, body: data });
        }
      }
    };

    app.handle(req, res);
  });
}

function mintToken(claims = {}) {
  const payload = {
    iss: 'https://sts.googleapis.com',
    sub: 'bob@example.com',
    aud: 'gcp-bigquery-mcp-server',
    scope: 'mcp:bigquery:query',
    roles: ['regular-user'],
    act: {
      sub: 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
      role: 'orchestrator',
      hop: 2,
      act: {
        sub: 'urn:agent:reasoning-engine:gemini-planner',
        role: 'cognitive-reasoner',
        turn: 2
      }
    },
    delegationType: 'RFC8693_MULTI_HOP',
    ...claims
  };
  return jwtUtil.signRS256(payload, googleStsPrivateKey, { expiresInSeconds: 300 });
}

test('GCP BigQuery MCP Server Test Suite (Spec 2026-07-15 & RFC 8693 Multi-Hop)', async (t) => {

  await t.test('GET /healthz verifies service is UP and identifies as Google Cloud Platform', async () => {
    const res = await mockRequest('GET', '/healthz');
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'UP');
    assert.equal(res.body.cloud, 'Google Cloud Platform (GCP)');
    assert.equal(res.body.protocolVersion, '2026-07-15');
    assert.equal(res.body.toolsRegistered, 2);
  });

  await t.test('POST /mcp initialize returns protocolVersion 2026-07-15 and capabilities', async () => {
    const res = await mockRequest('POST', '/mcp', {}, {
      jsonrpc: '2.0',
      id: 'init-1',
      method: 'initialize',
      params: { protocolVersion: '2026-07-15' }
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.result.protocolVersion, '2026-07-15');
    assert.equal(res.body.result.serverInfo.name, 'gcp-bigquery-lowcode-mcp-server');
    assert.ok(res.body.result.capabilities.tools);
  });

  await t.test('POST /mcp tools/list returns declarative BigQuery tools', async () => {
    const res = await mockRequest('POST', '/mcp', {}, {
      jsonrpc: '2.0',
      id: 'list-1',
      method: 'tools/list'
    });

    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.result.tools));
    const toolNames = res.body.result.tools.map(t => t.name);
    assert.ok(toolNames.includes('bigquery_query_sales'));
    assert.ok(toolNames.includes('bigquery_audit_compliance'));
  });

  await t.test('POST /mcp tools/call rejects requests without Authorization header', async () => {
    const res = await mockRequest('POST', '/mcp', {}, {
      jsonrpc: '2.0',
      id: 'call-unauth',
      method: 'tools/call',
      params: {
        name: 'bigquery_query_sales',
        arguments: { quarter: 'Q2-2026', region: 'north-america', metric: 'revenue_breakdown' }
      }
    });

    assert.equal(res.body.result.isError, true);
    assert.ok(res.body.result.content[0].text.includes('Authentication Failure'));
  });
  await t.test('POST /mcp tools/call rejects insecure symmetric HMAC tokens claiming to be Google IAM', async () => {
    const fakeHmacToken = jwtUtil.sign({
      iss: 'https://sts.googleapis.com',
      sub: 'bob@example.com',
      aud: 'gcp-bigquery-mcp-server'
    }, JWT_SECRET, { expiresInSeconds: 300 });

    const res = await mockRequest('POST', '/mcp', {
      authorization: `Bearer ${fakeHmacToken}`
    }, {
      jsonrpc: '2.0',
      id: 'call-hmac-blocked',
      method: 'tools/call',
      params: {
        name: 'bigquery_query_sales',
        arguments: { quarter: 'Q2-2026', region: 'north-america', metric: 'revenue_breakdown' }
      }
    });

    assert.equal(res.body.result.isError, true);
    assert.ok(res.body.result.content[0].text.includes('Insecure symmetric HMAC') || res.body.result.content[0].text.includes('RS256 PKI is required'));
  });

  await t.test('POST /mcp tools/call rejects tokens issued by Keycloak (enforces Google Cloud IAM protection)', async () => {
    const keycloakToken = mintToken({
      iss: 'https://identity.example.com/realms/azure-wif-realm'
    });

    const res = await mockRequest('POST', '/mcp', {
      authorization: `Bearer ${keycloakToken}`
    }, {
      jsonrpc: '2.0',
      id: 'call-keycloak-blocked',
      method: 'tools/call',
      params: {
        name: 'bigquery_query_sales',
        arguments: { quarter: 'Q2-2026', region: 'north-america', metric: 'revenue_breakdown' }
      }
    });

    assert.equal(res.body.result.isError, true);
    assert.ok(res.body.result.content[0].text.includes('protected by Google Cloud IAM'));
    assert.ok(res.body.result.content[0].text.includes('Keycloak tokens are not accepted'));
  });

  await t.test('POST /mcp tools/call rejects tokens with untrusted actor in multi-hop chain', async () => {
    const rogueToken = mintToken({
      act: {
        sub: 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
        act: {
          sub: 'spiffe://evil-attacker.com/malicious-agent',
          role: 'injected-actor'
        }
      }
    });

    const res = await mockRequest('POST', '/mcp', {
      authorization: `Bearer ${rogueToken}`
    }, {
      jsonrpc: '2.0',
      id: 'call-rogue',
      method: 'tools/call',
      params: {
        name: 'bigquery_query_sales',
        arguments: { quarter: 'Q2-2026', region: 'north-america', metric: 'revenue_breakdown' }
      }
    });

    assert.equal(res.body.result.isError, true);
    assert.ok(res.body.result.content[0].text.includes('RFC 8693 Cryptographic chain verification failed'));
  });

  await t.test('POST /mcp tools/call succeeds for Bob on bigquery_query_sales with multi-hop actor chain', async () => {
    const token = mintToken({
      sub: 'bob@example.com',
      scope: 'mcp:bigquery:query',
      act: {
        sub: 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
        role: 'orchestrator',
        hop: 2,
        act: {
          sub: 'urn:agent:reasoning-engine:gemini-planner',
          role: 'cognitive-reasoner',
          turn: 2,
          act: {
            sub: 'spiffe://example.org/ns/azure/sa/azure-mcp-server',
            role: 'prior-tool-execution',
            hop: 1
          }
        }
      }
    });

    const res = await mockRequest('POST', '/mcp', {
      authorization: `Bearer ${token}`
    }, {
      jsonrpc: '2.0',
      id: 'call-sales',
      method: 'tools/call',
      params: {
        name: 'bigquery_query_sales',
        arguments: {
          quarter: 'Q2-2026',
          region: 'north-america',
          metric: 'revenue_breakdown'
        }
      }
    });

    assert.equal(res.body.result.isError, false);
    assert.equal(res.body.result.audit.principal, 'bob@example.com');
    assert.equal(res.body.result.audit.decision, 'ALLOWED');
    assert.equal(res.body.result.audit.targetBackend, 'gcp_bigquery');
    assert.ok(res.body.result.audit.actorChain.includes('spiffe://example.org/ns/azure/sa/azure-mcp-server'));

    const contentJson = JSON.parse(res.body.result.content[0].text);
    assert.equal(contentJson.status, 'SUCCESS');
    assert.equal(contentJson.data.rows[0].data.totalRevenue, '$14,250,000');
    assert.ok(contentJson.data.labels);
    assert.equal(contentJson.data.labels.delegated_user, 'bob_example_com');
    assert.equal(contentJson.data.labels.actor_orchestrator, 'orchestrator_sa');
    assert.equal(contentJson.data.labels.trace_hop, '5');
  });

  await t.test('POST /mcp tools/call denies Bob on bigquery_audit_compliance (lacks mcp:bigquery:audit)', async () => {
    const token = mintToken({
      sub: 'bob@example.com',
      scope: 'mcp:bigquery:query',
      roles: ['regular-user']
    });

    const res = await mockRequest('POST', '/mcp', {
      authorization: `Bearer ${token}`
    }, {
      jsonrpc: '2.0',
      id: 'call-bob-audit',
      method: 'tools/call',
      params: {
        name: 'bigquery_audit_compliance',
        arguments: {
          dataset: 'audit_logs',
          timeRange: 'last_24h'
        }
      }
    });

    assert.equal(res.body.result.isError, true);
    assert.equal(res.body.result.audit.decision, 'DENIED_BY_POLICY');
    assert.equal(res.body.result.audit.requiredScope, 'mcp:bigquery:audit');
    assert.ok(res.body.result.content[0].text.includes('lacks required scope'));
  });

  await t.test('POST /mcp tools/call allows Alice (admin) on bigquery_audit_compliance', async () => {
    const token = mintToken({
      sub: 'alice@example.com',
      scope: 'mcp:bigquery:query mcp:bigquery:audit',
      roles: ['admin', 'BigQuery.Admin']
    });

    const res = await mockRequest('POST', '/mcp', {
      authorization: `Bearer ${token}`
    }, {
      jsonrpc: '2.0',
      id: 'call-alice-audit',
      method: 'tools/call',
      params: {
        name: 'bigquery_audit_compliance',
        arguments: {
          dataset: 'audit_logs',
          timeRange: 'last_24h'
        }
      }
    });

    assert.equal(res.body.result.isError, false);
    assert.equal(res.body.result.audit.principal, 'alice@example.com');
    assert.equal(res.body.result.audit.decision, 'ALLOWED');

    const contentJson = JSON.parse(res.body.result.content[0].text);
    assert.equal(contentJson.status, 'SUCCESS');
    assert.ok(contentJson.data.auditEvents.length > 0);
  });

  await t.test('POST /mcp tools/call enforces FGP: blocks wildcard query export', async () => {
    const token = mintToken({
      sub: 'alice@example.com',
      scope: 'mcp:bigquery:query',
      roles: ['admin']
    });

    const res = await mockRequest('POST', '/mcp', {
      authorization: `Bearer ${token}`
    }, {
      jsonrpc: '2.0',
      id: 'call-wildcard',
      method: 'tools/call',
      params: {
        name: 'bigquery_query_sales',
        arguments: {
          quarter: 'Q2-2026',
          region: '*',
          metric: 'dump_all'
        }
      }
    });

    assert.equal(res.body.result.isError, true);
    assert.equal(res.body.result.audit.decision, 'DENIED_BY_FGP');
    assert.equal(res.body.result.audit.policyId, 'prevent_unbounded_export');
    assert.ok(res.body.result.content[0].text.includes('Wildcard querying is strictly prohibited'));
  });
});
