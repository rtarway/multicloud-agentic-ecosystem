// Strict authentication for the GCP MCP server: IdP-issued access token + SPIRE JWT-SVID, bound together.

const path = require('path');
const MAP_PATH = path.resolve(__dirname, '../../../identity/identity-map.json');

process.env.ALLOW_SIMULATION = 'true'; // only for the BigQuery fixtures; authentication below never uses simulation
process.env.OIDC_ISSUER = 'https://idp.test/realms/poc';
process.env.SPIRE_OIDC_ISSUER = 'https://spire.test';
process.env.IDENTITY_MAP_PATH = MAP_PATH;

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { createIdp } = require('../../../shared/test/helpers');
const { createJwksClient } = require('../src/oidc');
const { createResolver } = require('../src/identityMapping');
const { createStrictAuthenticator, readStrictConfig } = require('../src/strictAuth');
const app = require('../src/index');
const jwtUtil = require('../src/jwtUtil');

const ORCH = 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa';
const idp = createIdp({ issuer: process.env.OIDC_ISSUER });
const spire = createIdp({ issuer: process.env.SPIRE_OIDC_ISSUER, kid: 'spire-key' });
const resolver = createResolver(MAP_PATH);

const config = readStrictConfig();
app.locals.strictAuthenticator = createStrictAuthenticator({
  config,
  jwks: createJwksClient({ issuer: idp.issuer, fetchJson: idp.fetchJson }),
  spireJwks: createJwksClient({ issuer: spire.issuer, fetchJson: spire.fetchJson }),
  resolver
});

const BOB = 'bob@rtarwaygmail.onmicrosoft.com';
const ALICE = 'alice@rtarwaygmail.onmicrosoft.com';
const CHARLIE = 'charlie@rtarwaygmail.onmicrosoft.com';

const accessToken = (overrides = {}) => idp.sign({
  sub: 'kc-bob', email: BOB, email_verified: true, aud: 'mcp-gcp-service', azp: 'agent-orchestrator-client',
  scope: 'profile email mcp:bigquery:query', act: { sub: ORCH }, ...overrides
});
const svid = (overrides = {}) => spire.sign({ sub: ORCH, aud: ['gcp-mcp-server'], ...overrides });

function call(headers, tool = 'bigquery_query_sales', args = { quarter: 'Q2-2026', region: 'emea', metric: 'revenue_breakdown' }) {
  return new Promise(resolve => {
    const res = {
      status() { return this; },
      setHeader() { return this; },
      json: data => resolve(data),
      send: data => resolve(data)
    };
    app.handle({
      method: 'POST', url: '/mcp',
      headers: { 'content-type': 'application/json', ...headers },
      body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: tool, arguments: args } },
      socket: { remoteAddress: '127.0.0.1' }
    }, res);
  });
}

const ok = (token, s = svid(), extra = {}) => ({ authorization: `Bearer ${token}`, 'x-agent-identity': s, ...extra });
const denied = async (headers, pattern) => {
  const out = await call(headers);
  assert.equal(out.result.isError, true);
  assert.match(out.result.content[0].text, pattern);
};

describe('GCP MCP strict authentication', () => {
  test('accepts an IdP token for this server plus a matching JWT-SVID, and uses the verified user', async () => {
    const out = await call(ok(accessToken()));
    assert.equal(out.result.isError, false);
    assert.equal(out.result.audit.principal, BOB);
    assert.deepEqual(out.result.audit.actorChain, [ORCH]);
  });

  test('requires the agent identity proof', async () => {
    await denied({ authorization: `Bearer ${accessToken()}` }, /X-Agent-Identity/);
  });

  test('rejects an SVID for another audience, from an unlisted workload, or from another trust domain', async () => {
    await denied(ok(accessToken(), svid({ aud: ['azure-mcp-server'] })), /JWT-SVID rejected/);
    await denied(ok(accessToken(), svid({ sub: 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa-evil' }), {}), /not an allowed actor/);
    await denied(ok(accessToken(), createIdp({ issuer: spire.issuer, kid: 'spire-key' }).sign({ sub: ORCH, aud: ['gcp-mcp-server'] })), /JWT-SVID rejected/);
  });

  test('the token act claim must match the workload proven by the SVID', async () => {
    await denied(ok(accessToken({ act: { sub: 'spiffe://example.org/ns/azure/sa/azure-mcp-server' } })), /does not match the SPIFFE ID/);
  });

  test('a token without an act claim (not issued for agent delegation) is rejected', async () => {
    await denied(ok(accessToken({ act: undefined })), /no act claim/);
  });

  test('nested actors must also be on the exact allow-list', async () => {
    await denied(ok(accessToken({ act: { sub: ORCH, act: { sub: 'spiffe://example.org/ns/evil/sa/x' } } })), /untrusted actor/);
  });

  test('rejects wrong audience, wrong authorized party, expired and HS256 tokens', async () => {
    await denied(ok(accessToken({ aud: 'mcp-azure-service' })), /audience/i);
    await denied(ok(accessToken({ azp: 'web-frontend' })), /authorized party/i);
    await denied(ok(accessToken({ exp: Math.floor(Date.now() / 1000) - 3600 })), /expired/i);
    await denied(ok(jwtUtil.sign({ iss: idp.issuer, aud: 'mcp-gcp-service', email: BOB }, 'secret')), /not allowed/i);
  });

  test('a locally signed "Google STS" demo token is not accepted once strict mode is configured', async () => {
    const demoKey = require('../src/demoKeys').getDemoKey('google', 'private');
    const demo = jwtUtil.signRS256({ iss: 'https://sts.googleapis.com', sub: BOB, aud: 'gcp-bigquery-mcp-server', scope: 'mcp:bigquery:query', act: { sub: ORCH } }, demoKey);
    await denied(ok(demo), /signature|key/i);
  });

  test('user mapping fails closed: unknown user, unverified email, ineligible scope, no agent scope', async () => {
    await denied(ok(accessToken({ email: 'mallory@evil.example' })), /IDENTITY_NOT_MAPPED|No directory entry/);
    await denied(ok(accessToken({ email_verified: false })), /not verified/);
    await denied(ok(accessToken({ email: CHARLIE, scope: 'profile email mcp:bigquery:query' })), /not eligible/);
    await denied(ok(accessToken({ scope: 'profile email' })), /no eligible agent scope/);
  });

  test('scope enforcement still applies per tool (Bob has no audit scope)', async () => {
    const out = await call(ok(accessToken()), 'bigquery_audit_compliance', { dataset: 'audit_logs', timeRange: 'last_24h' });
    assert.equal(out.result.isError, true);
    assert.equal(out.result.audit.decision, 'DENIED_BY_POLICY');
  });

  test('a forged X-Delegated-Identity header cannot change the principal or its roles', async () => {
    const out = await call(ok(accessToken(), svid(), {
      'x-delegated-identity': JSON.stringify({ sub: ALICE, email: ALICE, roles: ['admin', 'BigQuery.Admin'] })
    }), 'bigquery_audit_compliance', { dataset: 'audit_logs', timeRange: 'last_24h' });
    assert.equal(out.result.isError, true);
    assert.equal(out.result.audit.principal, BOB);
  });

  test('exact allow-list also governs the legacy path: prefix look-alikes are rejected', async () => {
    const { AUTHORIZED_SENDERS } = require('../src/auth');
    assert.ok(!AUTHORIZED_SENDERS.some(a => a.endsWith('/')), 'no prefix entries');
    assert.ok(AUTHORIZED_SENDERS.includes(ORCH));
    assert.ok(!AUTHORIZED_SENDERS.includes('spiffe://example.org/ns/agent-system/sa/orchestrator-sa-evil'));
  });

  test('strict mode refuses to start without SPIRE or the identity map configured', () => {
    assert.throws(() => createStrictAuthenticator({ config: { ...config, spireIssuer: '' } }), /SPIRE_OIDC_ISSUER/);
    assert.throws(() => createStrictAuthenticator({ config: { ...config, identityMapPath: '' } }), /IDENTITY_MAP_PATH/);
  });
});
