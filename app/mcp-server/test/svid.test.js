// Azure MCP: agent identity proof (JWT-SVID) and exact actor allow-listing.

process.env.ALLOW_SIMULATION = 'true'; // Entra-shaped tokens are signed with the demo key; the SVID path below is real verification

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const { createIdp } = require('../../../shared/test/helpers');
const { createJwksClient } = require('../src/oidc');
const { verifySvid } = require('../src/spiffe');
const jwtUtil = require('../src/jwtUtil');
const { verifyOboToken, setAgentVerifier, AUTHORIZED_SENDERS } = require('../src/auth');

const ORCH = 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa';
const ORCH_APP = 'a23206e1-2dda-4854-aac7-0536d2da2c4c';
const spire = createIdp({ issuer: 'https://spire.test', kid: 'spire-key' });
const jwks = createJwksClient({ issuer: spire.issuer, fetchJson: spire.fetchJson });
const verifier = token => verifySvid(token, { issuer: spire.issuer, audience: 'azure-mcp-server', jwks, allowedSpiffeIds: [ORCH] });

const entraToken = (claims = {}) => jwtUtil.signRS256({
  iss: 'https://login.microsoftonline.com/81f26b58-159c-4879-80a0-bab30b5b4dd3/v2.0',
  tid: '81f26b58-159c-4879-80a0-bab30b5b4dd3',
  aud: 'api://d5850aa0-a667-41c3-8dd0-16f2dee4da25',
  sub: 'bob@rtarwaygmail.onmicrosoft.com', upn: 'bob@rtarwaygmail.onmicrosoft.com',
  appid: ORCH_APP, scp: 'user_impersonation', roles: ['regular-user'],
  ...claims
}, jwtUtil.getAzureTestKey(), { kid: 'azure-test-key-1', expiresInSeconds: 300 });

const svid = (claims = {}) => spire.sign({ sub: ORCH, aud: ['azure-mcp-server'], ...claims });
const call = (token, agent) => verifyOboToken(`Bearer ${token}`, undefined, agent);

describe('Azure MCP agent identity (JWT-SVID)', () => {
  beforeEach(() => setAgentVerifier(verifier));
  afterEach(() => setAgentVerifier(null));

  test('accepts an Entra token from an authorized app together with a valid SVID', async () => {
    const ctx = await call(entraToken(), svid());
    assert.strictEqual(ctx.authenticated, true);
    assert.strictEqual(ctx.sub, 'bob@rtarwaygmail.onmicrosoft.com');
    assert.deepStrictEqual(ctx.actorChain, [ORCH]);
  });

  test('requires the SVID, and rejects one for another audience or workload', async () => {
    assert.match((await call(entraToken(), undefined)).error, /X-Agent-Identity/);
    assert.match((await call(entraToken(), svid({ aud: ['gcp-mcp-server'] }))).error, /JWT-SVID rejected/);
    assert.match((await call(entraToken(), svid({ sub: `${ORCH}-evil` }))).error, /not an allowed actor/);
  });

  test('the calling Entra application must be an authorized sender', async () => {
    const result = await call(entraToken({ appid: '00000000-0000-0000-0000-000000000000' }), svid());
    assert.strictEqual(result.authenticated, false);
    assert.match(result.error, /not an authorized sender/);
  });

  test('an act claim must agree with the SPIFFE ID proven by the SVID', async () => {
    const result = await call(entraToken({ act: { sub: 'spiffe://example.org/ns/azure/sa/azure-mcp-server' } }), svid());
    assert.strictEqual(result.authenticated, false);
    assert.match(result.error, /does not match the SPIFFE ID/);
  });
});

describe('exact actor allow-list (no prefix matching)', () => {
  test('prefix and urn look-alikes in the delegation chain are rejected', async () => {
    for (const actor of ['spiffe://example.org/ns/attacker/sa/anything', 'urn:agent:evil', 'spiffe://example.org/ns/']) {
      const result = await verifyOboToken(`Bearer ${entraToken({ act: { sub: actor } })}`);
      assert.strictEqual(result.authenticated, false, actor);
      assert.match(result.error, /untrusted actor|unauthorized actor/, actor);
    }
  });

  test('a token with neither an authorized app nor an actor is no longer accepted', async () => {
    const result = await verifyOboToken(`Bearer ${entraToken({ appid: undefined, azp: undefined })}`);
    assert.strictEqual(result.authenticated, false);
  });

  test('the allow-list contains only exact identities', () => {
    assert.ok(AUTHORIZED_SENDERS.every(a => !a.endsWith('/') && !a.endsWith('*')));
    assert.ok(AUTHORIZED_SENDERS.includes(ORCH));
  });
});
