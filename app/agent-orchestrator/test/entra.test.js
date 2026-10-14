// Entra on-behalf-of from the orchestrator: fine-grained scope per call, SPIFFE client assertion (no secret),
// result verification, identity cross-checks and step-up classification. Entra itself is faked.

process.env.ALLOW_SIMULATION = 'true'; // proves strict calls never fall back to simulation even when it is allowed
process.env.ENTRA_MCP_APP_ID = 'd5850aa0-a667-41c3-8dd0-16f2dee4da25';

const path = require('path');
const { test, describe, beforeEach, afterEach, mock } = require('node:test');
const assert = require('node:assert');
const { createResolver } = require('../src/identityMapping');
const tokenExchange = require('../src/tokenExchange');

const MAP_PATH = path.resolve(__dirname, '../../../identity/identity-map.json');
const resolver = createResolver(MAP_PATH);
const MCP = process.env.ENTRA_MCP_APP_ID;
const ORCH = 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa';

const jwt = claims => `h.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.s`;
const BOB_UPN = 'bob@rtarwaygmail.onmicrosoft.com';
const ALICE_UPN = 'alice@rtarwaygmail.onmicrosoft.com';

function verifiedUser(email, eligibleScopes) {
  const identity = resolver.resolveFromClaims({ email, email_verified: true });
  return { token: 'idp-access-token', identity, roles: [], groups: [...identity.groups], consentedScopes: eligibleScopes, eligibleScopes };
}

const bob = () => verifiedUser(BOB_UPN, ['mcp:tool1']);
const alice = () => verifiedUser('alice@rtarwaygmail.onmicrosoft.com', ['mcp:tool1', 'mcp:tool2', 'Mail.Send']);
const entraAssertion = (upn = BOB_UPN) => jwt({ upn, aud: 'api://orchestrator' });
const oboToken = (overrides = {}) => jwt({ aud: MCP, scp: 'Mcp.Storage.ReadApp2', upn: BOB_UPN, ...overrides });

let entraCalls, entraResponse;
beforeEach(() => {
  entraCalls = [];
  entraResponse = { statusCode: 200, body: { access_token: oboToken() } };
  mock.method(tokenExchange, '_callEntraWifTokenExchange', async params => { entraCalls.push(params); return entraResponse; });
  tokenExchange.setClientAssertionProvider(async () => 'spiffe-jwt-svid-for-entra');
});
afterEach(() => {
  mock.restoreAll();
  tokenExchange.setClientAssertionProvider(null);
});

const exchange = (user, args, extra = {}) => tokenExchange.exchangeToken({
  verifiedUser: user, userToken: user.token, userEntraToken: entraAssertion(), agentSvid: { spiffeId: ORCH },
  requestedTool: 'tool1', toolArgs: { container: 'app2', action: 'read' }, ...args, ...extra
});

describe('OBO request', () => {
  test('requests exactly the delegated scope for the operation, authenticating with the SVID (no client secret)', async () => {
    const result = await exchange(bob());
    assert.strictEqual(result.isError, undefined);
    const p = entraCalls[0];
    assert.strictEqual(p.grant_type, 'urn:ietf:params:oauth:grant-type:jwt-bearer');
    assert.strictEqual(p.requested_token_use, 'on_behalf_of');
    assert.strictEqual(p.scope, `api://${MCP}/Mcp.Storage.ReadApp2`);
    assert.strictEqual(p.assertion, entraAssertion());
    assert.strictEqual(p.client_assertion, 'spiffe-jwt-svid-for-entra');
    assert.strictEqual(p.client_assertion_type, 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    assert.strictEqual(p.client_secret, undefined);
    assert.strictEqual(result.tokenType, 'AZURE_ENTRA_OBO_LIVE');
  });

  test('the scope follows the container and action; tool2 is always ReadApp1; mail uses Graph Mail.Send', async () => {
    const cases = [
      [{ requestedTool: 'tool1', toolArgs: { container: 'app1', action: 'read' } }, 'Mcp.Storage.ReadApp1', 'mcp:tool1'],
      [{ requestedTool: 'tool1', toolArgs: { container: 'app2', action: 'write' } }, 'Mcp.Storage.WriteApp2', 'mcp:tool1'],
      [{ requestedTool: 'tool2', toolArgs: { container: 'app9', action: 'delete' } }, 'Mcp.Storage.ReadApp1', 'mcp:tool2']
    ];
    for (const [args, scopeName] of cases) {
      entraCalls.length = 0;
      entraResponse = { statusCode: 200, body: { access_token: oboToken({ scp: scopeName, upn: ALICE_UPN }) } };
      const result = await exchange(alice(), args, { userEntraToken: entraAssertion(ALICE_UPN) });
      assert.strictEqual(entraCalls[0].scope, `api://${MCP}/${scopeName}`, JSON.stringify(args));
      assert.strictEqual(result.isError, undefined);
    }
    entraCalls.length = 0;
    entraResponse = { statusCode: 200, body: { access_token: jwt({ aud: 'https://graph.microsoft.com', scp: 'Mail.Send', upn: 'alice@rtarwaygmail.onmicrosoft.com' }) } };
    const mail = await exchange(alice(), { requestedTool: 'microsoft_graph_direct', toolArgs: {}, targetAudience: 'https://graph.microsoft.com' }, { userEntraToken: entraAssertion('alice@rtarwaygmail.onmicrosoft.com') });
    assert.strictEqual(entraCalls[0].scope, 'https://graph.microsoft.com/Mail.Send');
    assert.strictEqual(mail.isError, undefined);
  });

  test('unknown containers or actions never reach Entra', async () => {
    for (const toolArgs of [{ container: 'app3', action: 'read' }, { container: 'app1', action: 'delete' }, {}]) {
      const result = await exchange(bob(), { toolArgs });
      assert.strictEqual(result.code, 'INVALID_STORAGE_REQUEST', JSON.stringify(toolArgs));
    }
    assert.strictEqual(entraCalls.length, 0);
  });
});

describe('result verification and identity cross-checks', () => {
  test('rejects tokens with the wrong resource, without the requested scope, or for another user', async () => {
    for (const [overrides, fragment] of [
      [{ aud: 'api://someone-else' }, 'audience'],
      [{ scp: 'Mcp.Storage.ReadApp1' }, 'does not carry the requested delegated scope'],
      [{ scp: 'user_impersonation' }, 'does not carry the requested delegated scope'],
      [{ upn: 'alice@rtarwaygmail.onmicrosoft.com' }, 'different user']
    ]) {
      entraResponse = { statusCode: 200, body: { access_token: oboToken(overrides) } };
      const result = await exchange(bob());
      assert.strictEqual(result.isError, true, JSON.stringify(overrides));
      assert.strictEqual(result.code, 'ENTRA_TOKEN_INVALID');
      assert.ok(result.error.includes(fragment), `${result.error} / ${fragment}`);
      assert.strictEqual(result.exchangedToken, undefined);
    }
  });

  test('an Entra assertion for a different person than the authenticated user is refused before Entra is called', async () => {
    const result = await exchange(bob(), {}, { userEntraToken: entraAssertion('alice@rtarwaygmail.onmicrosoft.com') });
    assert.strictEqual(result.code, 'ENTRA_IDENTITY_MISMATCH');
    assert.strictEqual(entraCalls.length, 0);
  });

  test('a Conditional Access / MFA challenge becomes STEP_UP_REQUIRED with the claims to replay at sign-in', async () => {
    entraResponse = { statusCode: 400, body: { error: 'interaction_required', claims: '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}' } };
    const result = await exchange(bob());
    assert.strictEqual(result.code, 'STEP_UP_REQUIRED');
    assert.strictEqual(result.status, 'STEP_UP_REQUIRED');
    assert.ok(result.claimsChallenge.includes('acrs'));
    assert.strictEqual(result.exchangedToken, undefined);
  });
});

describe('strict mode never degrades, even with ALLOW_SIMULATION=true', () => {
  test('no assertion, a rejection, or an unavailable client assertion all fail with no token', async () => {
    assert.strictEqual((await exchange(bob(), {}, { userEntraToken: null })).code, 'USER_ASSERTION_REQUIRED');

    entraResponse = { statusCode: 400, body: { error: 'invalid_grant' } };
    assert.strictEqual((await exchange(bob())).code, 'ENTRA_OBO_FAILED');

    entraCalls.length = 0;
    tokenExchange.setClientAssertionProvider(async () => { throw new Error('SPIRE agent unavailable'); });
    const result = await exchange(bob());
    assert.strictEqual(result.code, 'ENTRA_OBO_FAILED');
    assert.match(result.error, /SPIRE agent unavailable/);
    assert.strictEqual(entraCalls.length, 0, 'Entra must not be called without a client assertion');
  });

  test('the scope gate still applies first: not eligible or not consented means no Entra call', async () => {
    const noConsent = verifiedUser(BOB_UPN, []);
    const result = await exchange(noConsent);
    assert.strictEqual(result.code, 'SCOPE_ESCALATION_DENIED');
    assert.strictEqual(entraCalls.length, 0);
  });
});
