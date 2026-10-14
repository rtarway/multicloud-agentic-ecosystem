// Strict identity path: verified user tokens, directory mapping, consent, RFC 8693 exchange at the IdP,
// per-call JWT-SVIDs. Everything the IdP and SPIRE would do is faked in-process; nothing here uses the demo secrets.

const path = require('path');
const http = require('http');

// Strict mode is configured from the environment at module load.
const MAP_PATH = path.resolve(__dirname, '../../../identity/identity-map.json');
process.env.ALLOW_SIMULATION = 'true'; // proves strict mode never falls back even when simulation is allowed
process.env.OIDC_ISSUER = 'https://idp.test/realms/poc';
process.env.OIDC_AUDIENCE = 'agent-orchestrator-client';
process.env.OIDC_AUTHORIZED_PARTIES = 'web-frontend';
process.env.IDENTITY_MAP_PATH = MAP_PATH;
process.env.ORCHESTRATOR_CLIENT_SECRET = 'test-client-secret';
process.env.AGENT_SPIFFE_ID = 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert');
const { Readable, Writable } = require('stream');
const { createIdp, startFakeSpireAgent } = require('../../../shared/test/helpers');
const { createJwksClient } = require('../src/oidc');
const { createResolver } = require('../src/identityMapping');
const { createUserAuthenticator } = require('../src/userAuth');
const { createIdpClient } = require('../src/idpExchange');
const tokenExchange = require('../src/tokenExchange');

const ORCH = process.env.AGENT_SPIFFE_ID;
const idp = createIdp({ issuer: process.env.OIDC_ISSUER });
const jwks = createJwksClient({ issuer: idp.issuer, fetchJson: idp.fetchJson });
const resolver = createResolver(MAP_PATH);

// A local "GCP MCP server" that records what the orchestrator sends it, and a fake SPIRE agent.
const received = [];
let mcpServer, spireAgent;

function userToken({ email, scope, azp = 'web-frontend', aud = 'agent-orchestrator-client', ...extra }) {
  return idp.sign({ sub: `kc-${email}`, email, email_verified: true, azp, aud, scope: `openid profile email ${scope || ''}`.trim(), roles: [], ...extra });
}

const ALICE = 'alice@rtarwaygmail.onmicrosoft.com';
const BOB = 'bob@rtarwaygmail.onmicrosoft.com';
const CHARLIE = 'charlie@rtarwaygmail.onmicrosoft.com';

// ---- fake Keycloak token endpoint (standard token exchange) ----
let idpMode = {};
const idpCalls = [];
async function fakeKeycloak(url, opts) {
  const params = Object.fromEntries(new URLSearchParams(opts.body));
  idpCalls.push({ url, params, headers: opts.headers });
  if (idpMode.reject) return { ok: false, status: 400, json: async () => ({ error: 'access_denied' }) };
  if (idpMode.unreachable) throw new Error('connect ECONNREFUSED');
  const subject = JSON.parse(Buffer.from(params.subject_token.split('.')[1], 'base64url').toString());
  const exp = Math.floor(Date.now() / 1000) + (idpMode.ttl || 300);
  const claims = {
    sub: subject.sub, email: subject.email, email_verified: true,
    aud: idpMode.aud || params.audience, azp: 'agent-orchestrator-client',
    scope: idpMode.scope || `profile email ${params.scope}`,
    act: idpMode.noAct ? undefined : { sub: idpMode.actor || ORCH },
    exp
  };
  return { ok: true, status: 200, json: async () => ({ access_token: idp.sign(claims), token_type: 'Bearer', expires_in: 300 }) };
}

let app;
before(async () => {
  mcpServer = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', () => {
      received.push({ headers: req.headers, body: JSON.parse(body) });
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { isError: false, content: [{ type: 'text', text: JSON.stringify({ status: 'SUCCESS', data: { rows: [] } }) }] } }));
    });
  });
  await new Promise(r => mcpServer.listen(0, '127.0.0.1', r));
  process.env.GCP_MCP_ENDPOINT = `http://127.0.0.1:${mcpServer.address().port}`;
  process.env.AZURE_MCP_ENDPOINT = process.env.GCP_MCP_ENDPOINT;

  spireAgent = await startFakeSpireAgent((audience) => [{ spiffeId: ORCH, svid: `svid.for.${audience[0]}` }]);
  process.env.SPIRE_AGENT_SOCKET = spireAgent.socketPath;

  app = require('../src/index');
  // Replace the network-backed pieces built from the environment with in-process fakes
  app.locals.userAuthenticator = createUserAuthenticator({
    config: { issuer: idp.issuer, audience: 'agent-orchestrator-client', jwksUri: '', authorizedParties: ['web-frontend'], identityMapPath: MAP_PATH },
    jwks, resolver
  });
  tokenExchange.setIdpClient(createIdpClient({
    issuer: idp.issuer, tokenEndpoint: `${idp.issuer}/protocol/openid-connect/token`, clientId: 'agent-orchestrator-client',
    clientSecret: 'test-client-secret', jwks, fetchImpl: fakeKeycloak, knownAgentScopes: [...resolver.allAgentScopes]
  }));
});

after(async () => {
  await new Promise(r => mcpServer.close(r));
  await spireAgent.close();
});

function invokeApp({ headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const req = new Readable();
    req._read = () => {};
    req.method = 'POST';
    req.url = '/api/agent/chat';
    const data = JSON.stringify(body || {});
    req.headers = { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data).toString(), ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])) };
    let out = '';
    const res = new Writable();
    res.statusCode = 200;
    res._headers = {};
    res.setHeader = (k, v) => { res._headers[k.toLowerCase()] = v; };
    res.getHeader = k => res._headers[k.toLowerCase()];
    res.removeHeader = k => { delete res._headers[k.toLowerCase()]; };
    res.writeHead = (c, h = {}) => { res.statusCode = c; Object.assign(res._headers, h); };
    res._write = (chunk, enc, cb) => { out += chunk.toString(); cb(); };
    res.end = chunk => {
      if (chunk) out += chunk.toString();
      try { resolve({ statusCode: res.statusCode, body: JSON.parse(out) }); } catch { resolve({ statusCode: res.statusCode, body: out }); }
    };
    app.handle(req, res, reject);
    process.nextTick(() => { req.push(data); req.push(null); });
  });
}

const chat = (token, prompt = 'Query BigQuery sales in north-america', extra = {}) =>
  invokeApp({ headers: token ? { authorization: `Bearer ${token}` } : {}, body: { prompt, ...extra } });

describe('strict mode: the user token is verified, never merely decoded', () => {
  test('no token -> 401', async () => {
    const res = await chat(null);
    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(res.body.code, 'MISSING_BEARER');
  });

  test('a forged (unsigned-by-IdP) token claiming admin roles -> 401', async () => {
    const forged = createIdp({ issuer: idp.issuer }).sign({ email: ALICE, email_verified: true, aud: 'agent-orchestrator-client', azp: 'web-frontend', roles: ['admin'], scope: 'mcp:bigquery:audit' });
    const res = await chat(forged);
    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(res.body.code, 'BAD_SIGNATURE');
  });

  test('wrong audience, wrong authorized party, expired -> 401', async () => {
    assert.strictEqual((await chat(userToken({ email: BOB, aud: 'account' }))).body.code, 'BAD_AUDIENCE');
    assert.strictEqual((await chat(userToken({ email: BOB, azp: 'some-other-client' }))).body.code, 'BAD_AUTHORIZED_PARTY');
    assert.strictEqual((await chat(userToken({ email: BOB, exp: Math.floor(Date.now() / 1000) - 3600 }))).body.code, 'EXPIRED');
  });

  test('HS256 tokens signed with any shared secret are rejected', async () => {
    const hs = require('../src/jwtUtil').sign({ iss: idp.issuer, aud: 'agent-orchestrator-client', azp: 'web-frontend', email: ALICE, email_verified: true }, 'anything');
    const res = await chat(hs);
    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(res.body.code, 'ALG_NOT_ALLOWED');
  });

  test('a verified user with no directory entry, or an unverified email -> 403', async () => {
    const stranger = await chat(userToken({ email: 'mallory@evil.example', scope: 'mcp:tool1' }));
    assert.strictEqual(stranger.statusCode, 403);
    assert.strictEqual(stranger.body.code, 'IDENTITY_NOT_MAPPED');
    const unverified = await chat(userToken({ email: BOB, email_verified: false, scope: 'mcp:tool1' }));
    assert.strictEqual(unverified.statusCode, 403);
    assert.strictEqual(unverified.body.code, 'IDENTITY_EMAIL_UNVERIFIED');
  });
});

describe('strict mode: consent, eligibility and the token exchange', () => {
  test('Bob (eligible + consented) gets an IdP-issued token for exactly one audience and scope; the MCP never sees the user token', async () => {
    received.length = 0; idpCalls.length = 0; idpMode = {};
    const token = userToken({ email: BOB, scope: 'mcp:bigquery:query mcp:tool1' });
    const res = await chat(token);

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'COMPLETED_SUCCESSFULLY');

    // the exchange request
    assert.strictEqual(idpCalls.length, 1);
    const p = idpCalls[0].params;
    assert.strictEqual(p.grant_type, 'urn:ietf:params:oauth:grant-type:token-exchange');
    assert.strictEqual(p.subject_token, token);
    assert.strictEqual(p.audience, 'mcp-gcp-service');
    assert.strictEqual(p.scope, 'mcp:bigquery:query');
    assert.strictEqual(p.client_id, 'agent-orchestrator-client');

    // what the MCP server receives
    assert.strictEqual(received.length, 1);
    const sent = received[0].headers;
    assert.match(sent.authorization, /^Bearer /);
    assert.notStrictEqual(sent.authorization, `Bearer ${token}`, 'the user token must not be forwarded');
    assert.strictEqual(sent['x-agent-identity'], 'svid.for.gcp-mcp-server', 'a JWT-SVID bound to the MCP audience is presented');
    assert.strictEqual(sent['x-delegated-identity'], undefined);

    // the exchanged token is what the IdP minted
    const exchanged = JSON.parse(Buffer.from(sent.authorization.split('.')[1], 'base64url').toString());
    assert.strictEqual(exchanged.aud, 'mcp-gcp-service');
    assert.strictEqual(exchanged.act.sub, ORCH);

    // nothing credential-shaped is returned to the caller
    assert.ok(!/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\./.test(JSON.stringify(res.body)));
  });

  test('a scope the user is eligible for but did not consent to is denied (Alice, audit)', async () => {
    idpCalls.length = 0;
    const res = await chat(userToken({ email: ALICE, scope: 'mcp:bigquery:query' }), 'Run BigQuery audit compliance query');
    assert.strictEqual(res.body.status, 'FAILED_POLICY_CHECK');
    assert.strictEqual(res.body.code, 'SCOPE_ESCALATION_DENIED');
    assert.strictEqual(idpCalls.length, 0, 'no exchange may be attempted without consent');
  });

  test('a scope the user consented to but is not eligible for is denied (Charlie, BigQuery)', async () => {
    idpCalls.length = 0;
    const res = await chat(userToken({ email: CHARLIE, scope: 'mcp:bigquery:query mcp:tool1 mcp:tool2' }));
    assert.strictEqual(res.body.code, 'SCOPE_ESCALATION_DENIED');
    assert.strictEqual(idpCalls.length, 0);
  });

  test('eligible and consented for audit: Alice is exchanged a token carrying only the audit scope', async () => {
    idpCalls.length = 0; received.length = 0;
    const res = await chat(userToken({ email: ALICE, scope: 'mcp:bigquery:query mcp:bigquery:audit' }), 'Run BigQuery audit compliance query');
    assert.strictEqual(res.body.status, 'COMPLETED_SUCCESSFULLY');
    assert.strictEqual(idpCalls[0].params.scope, 'mcp:bigquery:audit');
  });

  test('IdP rejection or outage halts the call: no MCP request, no fallback token', async () => {
    for (const mode of [{ reject: true }, { unreachable: true }]) {
      received.length = 0; idpMode = mode;
      const res = await chat(userToken({ email: BOB, scope: 'mcp:bigquery:query' }));
      assert.strictEqual(res.body.status, 'FAILED_POLICY_CHECK');
      assert.match(res.body.code, /IDP_EXCHANGE_REJECTED|IDP_UNREACHABLE/);
      assert.strictEqual(received.length, 0);
    }
    idpMode = {};
  });

  test('the orchestrator rejects an exchanged token that breaks the contract', async () => {
    const bad = [
      [{ ttl: 3600 }, 'EXCHANGED_TOKEN_TTL'],
      [{ scope: 'profile email mcp:bigquery:query mcp:bigquery:audit' }, 'EXCHANGED_TOKEN_SCOPE'],
      [{ noAct: true }, 'EXCHANGED_TOKEN_ACTOR'],
      [{ actor: 'spiffe://example.org/ns/evil/sa/imposter' }, 'EXCHANGED_TOKEN_ACTOR'],
      [{ aud: 'mcp-azure-service' }, 'EXCHANGED_TOKEN_INVALID']
    ];
    for (const [mode, code] of bad) {
      received.length = 0; idpMode = mode;
      const res = await chat(userToken({ email: BOB, scope: 'mcp:bigquery:query' }));
      assert.strictEqual(res.body.code, code, JSON.stringify(mode));
      assert.strictEqual(received.length, 0);
    }
    idpMode = {};
  });
});

describe('strict mode: Azure leg end to end (Entra faked)', () => {
  const entraAssertion = jwt => jwt;
  const fakeJwt = claims => `h.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.s`;

  test('Bob reads app2: OBO with the SVID as client assertion, then the Azure MCP receives the OBO token and an SVID for it', async () => {
    const { mock } = require('node:test');
    const entraParams = [];
    const spy = mock.method(tokenExchange, '_callEntraWifTokenExchange', async params => {
      entraParams.push(params);
      return { statusCode: 200, body: { access_token: fakeJwt({ aud: process.env.ENTRA_MCP_APP_ID || 'd5850aa0-a667-41c3-8dd0-16f2dee4da25', scp: 'Mcp.Storage.ReadApp2', upn: BOB }) } };
    });
    try {
      received.length = 0; idpMode = {};
      const bobEntra = fakeJwt({ upn: BOB, aud: 'api://orchestrator' });
      const res = await invokeApp({
        headers: { authorization: `Bearer ${userToken({ email: BOB, scope: 'mcp:tool1' })}`, 'x-user-entra-token': bobEntra },
        body: { prompt: 'Read the customer metrics from app2' }
      });
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.body.status, 'COMPLETED_SUCCESSFULLY');

      assert.strictEqual(entraParams.length, 1);
      assert.match(entraParams[0].scope, /\/Mcp\.Storage\.ReadApp2$/);
      assert.strictEqual(entraParams[0].client_assertion, 'svid.for.api://AzureADTokenExchange');
      assert.strictEqual(entraParams[0].client_secret, undefined);
      assert.strictEqual(entraParams[0].assertion, bobEntra);

      const sent = received[0].headers;
      assert.strictEqual(sent['x-agent-identity'], 'svid.for.azure-mcp-server');
      assert.match(sent.authorization, /^Bearer h\./);
      assert.notStrictEqual(sent.authorization, `Bearer ${bobEntra}`, 'the Entra assertion is not forwarded to the MCP');
      assert.ok(!/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\./.test(JSON.stringify(res.body)));
    } finally {
      spy.mock.restore();
    }
  });

  test('a step-up challenge reaches the caller as `stepUp` with the claims to satisfy', async () => {
    const { mock } = require('node:test');
    const spy = mock.method(tokenExchange, '_callEntraWifTokenExchange', async () => ({ statusCode: 400, body: { error: 'interaction_required', claims: '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}' } }));
    try {
      const res = await invokeApp({
        headers: { authorization: `Bearer ${userToken({ email: BOB, scope: 'mcp:tool1' })}`, 'x-user-entra-token': fakeJwt({ upn: BOB }) },
        body: { prompt: 'Read the customer metrics from app2' }
      });
      assert.strictEqual(res.body.code, 'STEP_UP_REQUIRED');
      assert.strictEqual(res.body.stepUp.required, true);
      assert.ok(res.body.stepUp.claims.includes('acrs'));
    } finally {
      spy.mock.restore();
    }
  });
});

describe('strict mode never falls back to simulation', () => {
  test('Azure tools without a user Entra assertion fail even though ALLOW_SIMULATION=true', async () => {
    const res = await chat(userToken({ email: BOB, scope: 'mcp:tool1' }), 'Read the quarterly financial report from app1');
    assert.strictEqual(res.body.status, 'FAILED_POLICY_CHECK');
    assert.strictEqual(res.body.code, 'USER_ASSERTION_REQUIRED');
  });

  test('the legacy decode-only path is unreachable once an authenticator is configured', async () => {
    const res = await chat(require('../src/jwtUtil').sign({ email: ALICE, roles: ['admin'], scope: 'mcp:tool2' }, 'x'));
    assert.strictEqual(res.statusCode, 401);
  });
});
