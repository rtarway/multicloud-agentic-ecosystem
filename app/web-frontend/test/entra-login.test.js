// BFF: Microsoft Entra sign-in for the same user (code + PKCE, public client), tokens kept server-side.

const path = require('path');
const http = require('http');

const MAP_PATH = path.resolve(__dirname, '../../../identity/identity-map.json');
process.env.ALLOW_SIMULATION = 'false';
process.env.OIDC_ISSUER = 'https://idp.test/realms/poc';
process.env.OIDC_CLIENT_ID = 'web-frontend';
process.env.OIDC_REDIRECT_URI = 'http://localhost:3000/auth/callback';
process.env.IDENTITY_MAP_PATH = MAP_PATH;
process.env.ENTRA_TENANT_ID = 'tenant-1';
process.env.ENTRA_BFF_CLIENT_ID = 'bff-client';
process.env.ENTRA_ORCHESTRATOR_APP_ID = 'orch-app';

const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { Readable, Writable } = require('stream');
const { createIdp } = require('../../../shared/test/helpers');
const { createJwksClient } = require('../src/oidc');
const { readLoginConfig, createOidcLogin } = require('../src/oidcLogin');
const { readEntraConfig, createEntraLogin } = require('../src/entraLogin');

const kc = createIdp({ issuer: process.env.OIDC_ISSUER });
const entraIdp = createIdp({ issuer: 'https://login.microsoftonline.com/tenant-1/v2.0', kid: 'entra-key' });
const entraConfig = readEntraConfig();
const loginConfig = readLoginConfig();
const ORIGIN = 'http://localhost:3000';
const JWT = /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\./;
const BOB = 'bob@rtarwaygmail.onmicrosoft.com';

let app, orchestrator, orchestratorSeen, clock, entraBehaviour, entraRequests, authorizeRequests;

// ---- fake Keycloak (only what is needed to get a session) ----
function fakeKeycloak() {
  return async (url, opts) => {
    const p = Object.fromEntries(new URLSearchParams(opts.body));
    const claims = { sub: 'kc-bob', email: BOB, email_verified: true, name: 'Bob POC', preferred_username: 'bob', aud: 'web-frontend', azp: 'web-frontend', nonce: kcNonce };
    return { ok: true, status: 200, json: async () => ({ id_token: kc.sign(claims), access_token: kc.sign({ ...claims, aud: 'agent-orchestrator-client', scope: 'openid mcp:tool1' }), refresh_token: 'r', expires_in: 300 }) };
  };
}
let kcNonce;

// ---- fake Entra token endpoint ----
function fakeEntra() {
  return async (url, opts) => {
    const p = Object.fromEntries(new URLSearchParams(opts.body));
    entraRequests.push(p);
    if (p.grant_type === 'refresh_token') {
      if (entraBehaviour.failRefresh) return { ok: false, status: 400, json: async () => ({ error: 'invalid_grant' }) };
      return { ok: true, status: 200, json: async () => ({ access_token: 'entra-access-refreshed', expires_in: entraBehaviour.refreshExpiresIn ?? 3600, refresh_token: 'entra-refresh-2' }) };
    }
    const tx = authorizeRequests.get(p.code);
    const challenge = crypto.createHash('sha256').update(p.code_verifier || '').digest('base64url');
    if (!tx || challenge !== tx.challenge || p.client_id !== 'bff-client' || p.client_secret !== undefined) {
      return { ok: false, status: 400, json: async () => ({ error: 'invalid_grant' }) };
    }
    const idClaims = { aud: 'bff-client', tid: 'tenant-1', preferred_username: entraBehaviour.upn || BOB, nonce: tx.nonce, ...entraBehaviour.idClaims };
    return { ok: true, status: 200, json: async () => ({ id_token: entraIdp.sign(idClaims), access_token: 'entra-access-1', refresh_token: 'entra-refresh-1', expires_in: entraBehaviour.expiresIn ?? 3600 }) };
  };
}

function invoke({ method = 'GET', url = '/', headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const req = new Readable();
    req._read = () => {};
    req.method = method;
    req.url = url;
    const data = body ? JSON.stringify(body) : '';
    req.headers = { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data).toString(), ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])) };
    let out = '';
    const res = new Writable();
    res.statusCode = 200;
    res._headers = {};
    res.setHeader = (k, v) => { res._headers[k.toLowerCase()] = v; };
    res.getHeader = k => res._headers[k.toLowerCase()];
    res.removeHeader = k => { delete res._headers[k.toLowerCase()]; };
    res.writeHead = (c, h = {}) => { res.statusCode = c; Object.entries(h).forEach(([k, v]) => { res._headers[k.toLowerCase()] = v; }); };
    res._write = (c, e, cb) => { out += c.toString(); cb(); };
    res.end = chunk => {
      if (chunk) out += chunk.toString();
      let parsed = out;
      try { parsed = JSON.parse(out); } catch { /* not json */ }
      resolve({ statusCode: res.statusCode, headers: res._headers, body: parsed, raw: out });
    };
    app.handle(req, res, reject);
    process.nextTick(() => { req.push(data); req.push(null); });
  });
}

const cookiesOf = res => [].concat(res.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
const mergeCookies = (...jars) => jars.filter(Boolean).join('; ');

async function keycloakSignIn() {
  const login = await invoke({ url: '/auth/login' });
  const target = new URL(login.headers.location);
  kcNonce = target.searchParams.get('nonce');
  const cb = await invoke({ url: `/auth/callback?code=c&state=${target.searchParams.get('state')}`, headers: { cookie: cookiesOf(login) } });
  return cookiesOf(cb);
}

async function entraStart(cookie, query = '') {
  const res = await invoke({ url: `/auth/entra/login${query}`, headers: { cookie } });
  if (res.statusCode !== 302) return { res };
  const target = new URL(res.headers.location);
  const code = `ecode-${authorizeRequests.size + 1}`;
  authorizeRequests.set(code, { challenge: target.searchParams.get('code_challenge'), nonce: target.searchParams.get('nonce') });
  return { res, target, code, state: target.searchParams.get('state'), txCookie: cookiesOf(res) };
}

before(async () => {
  orchestrator = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', () => {
      orchestratorSeen.push({ headers: req.headers, body: JSON.parse(body) });
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ status: 'COMPLETED_SUCCESSFULLY' }));
    });
  });
  await new Promise(r => orchestrator.listen(0, '127.0.0.1', r));
  process.env.AGENT_ORCHESTRATOR_URL = `http://127.0.0.1:${orchestrator.address().port}`;
  app = require('../src/index');
});
after(() => new Promise(r => orchestrator.close(r)));

beforeEach(() => {
  clock = Date.now();
  orchestratorSeen = [];
  entraRequests = [];
  authorizeRequests = new Map();
  entraBehaviour = {};
  app.locals.oidcLogin = createOidcLogin({ config: loginConfig, fetchImpl: fakeKeycloak(), jwks: createJwksClient({ issuer: kc.issuer, fetchJson: kc.fetchJson }), now: () => clock });
  app.locals.entraLogin = createEntraLogin({ config: entraConfig, fetchImpl: fakeEntra(), jwks: createJwksClient({ jwksUri: entraConfig.jwksUri, fetchJson: async () => entraIdp.jwks() }), now: () => clock });
});

describe('starting the Entra sign-in', () => {
  test('requires the IdP session first', async () => {
    const res = await invoke({ url: '/auth/entra/login' });
    assert.strictEqual(res.statusCode, 302);
    assert.strictEqual(res.headers.location, '/auth/login');
  });

  test('redirects to Entra with PKCE, the orchestrator scope and a login_hint for the directory-mapped Azure identity', async () => {
    const { target, res } = await entraStart(await keycloakSignIn());
    assert.strictEqual(target.origin + target.pathname, 'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/authorize');
    assert.strictEqual(target.searchParams.get('client_id'), 'bff-client');
    assert.strictEqual(target.searchParams.get('code_challenge_method'), 'S256');
    assert.strictEqual(target.searchParams.get('login_hint'), BOB);
    const scope = target.searchParams.get('scope').split(' ');
    assert.ok(scope.includes('api://orch-app/access_as_user') && scope.includes('offline_access') && scope.includes('openid'));
    assert.strictEqual(target.searchParams.get('prompt'), null, 'interactive by default in the POC tenant');
    assert.match([].concat(res.headers['set-cookie'])[0], /^entra_tx=.*HttpOnly.*SameSite=Lax/);
  });

  test('passes a claims challenge and prompt=none through, and rejects malformed ones', async () => {
    const cookie = await keycloakSignIn();
    const claims = '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}';
    const { target } = await entraStart(cookie, `?claims=${encodeURIComponent(claims)}&prompt=none`);
    assert.strictEqual(target.searchParams.get('claims'), claims);
    assert.strictEqual(target.searchParams.get('prompt'), 'none');
    assert.strictEqual((await invoke({ url: '/auth/entra/login?claims=not-json', headers: { cookie } })).statusCode, 400);
    assert.strictEqual((await invoke({ url: `/auth/entra/login?claims=${'x'.repeat(5000)}`, headers: { cookie } })).statusCode, 400);
    assert.strictEqual((await invoke({ url: '/auth/entra/login?prompt=evil', headers: { cookie } })).statusCode, 400);
  });

  test('refuses when the directory has no Azure identity for the user (fail closed)', async () => {
    const cookie = await keycloakSignIn();
    const saved = app.locals.identityResolver;
    app.locals.identityResolver = null;
    try {
      assert.strictEqual((await invoke({ url: '/auth/entra/login', headers: { cookie } })).statusCode, 403);
    } finally {
      app.locals.identityResolver = saved;
    }
  });
});

describe('completing the Entra sign-in', () => {
  test('stores the Entra token server-side; the browser learns only that Azure is connected', async () => {
    const cookie = await keycloakSignIn();
    const { code, state, txCookie } = await entraStart(cookie);
    const cb = await invoke({ url: `/auth/entra/callback?code=${code}&state=${state}`, headers: { cookie: mergeCookies(cookie, txCookie) } });
    assert.strictEqual(cb.statusCode, 302);
    assert.strictEqual(cb.headers.location, '/');
    assert.ok(!JWT.test(cb.raw) && !cb.raw.includes('entra-access-1'));
    assert.strictEqual(entraRequests[0].client_secret, undefined, 'public client: no secret');

    const session = await invoke({ url: '/api/session', headers: { cookie } });
    assert.deepStrictEqual({ configured: session.body.entra.configured, connected: session.body.entra.connected, upn: session.body.entra.upn }, { configured: true, connected: true, upn: BOB });
    assert.ok(!session.raw.includes('entra-access-1'));
  });

  test('refuses a different Azure account than the authenticated user (nothing is stored)', async () => {
    entraBehaviour = { upn: 'alice@rtarwaygmail.onmicrosoft.com' };
    const cookie = await keycloakSignIn();
    const { code, state, txCookie } = await entraStart(cookie);
    const cb = await invoke({ url: `/auth/entra/callback?code=${code}&state=${state}`, headers: { cookie: mergeCookies(cookie, txCookie) } });
    assert.strictEqual(cb.statusCode, 403);
    assert.strictEqual(cb.body.error, 'ENTRA_USER_MISMATCH');
    assert.strictEqual((await invoke({ url: '/api/session', headers: { cookie } })).body.entra.connected, false);
  });

  test('rejects mismatched state, another session\'s attempt, Entra errors, wrong nonce, tenant or audience', async () => {
    const cookie = await keycloakSignIn();
    const attempt = await entraStart(cookie);
    assert.strictEqual((await invoke({ url: `/auth/entra/callback?code=${attempt.code}&state=${attempt.state}`, headers: { cookie } })).statusCode, 400, 'no entra_tx cookie');

    const otherCookie = await keycloakSignIn();
    const second = await entraStart(cookie);
    const crossSession = await invoke({ url: `/auth/entra/callback?code=${second.code}&state=${second.state}`, headers: { cookie: mergeCookies(otherCookie, second.txCookie) } });
    assert.strictEqual(crossSession.statusCode, 400, 'attempt started in a different session');

    const third = await entraStart(cookie);
    const denied = await invoke({ url: `/auth/entra/callback?error=interaction_required&state=${third.state}`, headers: { cookie: mergeCookies(cookie, third.txCookie) } });
    assert.strictEqual(denied.statusCode, 401, 'prompt=none can fail with interaction_required: retry interactively');

    for (const idClaims of [{ nonce: 'other' }, { tid: 'another-tenant' }, { aud: 'another-client' }]) {
      entraBehaviour = { idClaims };
      const a = await entraStart(cookie);
      const cb = await invoke({ url: `/auth/entra/callback?code=${a.code}&state=${a.state}`, headers: { cookie: mergeCookies(cookie, a.txCookie) } });
      assert.strictEqual(cb.statusCode, 401, JSON.stringify(idClaims));
    }
    assert.strictEqual((await invoke({ url: '/api/session', headers: { cookie } })).body.entra.connected, false);
  });
});

describe('chat carries the server-held Entra token', () => {
  async function connected() {
    const cookie = await keycloakSignIn();
    const { code, state, txCookie } = await entraStart(cookie);
    await invoke({ url: `/auth/entra/callback?code=${code}&state=${state}`, headers: { cookie: mergeCookies(cookie, txCookie) } });
    return cookie;
  }
  const chat = (cookie, extra = {}) => invoke({ method: 'POST', url: '/api/chat', headers: { cookie, origin: ORIGIN, ...(extra.headers || {}) }, body: { prompt: 'Read app2', ...(extra.body || {}) } });

  test('the Entra assertion sent to the orchestrator is the session\'s; a browser-supplied one is ignored', async () => {
    const cookie = await connected();
    const res = await chat(cookie, { headers: { 'x-user-entra-token': 'forged-by-browser' }, body: { userEntraToken: 'forged-in-body' } });
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(orchestratorSeen[0].headers['x-user-entra-token'], 'entra-access-1');
    assert.strictEqual(orchestratorSeen[0].body.userEntraToken, 'entra-access-1');
  });

  test('without an Entra sign-in no assertion is sent (and none from the browser)', async () => {
    const cookie = await keycloakSignIn();
    await chat(cookie, { headers: { 'x-user-entra-token': 'forged-by-browser' } });
    assert.strictEqual(orchestratorSeen[0].headers['x-user-entra-token'], undefined);
    assert.ok(!orchestratorSeen[0].body.userEntraToken);
  });

  test('a near-expiry Entra token is refreshed; a failed refresh disconnects Azure only', async () => {
    entraBehaviour = { expiresIn: 30, refreshExpiresIn: 30 };
    const cookie = await connected();
    await chat(cookie);
    assert.strictEqual(orchestratorSeen[0].headers['x-user-entra-token'], 'entra-access-refreshed');
    assert.ok(entraRequests.some(r => r.grant_type === 'refresh_token' && r.refresh_token === 'entra-refresh-1'));

    entraBehaviour = { failRefresh: true }; // the refreshed token is also about to expire
    const res = await chat(cookie);
    assert.strictEqual(res.statusCode, 200, 'the IdP session is still valid');
    assert.strictEqual(orchestratorSeen.at(-1).headers['x-user-entra-token'], undefined);
    assert.strictEqual((await invoke({ url: '/api/session', headers: { cookie } })).body.entra.connected, false);
  });
});
