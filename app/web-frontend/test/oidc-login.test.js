// BFF login: authorization code + PKCE, server-side session, no tokens in the browser.

process.env.ALLOW_SIMULATION = 'false';
process.env.OIDC_ISSUER = 'https://idp.test/realms/poc';
process.env.OIDC_CLIENT_ID = 'web-frontend';
process.env.OIDC_REDIRECT_URI = 'http://localhost:3000/auth/callback';

const { test, describe, beforeEach } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { Readable, Writable } = require('stream');
const { createIdp } = require('../../../shared/test/helpers');
const { createJwksClient } = require('../src/oidc');
const { readLoginConfig, createOidcLogin } = require('../src/oidcLogin');
const app = require('../src/index');

const idp = createIdp({ issuer: process.env.OIDC_ISSUER });
const jwks = createJwksClient({ issuer: idp.issuer, fetchJson: idp.fetchJson });
const config = readLoginConfig();
const ORIGIN = 'http://localhost:3000';
const JWT = /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\./;

let clock, authorizeRequests, tokenRequests, idpBehaviour;

// ---- a fake identity provider: records authorize params, enforces PKCE, mints tokens ----
function fakeFetch() {
  return async (url, opts) => {
    const p = Object.fromEntries(new URLSearchParams(opts.body));
    tokenRequests.push(p);
    if (idpBehaviour.failToken) return { ok: false, status: 400, json: async () => ({ error: 'invalid_grant' }) };
    if (p.grant_type === 'refresh_token') {
      if (idpBehaviour.failRefresh) return { ok: false, status: 400, json: async () => ({ error: 'invalid_grant' }) };
      return { ok: true, status: 200, json: async () => ({ access_token: accessToken('refreshed'), expires_in: 300, refresh_token: 'refresh-2' }) };
    }
    const tx = authorizeRequests.get(p.code);
    const challenge = crypto.createHash('sha256').update(p.code_verifier || '').digest('base64url');
    if (!tx || challenge !== tx.code_challenge || p.redirect_uri !== config.redirectUri || p.client_id !== 'web-frontend') {
      return { ok: false, status: 400, json: async () => ({ error: 'invalid_grant' }) };
    }
    const idClaims = { sub: 'kc-bob', email: 'bob@rtarwaygmail.onmicrosoft.com', email_verified: true, name: 'Bob POC', preferred_username: 'bob', aud: 'web-frontend', azp: 'web-frontend', nonce: tx.nonce, ...idpBehaviour.idClaims };
    return {
      ok: true, status: 200,
      json: async () => ({ id_token: idp.sign(idClaims), access_token: accessToken('first'), refresh_token: 'refresh-1', expires_in: idpBehaviour.expiresIn ?? 300 })
    };
  };
}

const accessToken = tag => idp.sign({ sub: 'kc-bob', email: 'bob@rtarwaygmail.onmicrosoft.com', aud: 'agent-orchestrator-client', azp: 'web-frontend', scope: 'openid profile email mcp:tool1 mcp:bigquery:query', roles: ['agent-scope-mcp-tool1'], jti: tag });

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

const cookiesFrom = res => [].concat(res.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');

// runs the browser's part: /auth/login, then the redirect back with a code
async function signIn({ tamperState = null, dropTx = false, error = null, overrideCode = null } = {}) {
  const login = await invoke({ url: '/auth/login' });
  const target = new URL(login.headers.location);
  const state = target.searchParams.get('state');
  const code = overrideCode || `code-${authorizeRequests.size + 1}`;
  authorizeRequests.set(code, { code_challenge: target.searchParams.get('code_challenge'), nonce: target.searchParams.get('nonce') });
  const qs = new URLSearchParams(error ? { error, state } : { code, state: tamperState || state });
  const callback = await invoke({ url: `/auth/callback?${qs}`, headers: dropTx ? {} : { cookie: cookiesFrom(login) } });
  return { login, target, callback, cookie: cookiesFrom(callback) };
}

beforeEach(() => {
  clock = Date.now();
  authorizeRequests = new Map();
  tokenRequests = [];
  idpBehaviour = {};
  app.locals.oidcLogin = createOidcLogin({ config, fetchImpl: fakeFetch(), jwks, now: () => clock });
});

describe('login start', () => {
  test('redirects to the IdP with PKCE (S256), state, nonce and the agent scopes; binds the flow with a cookie', async () => {
    const res = await invoke({ url: '/auth/login' });
    assert.strictEqual(res.statusCode, 302);
    const u = new URL(res.headers.location);
    assert.strictEqual(u.origin + u.pathname, `${idp.issuer}/protocol/openid-connect/auth`);
    assert.strictEqual(u.searchParams.get('response_type'), 'code');
    assert.strictEqual(u.searchParams.get('client_id'), 'web-frontend');
    assert.strictEqual(u.searchParams.get('redirect_uri'), config.redirectUri);
    assert.strictEqual(u.searchParams.get('code_challenge_method'), 'S256');
    assert.ok(u.searchParams.get('code_challenge').length >= 43);
    assert.ok(u.searchParams.get('state').length >= 32);
    assert.ok(u.searchParams.get('nonce').length >= 32);
    const scopes = u.searchParams.get('scope').split(' ');
    assert.ok(['openid', 'profile', 'email', 'mcp:tool1', 'mcp:bigquery:audit', 'Mail.Send'].every(s => scopes.includes(s)));
    const tx = [].concat(res.headers['set-cookie'])[0];
    assert.match(tx, /^oidc_tx=/);
    assert.match(tx, /HttpOnly/);
    assert.match(tx, /SameSite=Lax/);
  });
});

describe('callback', () => {
  test('creates a session: HttpOnly cookie, no token in the response, PKCE verifier sent to the token endpoint', async () => {
    const { callback } = await signIn();
    assert.strictEqual(callback.statusCode, 302);
    assert.strictEqual(callback.headers.location, '/');
    const sid = [].concat(callback.headers['set-cookie']).find(c => c.startsWith('sid='));
    assert.match(sid, /HttpOnly/);
    assert.match(sid, /SameSite=Lax/);
    assert.ok(!JWT.test(callback.raw) && !JWT.test(JSON.stringify(callback.headers)), 'no JWT in the response');
    assert.strictEqual(tokenRequests[0].grant_type, 'authorization_code');
    assert.ok(tokenRequests[0].code_verifier.length >= 43);
    assert.strictEqual(tokenRequests[0].client_secret, undefined, 'public client: no secret');
  });

  test('rejects a callback whose state cookie is missing or different (login CSRF)', async () => {
    assert.strictEqual((await signIn({ dropTx: true })).callback.statusCode, 400);
    assert.strictEqual((await signIn({ tamperState: 'attacker-state' })).callback.statusCode, 400);
  });

  test('a state value can be used only once', async () => {
    const first = await signIn();
    const replay = await invoke({ url: `/auth/callback?code=x&state=${first.target.searchParams.get('state')}`, headers: { cookie: cookiesFrom(first.login) } });
    assert.strictEqual(replay.statusCode, 400);
  });

  test('rejects IdP errors, a failed code exchange and an expired attempt', async () => {
    assert.strictEqual((await signIn({ error: 'access_denied' })).callback.statusCode, 400);
    idpBehaviour = { failToken: true };
    assert.strictEqual((await signIn()).callback.statusCode, 401);
    idpBehaviour = {};
    const login = await invoke({ url: '/auth/login' });
    const state = new URL(login.headers.location).searchParams.get('state');
    clock += 11 * 60 * 1000;
    const late = await invoke({ url: `/auth/callback?code=c&state=${state}`, headers: { cookie: cookiesFrom(login) } });
    assert.strictEqual(late.statusCode, 400);
  });

  test('rejects an ID token with the wrong nonce, audience, or signature', async () => {
    for (const idClaims of [{ nonce: 'someone-elses-nonce' }, { aud: 'another-client' }, { azp: 'another-client' }]) {
      idpBehaviour = { idClaims };
      const { callback } = await signIn();
      assert.strictEqual(callback.statusCode, 401, JSON.stringify(idClaims));
      assert.ok(!(callback.headers['set-cookie'] || []).toString().includes('sid='));
    }
  });
});

describe('session and chat', () => {
  test('/api/session reports identity and consented scopes without any token', async () => {
    const { cookie } = await signIn();
    const res = await invoke({ url: '/api/session', headers: { cookie } });
    assert.strictEqual(res.body.mode, 'oidc');
    assert.strictEqual(res.body.authenticated, true);
    assert.strictEqual(res.body.user.email, 'bob@rtarwaygmail.onmicrosoft.com');
    assert.deepStrictEqual(res.body.user.scopes, ['mcp:tool1', 'mcp:bigquery:query']);
    assert.ok(!JWT.test(res.raw));
    const anon = await invoke({ url: '/api/session' });
    assert.strictEqual(anon.body.authenticated, false);
    assert.strictEqual(anon.body.user, null);
  });

  test('chat requires a session and a same-origin request', async () => {
    const { cookie } = await signIn();
    assert.strictEqual((await invoke({ method: 'POST', url: '/api/chat', headers: { origin: ORIGIN }, body: { prompt: 'hi' } })).statusCode, 401);
    assert.strictEqual((await invoke({ method: 'POST', url: '/api/chat', headers: { cookie }, body: { prompt: 'hi' } })).statusCode, 403, 'no Origin header');
    assert.strictEqual((await invoke({ method: 'POST', url: '/api/chat', headers: { cookie, origin: 'https://evil.example' }, body: { prompt: 'hi' } })).statusCode, 403);
  });

  test('chat is sent with the SESSION access token; a token supplied by the browser is ignored', async () => {
    const { cookie } = await signIn();
    let seen = null;
    app.locals.agentDispatcher = async (prompt, token) => { seen = token; return { status: 'OK' }; };
    try {
      const res = await invoke({ method: 'POST', url: '/api/chat', headers: { cookie, origin: ORIGIN, authorization: 'Bearer forged-by-browser' }, body: { prompt: 'hi', token: 'forged-in-body' } });
      assert.strictEqual(res.statusCode, 200);
      assert.ok(seen && seen.startsWith('eyJ'));
      assert.notStrictEqual(seen, 'forged-by-browser');
      assert.notStrictEqual(seen, 'forged-in-body');
    } finally {
      delete app.locals.agentDispatcher;
    }
  });

  test('a near-expiry access token is refreshed; a failed refresh ends the session', async () => {
    idpBehaviour = { expiresIn: 20 };
    const { cookie } = await signIn();
    let seen = null;
    app.locals.agentDispatcher = async (prompt, token) => { seen = token; return { status: 'OK' }; };
    try {
      const ok = await invoke({ method: 'POST', url: '/api/chat', headers: { cookie, origin: ORIGIN }, body: { prompt: 'hi' } });
      assert.strictEqual(ok.statusCode, 200);
      assert.strictEqual(JSON.parse(Buffer.from(seen.split('.')[1], 'base64url')).jti, 'refreshed');
      assert.ok(tokenRequests.some(r => r.grant_type === 'refresh_token' && r.refresh_token === 'refresh-1'));

      clock += 400 * 1000; // refreshed token has expired as well
      idpBehaviour = { failRefresh: true };
      const gone = await invoke({ method: 'POST', url: '/api/chat', headers: { cookie, origin: ORIGIN }, body: { prompt: 'hi' } });
      assert.strictEqual(gone.statusCode, 401);
      assert.strictEqual((await invoke({ url: '/api/session', headers: { cookie } })).body.authenticated, false);
    } finally {
      delete app.locals.agentDispatcher;
    }
  });

  test('sessions expire when idle and after the absolute lifetime', async () => {
    const { cookie } = await signIn();
    clock += config.sessionIdleMs + 1000;
    assert.strictEqual((await invoke({ url: '/api/session', headers: { cookie } })).body.authenticated, false);

    const second = await signIn();
    for (let i = 0; i < 20; i++) { clock += config.sessionIdleMs - 1000; await invoke({ url: '/api/session', headers: { cookie: second.cookie } }); }
    assert.strictEqual((await invoke({ url: '/api/session', headers: { cookie: second.cookie } })).body.authenticated, false, 'absolute lifetime');
  });
});

describe('logout', () => {
  test('ends the session and sends the browser to the IdP end-session endpoint; refuses cross-origin requests', async () => {
    const { cookie } = await signIn();
    const cross = await invoke({ method: 'POST', url: '/auth/logout', headers: { cookie, origin: 'https://evil.example' } });
    assert.strictEqual(cross.statusCode, 403);

    const res = await invoke({ method: 'POST', url: '/auth/logout', headers: { cookie, origin: ORIGIN } });
    assert.strictEqual(res.statusCode, 200);
    const redirect = new URL(res.body.redirect);
    assert.strictEqual(redirect.pathname, '/realms/poc/protocol/openid-connect/logout');
    assert.ok(redirect.searchParams.get('id_token_hint'));
    assert.match([].concat(res.headers['set-cookie'])[0], /Max-Age=0/);
    assert.strictEqual((await invoke({ url: '/api/session', headers: { cookie } })).body.authenticated, false);
  });
});

describe('demo login stays off without simulation', () => {
  test('/api/login and /api/users are unavailable in OIDC mode when ALLOW_SIMULATION is not true', async () => {
    assert.strictEqual((await invoke({ method: 'POST', url: '/api/login', body: { userType: 'alice' } })).statusCode, 503);
    assert.strictEqual((await invoke({ url: '/api/users' })).statusCode, 503);
  });
});
