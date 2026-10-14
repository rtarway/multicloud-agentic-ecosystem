// Server-side OIDC login for the browser app (backend-for-frontend, "BFF").
//
// Authorization code flow with PKCE (S256), state and nonce. The browser only ever holds an opaque, HttpOnly session
// cookie; the access and refresh tokens stay on this server and are attached to calls to the orchestrator. Nothing here
// uses a client secret (public client + PKCE) or a password grant.

const crypto = require('crypto');
const { createJwksClient, verifyJwt, decodeJwt, tokenScopes } = require('./oidc');

const DEFAULT_AGENT_SCOPES = ['mcp:tool1', 'mcp:tool2', 'mcp:bigquery:query', 'mcp:bigquery:audit', 'Mail.Send'];
const list = v => (v || '').split(',').map(s => s.trim()).filter(Boolean);

function readLoginConfig(env = process.env) {
  if (!env.OIDC_ISSUER || !env.OIDC_CLIENT_ID) return null;
  const issuer = env.OIDC_ISSUER.replace(/\/+$/, '');
  const redirectUri = env.OIDC_REDIRECT_URI || 'http://localhost:3000/auth/callback';
  return {
    issuer,
    clientId: env.OIDC_CLIENT_ID,
    redirectUri,
    authorizationEndpoint: env.OIDC_AUTHORIZATION_ENDPOINT || `${issuer}/protocol/openid-connect/auth`,
    tokenEndpoint: env.OIDC_TOKEN_ENDPOINT || `${issuer}/protocol/openid-connect/token`,
    endSessionEndpoint: env.OIDC_END_SESSION_ENDPOINT || `${issuer}/protocol/openid-connect/logout`,
    jwksUri: env.OIDC_JWKS_URI || '',
    agentScopes: list(env.AGENT_SCOPES).length ? list(env.AGENT_SCOPES) : DEFAULT_AGENT_SCOPES,
    postLogoutRedirectUri: env.OIDC_POST_LOGOUT_REDIRECT_URI || new URL('/', redirectUri).href,
    sessionIdleMs: Number(env.SESSION_IDLE_MS || 30 * 60 * 1000),
    sessionMaxMs: Number(env.SESSION_MAX_MS || 8 * 60 * 60 * 1000)
  };
}

function parseCookies(header) {
  const out = {};
  for (const part of (header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

const b64url = buf => Buffer.from(buf).toString('base64url');
const randomToken = (bytes = 32) => b64url(crypto.randomBytes(bytes));

function createOidcLogin({ config, fetchImpl = fetch, jwks, now = Date.now }) {
  const keys = jwks || createJwksClient({ issuer: config.issuer, jwksUri: config.jwksUri || undefined });
  const secure = config.redirectUri.startsWith('https:');
  const origin = new URL(config.redirectUri).origin;
  const sessions = new Map(); // id -> session
  const pending = new Map(); // state -> { nonce, verifier, createdAt }

  const sweeper = setInterval(() => {
    const t = now();
    for (const [id, s] of sessions) if (expired(s, t)) sessions.delete(id);
    for (const [state, p] of pending) if (t - p.createdAt > 10 * 60 * 1000) pending.delete(state);
  }, 60 * 1000);
  sweeper.unref();

  function expired(session, t = now()) {
    return t - session.createdAt > config.sessionMaxMs || t - session.lastSeen > config.sessionIdleMs;
  }

  const cookie = (name, value, { maxAgeSec, path = '/' }) =>
    `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=${path}; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;

  async function tokenRequest(params) {
    const res = await fetchImpl(config.tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: new URLSearchParams({ client_id: config.clientId, ...params }),
      signal: AbortSignal.timeout(5000)
    });
    let json = null;
    try { json = await res.json(); } catch { /* handled below */ }
    if (!res.ok || !json || !json.access_token) {
      throw new Error(`token endpoint rejected the request (HTTP ${res.status}${json && json.error ? `: ${json.error}` : ''})`);
    }
    return json;
  }

  /** GET /auth/login: starts the flow. */
  function login(req, res) {
    const state = randomToken();
    const nonce = randomToken();
    const verifier = randomToken(48);
    pending.set(state, { nonce, verifier, createdAt: now() });

    const url = new URL(config.authorizationEndpoint);
    url.search = new URLSearchParams({
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: ['openid', 'profile', 'email', ...config.agentScopes].join(' '),
      state,
      nonce,
      code_challenge: b64url(crypto.createHash('sha256').update(verifier).digest()),
      code_challenge_method: 'S256'
    }).toString();

    // Binds the flow to this browser: the callback must present the same state in this cookie.
    res.setHeader('Set-Cookie', cookie('oidc_tx', state, { maxAgeSec: 600, path: '/auth' }));
    res.redirect(302, url.toString());
  }

  /** GET /auth/callback: completes the flow and creates the session. */
  async function callback(req, res) {
    const fail = (status, message) => res.status(status).json({ error: 'LOGIN_FAILED', message });
    const { code, state, error } = req.query || {};
    if (error) return fail(400, `The identity provider returned an error: ${error}`);

    const txCookie = parseCookies(req.headers.cookie).oidc_tx;
    const tx = typeof state === 'string' ? pending.get(state) : null;
    if (!tx || !txCookie || txCookie !== state) return fail(400, 'Unknown or mismatched login state.');
    pending.delete(state);
    if (now() - tx.createdAt > 10 * 60 * 1000) return fail(400, 'The login attempt expired.');
    if (typeof code !== 'string' || !code) return fail(400, 'No authorization code was returned.');

    let tokens, idClaims;
    try {
      tokens = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: config.redirectUri, code_verifier: tx.verifier });
      if (!tokens.id_token) throw new Error('no id_token was returned');
      idClaims = await verifyJwt(tokens.id_token, { issuer: config.issuer, audience: config.clientId, jwks: keys, now });
      if (idClaims.nonce !== tx.nonce) throw new Error('nonce mismatch');
      if (idClaims.azp && idClaims.azp !== config.clientId) throw new Error('unexpected authorized party');
    } catch (err) {
      return fail(401, `Login could not be completed: ${err.message}`);
    }

    const id = randomToken();
    sessions.set(id, {
      id,
      createdAt: now(),
      lastSeen: now(),
      email: idClaims.email,
      emailVerified: idClaims.email_verified === true,
      name: idClaims.name || idClaims.preferred_username || idClaims.email,
      username: idClaims.preferred_username || idClaims.email,
      accessToken: tokens.access_token,
      accessExp: now() + (Number(tokens.expires_in) || 300) * 1000,
      refreshToken: tokens.refresh_token || null,
      idToken: tokens.id_token
    });
    res.setHeader('Set-Cookie', [
      cookie('sid', id, { maxAgeSec: Math.floor(config.sessionMaxMs / 1000) }),
      cookie('oidc_tx', '', { maxAgeSec: 0, path: '/auth' })
    ]);
    res.redirect(302, '/');
  }

  /** Returns the live session for the request, or null. */
  function getSession(req) {
    const id = parseCookies(req.headers.cookie).sid;
    const session = id ? sessions.get(id) : null;
    if (!session) return null;
    if (expired(session)) { sessions.delete(id); return null; }
    session.lastSeen = now();
    return session;
  }

  /** Returns a usable access token for the session, refreshing it when close to expiry. Null if the session is over. */
  async function accessTokenFor(session) {
    if (session.accessExp - now() > 30 * 1000) return session.accessToken;
    if (!session.refreshToken) { sessions.delete(session.id); return null; }
    try {
      const tokens = await tokenRequest({ grant_type: 'refresh_token', refresh_token: session.refreshToken });
      session.accessToken = tokens.access_token;
      session.accessExp = now() + (Number(tokens.expires_in) || 300) * 1000;
      if (tokens.refresh_token) session.refreshToken = tokens.refresh_token;
      return session.accessToken;
    } catch {
      sessions.delete(session.id);
      return null;
    }
  }

  /** What the browser is allowed to know about the session: identity and consented scopes, never tokens. */
  function sessionInfo(session) {
    let claims = {};
    try { claims = decodeJwt(session.accessToken).payload; } catch { /* keep empty */ }
    const consented = tokenScopes(claims).filter(s => config.agentScopes.includes(s));
    return {
      username: session.username,
      displayName: session.name,
      email: session.email,
      scopes: consented,
      roles: Array.isArray(claims.roles) ? claims.roles : []
    };
  }

  /** POST /auth/logout: ends the local session and returns where to send the browser to end the IdP session. */
  function logout(req, res) {
    const session = getSession(req);
    let redirect = '/';
    if (session) {
      sessions.delete(session.id);
      const url = new URL(config.endSessionEndpoint);
      url.search = new URLSearchParams({
        id_token_hint: session.idToken,
        post_logout_redirect_uri: config.postLogoutRedirectUri,
        client_id: config.clientId
      }).toString();
      redirect = url.toString();
    }
    res.setHeader('Set-Cookie', cookie('sid', '', { maxAgeSec: 0 }));
    res.json({ loggedOut: true, redirect });
  }

  /** CSRF defence for state-changing requests: the browser-supplied Origin must be this app's origin. */
  function sameOrigin(req) {
    return req.headers.origin === origin;
  }

  return { login, callback, logout, getSession, accessTokenFor, sessionInfo, sameOrigin, sessions };
}

module.exports = { readLoginConfig, createOidcLogin, parseCookies };
