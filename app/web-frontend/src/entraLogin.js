// Microsoft Entra ID sign-in for the signed-in user (second leg of the user's identity, server side).
//
// The orchestrator needs an Entra access token FOR THE USER (audience = the orchestrator's Entra app) to perform the
// on-behalf-of exchange to the Azure MCP server. This module obtains it with the authorization code flow + PKCE as a
// public client (no client secret). In an enterprise tenant federated to the corporate IdP the same flow completes
// silently (prompt=none); in the POC tenant the user signs in once per session.
//
// The Entra user must be the SAME person as the user already authenticated at the IdP (the directory says which Entra
// identity that is); a different Entra account is refused. Tokens stay in the server-side session.

const crypto = require('crypto');
const { createJwksClient, verifyJwt } = require('./oidc');
const { parseCookies } = require('./oidcLogin');

function readEntraConfig(env = process.env) {
  const tenant = env.ENTRA_TENANT_ID;
  const clientId = env.ENTRA_BFF_CLIENT_ID;
  const scopeBase = env.ENTRA_ORCHESTRATOR_SCOPE || (env.ENTRA_ORCHESTRATOR_APP_ID ? `api://${env.ENTRA_ORCHESTRATOR_APP_ID}/access_as_user` : '');
  if (!tenant || !clientId || !scopeBase) return null;
  const authority = `https://login.microsoftonline.com/${tenant}`;
  return {
    tenant,
    clientId,
    issuer: `${authority}/v2.0`,
    authorizationEndpoint: env.ENTRA_AUTHORIZATION_ENDPOINT || `${authority}/oauth2/v2.0/authorize`,
    tokenEndpoint: env.ENTRA_TOKEN_ENDPOINT || `${authority}/oauth2/v2.0/token`,
    jwksUri: env.ENTRA_JWKS_URI || `${authority}/discovery/v2.0/keys`,
    redirectUri: env.ENTRA_REDIRECT_URI || 'http://localhost:3000/auth/entra/callback',
    scope: `${scopeBase} openid profile offline_access`,
    // 'none' in a tenant federated to the corporate IdP (silent sign-in); unset in the POC tenant
    defaultPrompt: env.ENTRA_PROMPT || ''
  };
}

const b64url = buf => Buffer.from(buf).toString('base64url');
const randomToken = (bytes = 32) => b64url(crypto.randomBytes(bytes));
const ALLOWED_PROMPTS = ['none', 'login', 'select_account', 'consent'];

function createEntraLogin({ config, fetchImpl = fetch, jwks, now = Date.now }) {
  const keys = jwks || createJwksClient({ jwksUri: config.jwksUri });
  const secure = config.redirectUri.startsWith('https:');
  const pending = new Map(); // state -> { nonce, verifier, createdAt, sessionId, expectedUpn }

  const sweeper = setInterval(() => {
    for (const [state, p] of pending) if (now() - p.createdAt > 10 * 60 * 1000) pending.delete(state);
  }, 60 * 1000);
  sweeper.unref();

  const cookie = (name, value, maxAgeSec) =>
    `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=/auth/entra; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;

  async function tokenRequest(params) {
    const res = await fetchImpl(config.tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: new URLSearchParams({ client_id: config.clientId, scope: config.scope, ...params }),
      signal: AbortSignal.timeout(8000)
    });
    let json = null;
    try { json = await res.json(); } catch { /* handled below */ }
    if (!res.ok || !json || !json.access_token) {
      throw new Error(`Entra token endpoint rejected the request (HTTP ${res.status}${json && json.error ? `: ${json.error}` : ''})`);
    }
    return json;
  }

  /**
   * GET /auth/entra/login — starts the sign-in for an already authenticated session.
   * @param {object} opts
   * @param {object} opts.session   the IdP session
   * @param {string} opts.expectedUpn  the Entra identity the directory maps this user to
   */
  function start(req, res, { session, expectedUpn }) {
    const { claims, prompt } = req.query || {};
    if (claims !== undefined) {
      if (typeof claims !== 'string' || claims.length > 4096) return res.status(400).json({ error: 'INVALID_CLAIMS_CHALLENGE' });
      try { JSON.parse(claims); } catch { return res.status(400).json({ error: 'INVALID_CLAIMS_CHALLENGE' }); }
    }
    if (prompt !== undefined && !ALLOWED_PROMPTS.includes(prompt)) return res.status(400).json({ error: 'INVALID_PROMPT' });

    const state = randomToken();
    const nonce = randomToken();
    const verifier = randomToken(48);
    pending.set(state, { nonce, verifier, createdAt: now(), sessionId: session.id, expectedUpn });

    const params = {
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_mode: 'query',
      scope: config.scope,
      state,
      nonce,
      code_challenge: b64url(crypto.createHash('sha256').update(verifier).digest()),
      code_challenge_method: 'S256',
      login_hint: expectedUpn
    };
    const chosenPrompt = prompt || config.defaultPrompt;
    if (chosenPrompt) params.prompt = chosenPrompt;
    if (claims) params.claims = claims;

    const url = new URL(config.authorizationEndpoint);
    url.search = new URLSearchParams(params).toString();
    res.setHeader('Set-Cookie', cookie('entra_tx', state, 600));
    res.redirect(302, url.toString());
  }

  /** GET /auth/entra/callback — completes sign-in and attaches the Entra token to the IdP session. */
  async function callback(req, res, { session }) {
    const fail = (status, error, message) => res.status(status).json({ error, message });
    const { code, state, error, error_description: errorDescription } = req.query || {};

    const tx = typeof state === 'string' ? pending.get(state) : null;
    const txCookie = parseCookies(req.headers.cookie).entra_tx;
    if (!tx || !txCookie || txCookie !== state) return fail(400, 'ENTRA_LOGIN_FAILED', 'Unknown or mismatched Entra login state.');
    pending.delete(state);
    if (now() - tx.createdAt > 10 * 60 * 1000) return fail(400, 'ENTRA_LOGIN_FAILED', 'The Entra login attempt expired.');
    // The attempt must finish in the same browser session that started it
    if (tx.sessionId !== session.id) return fail(400, 'ENTRA_LOGIN_FAILED', 'The Entra login does not belong to this session.');
    if (error) {
      // interaction_required with prompt=none: the caller should retry interactively
      return fail(error === 'interaction_required' || error === 'login_required' ? 401 : 400, 'ENTRA_LOGIN_FAILED', `Entra returned an error: ${error}${errorDescription ? ` (${String(errorDescription).slice(0, 200)})` : ''}`);
    }
    if (typeof code !== 'string' || !code) return fail(400, 'ENTRA_LOGIN_FAILED', 'No authorization code was returned.');

    let tokens, idClaims;
    try {
      tokens = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: config.redirectUri, code_verifier: tx.verifier });
      if (!tokens.id_token) throw new Error('no id_token was returned');
      idClaims = await verifyJwt(tokens.id_token, { issuer: config.issuer, audience: config.clientId, jwks: keys, now });
      if (idClaims.nonce !== tx.nonce) throw new Error('nonce mismatch');
      if (idClaims.tid !== config.tenant) throw new Error('unexpected tenant');
    } catch (err) {
      return fail(401, 'ENTRA_LOGIN_FAILED', `Entra sign-in could not be completed: ${err.message}`);
    }

    // Same person at both providers, or nothing is stored
    const upn = String(idClaims.preferred_username || idClaims.upn || '').toLowerCase();
    if (upn !== tx.expectedUpn) {
      return fail(403, 'ENTRA_USER_MISMATCH', `Signed in to Entra as '${upn}', but this session belongs to '${tx.expectedUpn}'. Sign in with the matching Azure account.`);
    }

    session.entra = {
      upn,
      accessToken: tokens.access_token,
      accessExp: now() + (Number(tokens.expires_in) || 3600) * 1000,
      refreshToken: tokens.refresh_token || null
    };
    res.setHeader('Set-Cookie', cookie('entra_tx', '', 0));
    res.redirect(302, '/');
  }

  /** A usable Entra access token for the session (refreshing when close to expiry), or null. */
  async function accessTokenFor(session) {
    const entra = session && session.entra;
    if (!entra) return null;
    if (entra.accessExp - now() > 60 * 1000) return entra.accessToken;
    if (!entra.refreshToken) { session.entra = null; return null; }
    try {
      const tokens = await tokenRequest({ grant_type: 'refresh_token', refresh_token: entra.refreshToken });
      entra.accessToken = tokens.access_token;
      entra.accessExp = now() + (Number(tokens.expires_in) || 3600) * 1000;
      if (tokens.refresh_token) entra.refreshToken = tokens.refresh_token;
      return entra.accessToken;
    } catch {
      session.entra = null;
      return null;
    }
  }

  function info(session) {
    return { configured: true, connected: Boolean(session && session.entra), upn: session && session.entra ? session.entra.upn : null };
  }

  return { start, callback, accessTokenFor, info };
}

module.exports = { readEntraConfig, createEntraLogin };
