// OIDC / JWT verification (canonical copy: shared/oidc.js; vendored into services by scripts/sync-shared.sh).
//
// Verifies tokens issued by an external identity provider (Keycloak, Entra, SPIRE's OIDC discovery endpoint) using the
// issuer's published JWKS. Strict by construction: an explicit algorithm allow-list (RS256 only), an exact issuer match,
// an exact audience match, a mandatory expiry, and no fallback to a shared secret. Network access is injectable so the
// verifier is fully testable offline.

const crypto = require('crypto');

class OidcError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'OidcError';
    this.code = code;
  }
}

function b64urlDecode(segment) {
  return Buffer.from(segment.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

async function defaultFetchJson(url, { timeoutMs = 5000 } = {}) {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: 'application/json' } });
  if (!res.ok) throw new OidcError('FETCH_FAILED', `GET ${url} failed (HTTP ${res.status})`);
  return res.json();
}

/**
 * JWKS client with caching. Unknown key ids trigger one refetch (rate limited) so key rotation works without
 * letting a stream of bogus kids hammer the IdP.
 */
function createJwksClient({ jwksUri, issuer, fetchJson = defaultFetchJson, ttlMs = 10 * 60 * 1000, minRefetchMs = 30 * 1000, now = Date.now }) {
  if (!jwksUri && !issuer) throw new OidcError('CONFIG', 'createJwksClient needs jwksUri or issuer (for discovery).');
  let keys = null; // Map kid -> KeyObject
  let fetchedAt = 0;
  let resolvedUri = jwksUri || null;
  let inflight = null;

  async function resolveUri() {
    if (resolvedUri) return resolvedUri;
    const base = issuer.replace(/\/+$/, '');
    const discovery = await fetchJson(`${base}/.well-known/openid-configuration`);
    if (!discovery || discovery.issuer !== issuer || typeof discovery.jwks_uri !== 'string') {
      throw new OidcError('DISCOVERY', 'OIDC discovery document is missing, or its issuer does not match the configured issuer.');
    }
    resolvedUri = discovery.jwks_uri;
    return resolvedUri;
  }

  async function load() {
    if (inflight) return inflight;
    inflight = (async () => {
      const doc = await fetchJson(await resolveUri());
      if (!doc || !Array.isArray(doc.keys)) throw new OidcError('JWKS', 'JWKS document has no keys array.');
      const next = new Map();
      for (const jwk of doc.keys) {
        if (jwk.kty !== 'RSA' || (jwk.use && jwk.use !== 'sig')) continue;
        try {
          next.set(jwk.kid || '', crypto.createPublicKey({ key: jwk, format: 'jwk' }));
        } catch { /* skip malformed key */ }
      }
      keys = next;
      fetchedAt = now();
    })().finally(() => { inflight = null; });
    return inflight;
  }

  async function getKey(kid) {
    const stale = !keys || now() - fetchedAt > ttlMs;
    if (stale) await load();
    if (keys.has(kid || '')) return keys.get(kid || '');
    if (!kid && keys.size === 1) return [...keys.values()][0];
    if (now() - fetchedAt >= minRefetchMs) {
      await load();
      if (keys.has(kid || '')) return keys.get(kid || '');
    }
    throw new OidcError('UNKNOWN_KEY', `No signing key found for kid '${kid}'.`);
  }

  return { getKey };
}

function decodeJwt(token) {
  if (typeof token !== 'string') throw new OidcError('MALFORMED', 'Token must be a string.');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p, i) => i < 2 && p.length === 0)) throw new OidcError('MALFORMED', 'Token is not a three-part JWT.');
  try {
    return {
      header: JSON.parse(b64urlDecode(parts[0]).toString('utf8')),
      payload: JSON.parse(b64urlDecode(parts[1]).toString('utf8')),
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: b64urlDecode(parts[2])
    };
  } catch {
    throw new OidcError('MALFORMED', 'Token header or payload is not valid JSON.');
  }
}

/**
 * Verifies signature and standard claims. Returns the payload.
 * @param {object} opts
 * @param {string} opts.issuer     exact expected `iss`
 * @param {string|string[]} opts.audience  at least one of these must appear in `aud` (exact match)
 * @param {{getKey:Function}} opts.jwks
 * @param {string[]} [opts.authorizedParties]  if set, `azp` must be one of these
 * @param {string[]} [opts.requiredScopes]     every one must appear in the space-separated `scope` claim
 */
async function verifyJwt(token, { issuer, audience, jwks, algorithms = ['RS256'], clockToleranceSec = 30, now = Date.now, authorizedParties, requiredScopes = [] }) {
  const { header, payload, signingInput, signature } = decodeJwt(token);

  if (!algorithms.includes(header.alg)) {
    throw new OidcError('ALG_NOT_ALLOWED', `Algorithm '${header.alg}' is not allowed (expected ${algorithms.join(', ')}).`);
  }
  const key = await jwks.getKey(header.kid);
  if (!crypto.verify('RSA-SHA256', Buffer.from(signingInput), key, signature)) {
    throw new OidcError('BAD_SIGNATURE', 'Token signature verification failed.');
  }

  const nowSec = Math.floor(now() / 1000);
  if (typeof payload.exp !== 'number') throw new OidcError('NO_EXPIRY', 'Token has no exp claim.');
  if (payload.exp + clockToleranceSec < nowSec) throw new OidcError('EXPIRED', 'Token has expired.');
  if (typeof payload.nbf === 'number' && payload.nbf - clockToleranceSec > nowSec) throw new OidcError('NOT_YET_VALID', 'Token is not yet valid.');
  if (typeof payload.iat === 'number' && payload.iat - clockToleranceSec > nowSec) throw new OidcError('IAT_IN_FUTURE', 'Token was issued in the future.');

  if (payload.iss !== issuer) throw new OidcError('BAD_ISSUER', `Unexpected issuer '${payload.iss}'.`);

  const wanted = Array.isArray(audience) ? audience : [audience];
  const have = (Array.isArray(payload.aud) ? payload.aud : [payload.aud]).filter(a => typeof a === 'string');
  if (have.length === 0) throw new OidcError('NO_AUDIENCE', 'Token has no aud claim.');
  if (!wanted.some(a => have.includes(a))) throw new OidcError('BAD_AUDIENCE', `Token audience ${JSON.stringify(payload.aud)} does not include ${JSON.stringify(wanted)}.`);

  if (authorizedParties && !authorizedParties.includes(payload.azp)) {
    throw new OidcError('BAD_AUTHORIZED_PARTY', `Token authorized party '${payload.azp}' is not allowed.`);
  }
  if (requiredScopes.length > 0) {
    const scopes = typeof payload.scope === 'string' ? payload.scope.split(' ') : [];
    const missing = requiredScopes.filter(s => !scopes.includes(s));
    if (missing.length > 0) throw new OidcError('MISSING_SCOPE', `Token lacks required scope(s): ${missing.join(', ')}.`);
  }
  return payload;
}

/** Scopes granted in the token's space-separated `scope` claim. */
function tokenScopes(payload) {
  return typeof payload.scope === 'string' ? payload.scope.split(' ').filter(Boolean) : [];
}

module.exports = { OidcError, createJwksClient, verifyJwt, decodeJwt, tokenScopes, defaultFetchJson };
