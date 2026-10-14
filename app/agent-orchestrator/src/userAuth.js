// Authentication of the end user at the orchestrator.
//
// Strict mode (OIDC_ISSUER is set): the bearer token must be an access token issued by the IdP, with a valid signature
// (JWKS), exact issuer, the orchestrator as audience, an allowed authorized party and a valid lifetime. The verified
// email is then mapped to the user's identities through the identity directory, and the scopes the agent may use are
// the intersection of what the user is ELIGIBLE for (group membership) and what they CONSENTED to (token scope claim).
// Anything that fails is rejected; there is no fallback to decoding an unverified token.

const { createJwksClient, verifyJwt, tokenScopes, OidcError } = require('./oidc');
const { createResolver, IdentityMappingError } = require('./identityMapping');

class AuthError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
    this.code = code;
  }
}

function readConfig(env = process.env) {
  const list = v => (v || '').split(',').map(s => s.trim()).filter(Boolean);
  return {
    issuer: env.OIDC_ISSUER || '',
    audience: env.OIDC_AUDIENCE || 'agent-orchestrator-client',
    jwksUri: env.OIDC_JWKS_URI || '',
    authorizedParties: list(env.OIDC_AUTHORIZED_PARTIES || 'web-frontend'),
    identityMapPath: env.IDENTITY_MAP_PATH || ''
  };
}

const isStrict = config => Boolean(config.issuer);

function createUserAuthenticator({ config = readConfig(), jwks, resolver } = {}) {
  if (!isStrict(config)) throw new Error('createUserAuthenticator requires OIDC_ISSUER.');
  const keys = jwks || createJwksClient({ issuer: config.issuer, jwksUri: config.jwksUri || undefined });
  const directory = resolver || createResolver(config.identityMapPath);

  /**
   * @param {string} authorizationHeader the raw Authorization header value
   * @returns verified user context
   */
  async function authenticate(authorizationHeader) {
    if (typeof authorizationHeader !== 'string' || !/^Bearer\s+\S+$/i.test(authorizationHeader)) {
      throw new AuthError(401, 'MISSING_BEARER', 'A bearer access token is required.');
    }
    const token = authorizationHeader.replace(/^Bearer\s+/i, '');

    let claims;
    try {
      claims = await verifyJwt(token, {
        issuer: config.issuer,
        audience: config.audience,
        jwks: keys,
        authorizedParties: config.authorizedParties.length ? config.authorizedParties : undefined
      });
    } catch (err) {
      if (err instanceof OidcError) throw new AuthError(401, err.code, `Token rejected: ${err.message}`);
      throw new AuthError(503, 'IDP_UNAVAILABLE', `Could not verify the token: ${err.message}`);
    }

    let identity;
    try {
      identity = directory.resolveFromClaims(claims);
    } catch (err) {
      if (err instanceof IdentityMappingError) throw new AuthError(403, err.code, err.message);
      throw err;
    }

    const consentedScopes = tokenScopes(claims).filter(s => directory.allAgentScopes.includes(s));
    const eligibleScopes = identity.agentScopes.filter(s => consentedScopes.includes(s));
    return {
      token,
      claims,
      identity,
      consentedScopes,
      eligibleScopes,
      roles: Array.isArray(claims.roles) ? claims.roles : [],
      groups: Array.isArray(claims.groups) ? claims.groups : [...identity.groups]
    };
  }

  return { strict: true, authenticate, resolver: directory };
}

module.exports = { AuthError, readConfig, isStrict, createUserAuthenticator };
