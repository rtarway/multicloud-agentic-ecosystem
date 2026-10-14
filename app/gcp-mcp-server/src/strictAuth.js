// Strict authentication for the GCP MCP server (real identity path).
//
// A request must carry BOTH
//   1. Authorization: Bearer <access token issued by the IdP for THIS server, on behalf of the user>, and
//   2. X-Agent-Identity: <JWT-SVID issued by SPIRE to the calling workload for THIS server>.
// The token is verified against the IdP's JWKS (exact issuer, exact audience, authorized party, lifetime); the user is
// mapped through the identity directory (verified email only) and must be eligible for the scope; the SVID is verified
// against the SPIRE trust domain's JWKS; and the actor named in the token's `act` claim must be exactly the SPIFFE ID
// proven by the SVID and be on the allow-list. Nothing is accepted on the strength of a header the caller could forge.

const { createJwksClient, verifyJwt, tokenScopes, OidcError } = require('./oidc');
const { verifySvid, SpiffeError } = require('./spiffe');
const { createResolver, IdentityMappingError } = require('./identityMapping');

const ORCHESTRATOR_SPIFFE_ID = 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa';

const list = v => (v || '').split(',').map(s => s.trim()).filter(Boolean);

function readStrictConfig(env = process.env) {
  return {
    issuer: env.OIDC_ISSUER || '',
    audience: env.GCP_MCP_CLIENT_ID || 'mcp-gcp-service',
    jwksUri: env.OIDC_JWKS_URI || '',
    authorizedParties: list(env.OIDC_AUTHORIZED_PARTIES || 'agent-orchestrator-client'),
    allowedActors: list(env.ALLOWED_ACTORS || ORCHESTRATOR_SPIFFE_ID),
    spireIssuer: env.SPIRE_OIDC_ISSUER || '',
    spireJwksUri: env.SPIRE_JWKS_URI || '',
    svidAudience: env.SVID_AUDIENCE || 'gcp-mcp-server',
    identityMapPath: env.IDENTITY_MAP_PATH || ''
  };
}

const isStrictConfigured = config => Boolean(config.issuer);

function validateStrictConfig(config) {
  const problems = [];
  if (!config.spireIssuer) problems.push('SPIRE_OIDC_ISSUER is required in strict mode (the calling agent must prove its identity)');
  if (!config.identityMapPath) problems.push('IDENTITY_MAP_PATH is required in strict mode');
  if (config.allowedActors.length === 0) problems.push('ALLOWED_ACTORS must name at least one SPIFFE ID');
  return problems;
}

function createStrictAuthenticator({ config = readStrictConfig(), jwks, spireJwks, resolver } = {}) {
  const problems = validateStrictConfig(config);
  if (problems.length > 0 && !(jwks && spireJwks && resolver)) throw new Error(`GCP MCP strict mode misconfigured: ${problems.join('; ')}.`);

  const idpKeys = jwks || createJwksClient({ issuer: config.issuer, jwksUri: config.jwksUri || undefined });
  const spireKeys = spireJwks || createJwksClient({ issuer: config.spireIssuer, jwksUri: config.spireJwksUri || undefined });
  const directory = resolver || createResolver(config.identityMapPath);

  const deny = error => ({ authenticated: false, error });

  async function authenticate(headers) {
    const authHeader = headers['authorization'];
    if (!authHeader || !/^Bearer\s+\S+$/i.test(authHeader)) return deny('Missing or malformed Authorization header with Bearer token.');
    const token = authHeader.replace(/^Bearer\s+/i, '');

    // 1. The access token issued by the IdP for this server
    let claims;
    try {
      claims = await verifyJwt(token, {
        issuer: config.issuer, audience: config.audience, jwks: idpKeys,
        authorizedParties: config.authorizedParties.length ? config.authorizedParties : undefined
      });
    } catch (err) {
      if (err instanceof OidcError) return deny(`Token verification failed: ${err.message}`);
      return deny(`Token verification failed: ${err.message}`);
    }

    // 2. The agent's own identity (JWT-SVID), bound to this server by audience
    const svidHeader = headers['x-agent-identity'];
    if (!svidHeader) return deny('Agent identity proof (X-Agent-Identity JWT-SVID) is required.');
    let svid;
    try {
      svid = await verifySvid(svidHeader, {
        issuer: config.spireIssuer, audience: config.svidAudience, jwks: spireKeys, allowedSpiffeIds: config.allowedActors
      });
    } catch (err) {
      return deny(err instanceof SpiffeError ? err.message : `JWT-SVID verification failed: ${err.message}`);
    }

    // 3. The delegation chain: the IdP-attested actor must be the workload that proved itself
    const actorChain = [];
    for (let cur = claims.act; cur && cur.sub; cur = cur.act) actorChain.push(cur.sub);
    if (actorChain.length === 0) return deny('The token has no act claim: it was not issued for delegated agent access.');
    if (actorChain[0] !== svid.spiffeId) {
      return deny(`The token's actor '${actorChain[0]}' does not match the SPIFFE ID '${svid.spiffeId}' proven by the JWT-SVID.`);
    }
    const untrusted = actorChain.find(a => !config.allowedActors.includes(a));
    if (untrusted) return deny(`RFC 8693 chain verification failed: untrusted actor '${untrusted}' in delegation chain.`);

    // 4. The user: verified email mapped through the directory; scope must be consented AND eligible
    let identity;
    try {
      identity = directory.resolveFromClaims(claims);
    } catch (err) {
      if (err instanceof IdentityMappingError) return deny(`Identity mapping failed: ${err.message}`);
      throw err;
    }
    const scopes = tokenScopes(claims).filter(s => directory.allAgentScopes.includes(s));
    const ineligible = scopes.filter(s => !identity.agentScopes.includes(s));
    if (scopes.length === 0 || ineligible.length > 0) {
      return deny(`The token carries no eligible agent scope for '${identity.id}'${ineligible.length ? ` (not eligible: ${ineligible.join(', ')})` : ''}.`);
    }

    return {
      authenticated: true,
      sub: identity.keycloakEmail,
      email: identity.keycloakEmail,
      identity,
      aud: claims.aud,
      act: claims.act,
      actorChain,
      actorDetails: actorChain.map((sub, i) => ({ hop: i + 1, sub })),
      scopes,
      roles: Array.isArray(claims.roles) ? claims.roles : [],
      tokenPayload: claims,
      rawToken: token
    };
  }

  return { strict: true, authenticate };
}

module.exports = { readStrictConfig, isStrictConfigured, validateStrictConfig, createStrictAuthenticator, ORCHESTRATOR_SPIFFE_ID };
