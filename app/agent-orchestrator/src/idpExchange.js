// RFC 8693 token exchange at the identity provider (Keycloak standard token exchange).
//
// The orchestrator never mints tokens. It presents the user's access token as the subject token and asks the IdP for a
// token for exactly ONE resource server (audience) carrying exactly ONE agent scope. The IdP stamps the delegation
// (`act`) claim for the calling client. The result is verified again here before it is used: signature, issuer,
// audience, lifetime, a single audience, only the requested agent scope, and an `act` claim naming this agent.

const { createJwksClient, verifyJwt, tokenScopes, OidcError } = require('./oidc');

class ExchangeError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ExchangeError';
    this.code = code;
  }
}

const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';

function createIdpClient({
  issuer, tokenEndpoint, clientId, clientSecret,
  jwks, fetchImpl = fetch, maxTtlSec = 300, knownAgentScopes = [], timeoutMs = 5000, now = Date.now
}) {
  if (!issuer || !tokenEndpoint || !clientId || !clientSecret) {
    throw new ExchangeError('CONFIG', 'IdP exchange needs issuer, tokenEndpoint, clientId and clientSecret.');
  }
  const keys = jwks || createJwksClient({ issuer });

  /**
   * @param {object} p
   * @param {string} p.subjectToken      the user's access token
   * @param {string} p.audience          the resource server's client id (exactly one)
   * @param {string} p.scope             the single agent scope to carry
   * @param {string} [p.expectedActor]   SPIFFE ID the IdP must have stamped into `act.sub`
   */
  async function exchange({ subjectToken, audience, scope, expectedActor }) {
    const body = new URLSearchParams({
      grant_type: GRANT_TYPE,
      client_id: clientId,
      client_secret: clientSecret,
      subject_token: subjectToken,
      subject_token_type: ACCESS_TOKEN,
      requested_token_type: ACCESS_TOKEN,
      audience,
      scope
    });

    let res;
    try {
      res = await fetchImpl(tokenEndpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body,
        signal: AbortSignal.timeout(timeoutMs)
      });
    } catch (err) {
      throw new ExchangeError('IDP_UNREACHABLE', `Token exchange request failed: ${err.message}`);
    }

    let json = null;
    try { json = await res.json(); } catch { /* handled below */ }
    if (!res.ok) {
      throw new ExchangeError('IDP_EXCHANGE_REJECTED', `The IdP rejected the token exchange (HTTP ${res.status}${json && json.error ? `: ${json.error}` : ''}).`);
    }
    if (!json || typeof json.access_token !== 'string') {
      throw new ExchangeError('IDP_BAD_RESPONSE', 'The IdP response contained no access_token.');
    }

    let claims;
    try {
      claims = await verifyJwt(json.access_token, { issuer, audience, jwks: keys, now });
    } catch (err) {
      if (err instanceof OidcError) throw new ExchangeError('EXCHANGED_TOKEN_INVALID', `Exchanged token failed verification: ${err.message}`);
      throw err;
    }

    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (audiences.length !== 1 || audiences[0] !== audience) {
      throw new ExchangeError('EXCHANGED_TOKEN_AUDIENCE', `Exchanged token must have exactly one audience ('${audience}'); got ${JSON.stringify(claims.aud)}.`);
    }
    const lifetime = typeof claims.iat === 'number' ? claims.exp - claims.iat : claims.exp - Math.floor(now() / 1000);
    if (lifetime > maxTtlSec) {
      throw new ExchangeError('EXCHANGED_TOKEN_TTL', `Exchanged token lifetime ${lifetime}s exceeds the ${maxTtlSec}s maximum.`);
    }
    const agentScopes = tokenScopes(claims).filter(s => knownAgentScopes.includes(s));
    if (!agentScopes.includes(scope) || agentScopes.length !== 1) {
      throw new ExchangeError('EXCHANGED_TOKEN_SCOPE', `Exchanged token must carry exactly the agent scope '${scope}'; got [${agentScopes.join(', ')}].`);
    }
    if (expectedActor && !(claims.act && claims.act.sub === expectedActor)) {
      throw new ExchangeError('EXCHANGED_TOKEN_ACTOR', `Exchanged token does not name the agent '${expectedActor}' in its act claim.`);
    }
    return { token: json.access_token, claims, expiresIn: lifetime };
  }

  return { exchange };
}

module.exports = { ExchangeError, createIdpClient };
