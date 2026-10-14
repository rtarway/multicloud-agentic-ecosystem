// On-behalf-of exchange for Azure Storage.
//
// The Azure MCP server receives a token for ITSELF (audience = its Entra app) that carries the signed-in user's identity.
// To touch storage it exchanges that token (OAuth 2.0 OBO, RFC 7523 jwt-bearer with requested_token_use=on_behalf_of) for
// a Storage token for the SAME user, so Azure RBAC on the container decides what is allowed. No client secret is used:
// the server authenticates with a federated client assertion.

const { getClientAssertion } = require('./federatedAssertion');

const STORAGE_SCOPE = 'https://storage.azure.com/user_impersonation';
const STORAGE_AUDIENCES = ['https://storage.azure.com', 'https://storage.azure.com/'];

class StorageAuthError extends Error {
  constructor(code, message, { claims = null } = {}) {
    super(message);
    this.name = 'StorageAuthError';
    this.code = code;
    this.claims = claims; // claims challenge from Entra (Conditional Access / MFA), when present
  }
}

function decodePayload(jwt) {
  try {
    return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

function createStorageTokenProvider({ env = process.env, fetchImpl = fetch, assertionProvider = () => getClientAssertion({ env }), now = Date.now } = {}) {
  const tenant = () => env.ENTRA_TENANT_ID;
  const clientId = () => env.ENTRA_CLIENT_ID;

  /**
   * @param {string} userAssertion the incoming (already verified) access token for this server
   * @returns {Promise<{token:string, expiresAt:number, claims:object}>}
   */
  async function acquire(userAssertion) {
    if (!tenant() || !clientId()) throw new StorageAuthError('NOT_CONFIGURED', 'ENTRA_TENANT_ID and ENTRA_CLIENT_ID are required for the storage on-behalf-of exchange.');

    let assertion;
    try {
      assertion = await assertionProvider();
    } catch (err) {
      throw new StorageAuthError('CLIENT_ASSERTION_UNAVAILABLE', err.message);
    }

    let res;
    try {
      res = await fetchImpl(`https://login.microsoftonline.com/${tenant()}/oauth2/v2.0/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          client_id: clientId(),
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: assertion,
          assertion: userAssertion,
          scope: STORAGE_SCOPE,
          requested_token_use: 'on_behalf_of'
        }),
        signal: AbortSignal.timeout(8000)
      });
    } catch (err) {
      throw new StorageAuthError('ENTRA_UNREACHABLE', `The storage on-behalf-of request failed: ${err.message}`);
    }

    let json = null;
    try { json = await res.json(); } catch { /* handled below */ }
    if (!res.ok || !json || !json.access_token) {
      const error = json && json.error;
      if (json && json.claims && (error === 'interaction_required' || error === 'invalid_grant')) {
        throw new StorageAuthError('INTERACTION_REQUIRED', 'Entra requires additional user interaction (for example MFA) before storage can be accessed.', { claims: json.claims });
      }
      throw new StorageAuthError('OBO_REJECTED', `Entra rejected the storage on-behalf-of exchange (HTTP ${res.status}${error ? `: ${error}` : ''}).`);
    }

    // Defence in depth: the result must be a Storage token for the same user that this request is for.
    const claims = decodePayload(json.access_token);
    const original = decodePayload(userAssertion);
    if (!claims || !STORAGE_AUDIENCES.includes(claims.aud)) {
      throw new StorageAuthError('BAD_TOKEN', `The exchanged token is not a Storage token (aud '${claims && claims.aud}').`);
    }
    if (original && original.oid && claims.oid && original.oid !== claims.oid) {
      throw new StorageAuthError('IDENTITY_MISMATCH', 'The exchanged token belongs to a different user than the request.');
    }
    return { token: json.access_token, expiresAt: claims.exp ? claims.exp * 1000 : now() + 3000 * 1000, claims };
  }

  return { acquire };
}

module.exports = { createStorageTokenProvider, StorageAuthError, STORAGE_SCOPE };
