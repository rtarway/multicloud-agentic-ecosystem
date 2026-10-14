const jwtUtil = require('./jwtUtil');
const { createJwksClient } = require('./oidc');
const { verifySvid, SpiffeError } = require('./spiffe');

const ENTRA_TENANT_ID = process.env.ENTRA_TENANT_ID || '81f26b58-159c-4879-80a0-bab30b5b4dd3';
const ENTRA_MCP_APP_ID = process.env.ENTRA_CLIENT_ID || 'd5850aa0-a667-41c3-8dd0-16f2dee4da25';
const EXPECTED_AUDIENCES = [
  `api://${ENTRA_MCP_APP_ID}`,
  ENTRA_MCP_APP_ID,
  'mcp-azure-service',
  'azure-mcp-server'
];
// Exact identities only: no prefix or substring matching. ALLOWED_ACTORS (comma-separated) replaces the list.
const ORCHESTRATOR_SPIFFE_ID = 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa';
const AUTHORIZED_SENDERS = process.env.ALLOWED_ACTORS
  ? process.env.ALLOWED_ACTORS.split(',').map(a => a.trim()).filter(Boolean)
  : [
    'a23206e1-2dda-4854-aac7-0536d2da2c4c', // k8s-agent-orchestrator Entra App ID
    'agent-orchestrator-client',
    ORCHESTRATOR_SPIFFE_ID,
    'spiffe://example.org/ns/azure/sa/azure-mcp-server',
    'urn:agent:reasoning-engine:gemini-planner'
  ];

// Agent identity proof (JWT-SVID). When SPIRE_OIDC_ISSUER is configured every request must carry a JWT-SVID for this
// server, from an allowed workload; the Entra app (azp) must also be an authorized sender.
const SPIRE_OIDC_ISSUER = process.env.SPIRE_OIDC_ISSUER || '';
const SVID_AUDIENCE = process.env.SVID_AUDIENCE || 'azure-mcp-server';
let agentVerifier = null;

function getAgentVerifier() {
  if (agentVerifier) return agentVerifier;
  if (!SPIRE_OIDC_ISSUER) return null;
  const jwks = createJwksClient({ issuer: SPIRE_OIDC_ISSUER, jwksUri: process.env.SPIRE_JWKS_URI || undefined });
  const allowedSpiffeIds = AUTHORIZED_SENDERS.filter(a => a.startsWith('spiffe://'));
  agentVerifier = token => verifySvid(token, { issuer: SPIRE_OIDC_ISSUER, audience: SVID_AUDIENCE, jwks, allowedSpiffeIds });
  return agentVerifier;
}

/** Test seam: replaces the JWT-SVID verifier (pass null to restore the environment-derived one). */
function setAgentVerifier(fn) {
  agentVerifier = fn;
}

/**
 * Extracts and verifies the OBO token from authorization header.
 * Supports:
 *   - Microsoft Entra ID Access Tokens (aud: api://<mcp-app-id>, roles: [mcp:tool1, ...])
 *   - Keycloak & Local OBO tokens for test environments
 *   - Delegated human user identity via X-Delegated-Identity header or token claim
 */
async function verifyOboToken(authHeader, ignoredDelegatedHeader, agentIdentityHeader) {
  if (ignoredDelegatedHeader) {
    console.warn('[MCP-AUTH] ⚠️ Ignoring caller-supplied X-Delegated-Identity; the user is taken from the verified token only.');
  }
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      authenticated: false,
      error: 'Missing or malformed Authorization header with Bearer token.'
    };
  }

  const token = authHeader.substring(7).trim();

  try {
    let decoded;

    // Reject insecure symmetric HMAC tokens claiming to be Microsoft Entra ID
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const header = JSON.parse(jwtUtil.base64UrlDecode(parts[0]));
        if (header.alg === 'HS256') {
          console.warn(`[MCP-AUTH] 🚨 REJECTED: Insecure symmetric HMAC token detected claiming to be Microsoft Entra ID! RFC 7515 RS256 PKI is required.`);
          return {
            authenticated: false,
            error: 'Security Policy Violation: Insecure symmetric HMAC signature rejected. Azure MCP Server requires authentic Microsoft Entra ID RS256 PKI.'
          };
        }
      }
    } catch {
      // Continue to verification
    }

    try {
      decoded = await jwtUtil.verifyEntraToken(token, ENTRA_TENANT_ID);
    } catch (err) {
      return {
        authenticated: false,
        error: `Cryptographic signature verification failed: ${err.message}`
      };
    }

    if (!decoded) {
      return {
        authenticated: false,
        error: 'Invalid token payload: unable to decode JWT.'
      };
    }

    // 0. Issuer Verification (Must be Microsoft Entra ID)
    const tokenIss = decoded.iss;
    const isEntraIssuer = tokenIss && (
      tokenIss === `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0` ||
      tokenIss === `https://sts.windows.net/${ENTRA_TENANT_ID}/`
    );
    if (!isEntraIssuer) {
      return {
        authenticated: false,
        error: `Token issuer verification failed: Azure MCP Server is protected by Microsoft Entra ID. Received untrusted issuer: '${tokenIss}'.`
      };
    }

    // 1. Audience Verification
    const tokenAud = (Array.isArray(decoded.aud) ? decoded.aud : [decoded.aud]).filter(a => typeof a === 'string' && a);
    if (tokenAud.length === 0) {
      return {
        authenticated: false,
        error: 'Token audience verification failed: the aud claim is required.'
      };
    }
    const hasValidAud = tokenAud.some(a => EXPECTED_AUDIENCES.includes(a));
    if (!hasValidAud) {
      console.warn(`[MCP-AUTH] ❌ Audience check failed. Received: ${JSON.stringify(decoded.aud)}, Expected one of: [${EXPECTED_AUDIENCES.join(', ')}]`);
      return {
        authenticated: false,
        error: `Token audience verification failed: '${JSON.stringify(decoded.aud)}' does not match expected audiences [${EXPECTED_AUDIENCES.join(', ')}].`
      };
    }
    console.log(`[MCP-AUTH] ✅ Audience verified: ${JSON.stringify(decoded.aud)}`);

    // 2. RFC 8693 Cryptographic Sender & Actor Chain Verification
    const tokenAzp = decoded.appid || decoded.azp;
    const actorChain = [];
    let currAct = decoded.act;
    while (currAct && currAct.sub) {
      actorChain.push(currAct.sub);
      currAct = currAct.act;
    }

    // Agent identity proof: the workload that is calling must prove its SPIFFE ID with a JWT-SVID for this server.
    const verifier = getAgentVerifier();
    if (verifier) {
      if (!agentIdentityHeader) {
        return { authenticated: false, error: 'Agent identity proof (X-Agent-Identity JWT-SVID) is required.' };
      }
      let svid;
      try {
        svid = await verifier(agentIdentityHeader);
      } catch (err) {
        return { authenticated: false, error: err instanceof SpiffeError ? err.message : `JWT-SVID verification failed: ${err.message}` };
      }
      if (actorChain.length > 0 && actorChain[0] !== svid.spiffeId) {
        return {
          authenticated: false,
          error: `RFC 8693 chain verification failed: the token's actor '${actorChain[0]}' does not match the SPIFFE ID '${svid.spiffeId}' proven by the JWT-SVID.`
        };
      }
      if (actorChain.length === 0) actorChain.push(svid.spiffeId);
      if (!(tokenAzp && AUTHORIZED_SENDERS.includes(tokenAzp))) {
        return { authenticated: false, error: `RFC 8693 chain verification failed: the calling application '${tokenAzp}' is not an authorized sender.` };
      }
    }

    const actorSub = actorChain[0] || decoded.act?.sub;
    const isValidSender =
      (tokenAzp && AUTHORIZED_SENDERS.includes(tokenAzp)) ||
      (actorSub && AUTHORIZED_SENDERS.includes(actorSub));

    if (!isValidSender) {
      console.warn(`[MCP-AUTH] ❌ Sender verification failed: unauthorized client '${tokenAzp || actorSub}'`);
      return {
        authenticated: false,
        error: `RFC 8693 Cryptographic chain verification failed: unauthorized actor '${tokenAzp || actorSub}'.`
      };
    }

    // Verify all actors in the recursive chain are trusted
    for (const actor of actorChain) {
      const isTrusted = AUTHORIZED_SENDERS.includes(actor);
      if (!isTrusted) {
        console.warn(`[MCP-AUTH] ❌ Untrusted actor in RFC 8693 chain: '${actor}'`);
        return {
          authenticated: false,
          error: `RFC 8693 Cryptographic chain verification failed: untrusted actor '${actor}' in delegation chain.`
        };
      }
    }
    console.log(`[MCP-AUTH] ✅ RFC 8693 Actor chain cryptographically verified: [${(actorChain.length ? actorChain : [tokenAzp || 'authorized-agent']).join(' -> ')}]`);

    // 3. Delegated scopes. Only a token issued on behalf of a signed-in user is accepted: it carries the scopes the user's
    //    session was granted in `scp` (for example Mcp.Storage.ReadApp1). App-only tokens (roles, no scp) are refused, and
    //    nothing about the user's name or roles widens the scopes.
    if (decoded.idtyp === 'app' || typeof decoded.scp !== 'string' || !decoded.scp.trim()) {
      return {
        authenticated: false,
        error: 'A delegated user token with an scp claim is required; app-only tokens are not accepted.'
      };
    }
    const scopes = decoded.scp.split(' ').filter(Boolean);
    const roles = Array.isArray(decoded.roles) ? decoded.roles : [];
    console.log(`[MCP-AUTH] ✅ Delegated scopes: [${scopes.join(', ')}]`);

    // 4. Resolve the delegated human user (from the verified token only)
    const userUpn = decoded.upn || decoded.preferred_username || decoded.unique_name || decoded.email || decoded.sub || 'anonymous-user';
    const delegatedUser = {
      sub: userUpn,
      email: userUpn,
      oid: decoded.oid || null,
      roles: roles
    };
    console.log(`[MCP-AUTH] ✅ Delegated user principal: sub='${delegatedUser.sub}', oid='${delegatedUser.oid}'`);

    const agentSpiffeId = actorSub || (tokenAzp ? `entra://${tokenAzp}` : 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa');

    return {
      authenticated: true,
      sub: delegatedUser.sub,
      email: delegatedUser.email,
      aud: decoded.aud,
      azp: tokenAzp || 'a23206e1-2dda-4854-aac7-0536d2da2c4c',
      act: decoded.act || { sub: agentSpiffeId },
      actorChain: actorChain.length ? actorChain : [agentSpiffeId],
      scopes: scopes,
      oid: delegatedUser.oid,
      roles: delegatedUser.roles,
      tokenPayload: decoded,
      rawToken: token
    };
  } catch (err) {
    return {
      authenticated: false,
      error: `Token verification failed: ${err.message}`
    };
  }
}

module.exports = {
  verifyOboToken,
  setAgentVerifier,
  AUTHORIZED_SENDERS
};
