// RFC 8693 Multi-Hop Delegated Actor Chain & Scope Authorization for GCP MCP Server
// Grounds security enforcement in NIST SP 800-207 Zero Trust and MAESTRO Actor Lineage
//
// Phase 0 hardening: the user identity comes ONLY from the verified token (no caller-supplied
// identity headers), the audience is mandatory and compared exactly, and the issuer is matched
// against an exact list.

const jwtUtil = require('./jwtUtil');

const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID || 'wifdemoproject-507002';
const GCP_PROJECT_NUMBER = process.env.GCP_PROJECT_NUMBER || '834200279688';

const VALID_GCP_ISSUERS = [
  'https://accounts.google.com',
  'https://sts.googleapis.com',
  `//iam.googleapis.com/projects/${GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/k8s-agent-pool/providers/spire-oidc-provider`,
  '//iam.googleapis.com/locations/global/workforcePools/enterprise-workforce-pool/providers/keycloak-workforce-provider'
];

const EXPECTED_AUDIENCES = [
  'gcp-bigquery-mcp-server',
  'gcp-mcp-server',
  'https://gcp-mcp-server-ur5vhsneiq-uc.a.run.app',
  'https://gcp-mcp-server-ur5vhsneiq-uc.a.run.app/mcp',
  `//iam.googleapis.com/projects/${GCP_PROJECT_ID}`,
  `https://bigquery.googleapis.com/`,
  'api://gcp-bigquery-service',
  `//iam.googleapis.com/projects/${GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/k8s-agent-pool/providers/spire-oidc-provider`,
  '//iam.googleapis.com/locations/global/workforcePools/enterprise-workforce-pool/providers/keycloak-workforce-provider'
];

// Exact identities only: no prefix or substring matching. ALLOWED_ACTORS (comma-separated) replaces this list.
const AUTHORIZED_SENDERS = process.env.ALLOWED_ACTORS
  ? process.env.ALLOWED_ACTORS.split(',').map(a => a.trim()).filter(Boolean)
  : [
    'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
    'spiffe://example.org/ns/azure/sa/azure-mcp-server',
    'urn:agent:reasoning-engine:gemini-planner'
  ];

const INSECURE_ALGORITHMS = new Set(['HS256', 'HS384', 'HS512', 'NONE']);

function peekAlgorithm(token) {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const header = JSON.parse(jwtUtil.base64UrlDecode(parts[0]));
    return typeof header.alg === 'string' ? header.alg.toUpperCase() : null;
  } catch {
    return null;
  }
}

/**
 * Extracts and cryptographically verifies the multi-hop RFC 8693 OBO token.
 * The principal is taken from the verified token only. The optional second argument is accepted for
 * backward compatibility and ignored (a caller-supplied identity header must never override the token).
 */
function verifyGcpOboToken(authHeader, ignoredDelegatedHeader) {
  if (ignoredDelegatedHeader) {
    console.warn('[GCP-MCP-AUTH] ⚠️ Ignoring caller-supplied X-Delegated-Identity; the user is taken from the verified token only.');
  }

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      authenticated: false,
      error: 'Missing or malformed Authorization header with Bearer token.'
    };
  }

  const token = authHeader.substring(7).trim();

  try {
    // Reject symmetric / unsigned tokens outright (no shared secret exists on this server).
    const alg = peekAlgorithm(token);
    if (alg && INSECURE_ALGORITHMS.has(alg)) {
      console.warn(`[GCP-MCP-AUTH] 🚨 REJECTED: Insecure '${alg}' token presented as Google Cloud IAM. RFC 7515 RS256 PKI is required.`);
      return {
        authenticated: false,
        error: 'Security Policy Violation: Insecure symmetric HMAC signature rejected. GCP MCP Server requires authentic Google Cloud IAM RS256 PKI.'
      };
    }

    let decoded;
    try {
      decoded = jwtUtil.verifyGoogleIamToken(token);
    } catch (rs256Err) {
      const peek = jwtUtil.decode(token);
      if (!peek) {
        return {
          authenticated: false,
          error: `Token verification failed: Invalid JWT format or unverified signature (${rs256Err.message}).`
        };
      }
      return {
        authenticated: false,
        error: `Cryptographic signature verification failed: ${rs256Err.message}`
      };
    }

    if (!decoded) {
      return {
        authenticated: false,
        error: 'Invalid token payload: unable to decode JWT.'
      };
    }

    // 1. Issuer verification (exact match)
    const tokenIss = decoded.iss;
    if (!tokenIss || !VALID_GCP_ISSUERS.includes(tokenIss)) {
      console.warn(`[GCP-MCP-AUTH] ❌ Token issuer verification failed. Received issuer: '${tokenIss}'.`);
      return {
        authenticated: false,
        error: `Token issuer verification failed: GCP MCP Server is protected by Google Cloud IAM (expected 'https://accounts.google.com' or Google STS). Received untrusted issuer: '${tokenIss}'. Keycloak tokens are not accepted.`
      };
    }
    console.log(`[GCP-MCP-AUTH] ✅ Google Cloud IAM Issuer verified: ${tokenIss}`);

    // 2. Audience verification (mandatory, exact match)
    const tokenAud = (Array.isArray(decoded.aud) ? decoded.aud : [decoded.aud]).filter(a => typeof a === 'string' && a);
    if (tokenAud.length === 0) {
      return {
        authenticated: false,
        error: 'Token audience verification failed: the aud claim is required.'
      };
    }
    if (!tokenAud.some(a => EXPECTED_AUDIENCES.includes(a))) {
      console.warn(`[GCP-MCP-AUTH] ❌ Audience check failed. Received: ${JSON.stringify(decoded.aud)}, Expected one of: [${EXPECTED_AUDIENCES.join(', ')}]`);
      return {
        authenticated: false,
        error: `Token audience verification failed: '${JSON.stringify(decoded.aud)}' does not match expected GCP MCP audiences.`
      };
    }
    console.log(`[GCP-MCP-AUTH] ✅ Audience verified: ${JSON.stringify(decoded.aud)}`);

    // 3. RFC 8693 Recursive Multi-Hop Actor Chain Verification
    // Traverses nested act -> act -> act...
    const actorChain = [];
    const actorDetails = [];
    let currAct = decoded.act;
    let hopIndex = 1;

    while (currAct && currAct.sub) {
      actorChain.push(currAct.sub);
      actorDetails.push({
        hop: currAct.hop || hopIndex,
        sub: currAct.sub,
        role: currAct.role || 'delegated-actor',
        turn: currAct.turn || null,
        priorHop: currAct.priorHop || null
      });
      currAct = currAct.act;
      hopIndex++;
    }

    // Immediate presenter is actorChain[0] or default orchestrator
    const immediateActor = actorChain[0] || decoded.act?.sub;
    const isSenderTrusted = !immediateActor || AUTHORIZED_SENDERS.includes(immediateActor);

    if (!isSenderTrusted) {
      console.warn(`[GCP-MCP-AUTH] ❌ Immediate sender verification failed: untrusted actor '${immediateActor}'`);
      return {
        authenticated: false,
        error: `RFC 8693 Cryptographic chain verification failed: untrusted immediate actor '${immediateActor}'.`
      };
    }

    // Verify all upstream actors in the recursive chain are legitimate
    for (const actor of actorChain) {
      const isTrusted = AUTHORIZED_SENDERS.includes(actor);

      if (!isTrusted) {
        console.warn(`[GCP-MCP-AUTH] ❌ Untrusted actor detected in RFC 8693 multi-hop chain: '${actor}'`);
        return {
          authenticated: false,
          error: `RFC 8693 Cryptographic chain verification failed: untrusted actor '${actor}' in delegation chain.`
        };
      }
    }

    console.log(`[GCP-MCP-AUTH] ✅ RFC 8693 Multi-Hop Actor chain verified: [${(actorChain.length ? actorChain : ['authorized-agent']).join(' -> ')}]`);

    // 4. Scopes & Entitlements Resolution
    let scopes = [];
    if (typeof decoded.scope === 'string') {
      scopes = decoded.scope.split(' ').filter(Boolean);
    } else if (typeof decoded.scp === 'string') {
      scopes = decoded.scp.split(' ').filter(Boolean);
    } else if (Array.isArray(decoded.roles)) {
      scopes = decoded.roles.filter(r => r.startsWith('mcp:bigquery:'));
    } else if (Array.isArray(decoded.scopes)) {
      scopes = decoded.scopes;
    }

    const roles = Array.isArray(decoded.roles)
      ? decoded.roles
      : (decoded.realm_access?.roles || []);

    if (scopes.length === 0) {
      if (roles.includes('admin') || roles.includes('BigQuery.Admin')) {
        scopes = ['mcp:bigquery:query', 'mcp:bigquery:audit'];
      } else {
        scopes = ['mcp:bigquery:query'];
      }
    }
    console.log(`[GCP-MCP-AUTH] ✅ Scopes resolved: [${scopes.join(', ')}]`);

    // 5. Delegated human principal: taken from the verified token only
    const delegatedUser = {
      sub: decoded.sub || 'anonymous-user',
      email: decoded.email || decoded.preferred_username || decoded.sub || 'anonymous-user',
      roles
    };

    console.log(`[GCP-MCP-AUTH] ✅ Delegated Human Principal: sub='${delegatedUser.sub}', email='${delegatedUser.email}', roles=[${delegatedUser.roles.join(', ')}]`);

    return {
      authenticated: true,
      sub: delegatedUser.sub,
      email: delegatedUser.email,
      aud: decoded.aud,
      act: decoded.act || { sub: immediateActor || 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa' },
      actorChain: actorChain.length ? actorChain : [immediateActor || 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa'],
      actorDetails,
      scopes,
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
  verifyGcpOboToken,
  EXPECTED_AUDIENCES,
  AUTHORIZED_SENDERS,
  VALID_GCP_ISSUERS
};
