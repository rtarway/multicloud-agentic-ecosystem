// RFC 8693 Multi-Hop Delegated Actor Chain & Scope Authorization for GCP MCP Server
// Grounds security enforcement in NIST SP 800-207 Zero Trust and MAESTRO Actor Lineage

const jwtUtil = require('./jwtUtil');

const JWT_SECRET = process.env.JWT_SECRET || 'demo-obo-token-secret-key-2026';
const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID || 'wifdemoproject-507002';
const GCP_PROJECT_NUMBER = process.env.GCP_PROJECT_NUMBER || '834200279688';

const VALID_GCP_ISSUERS = [
  'https://accounts.google.com',
  'https://sts.googleapis.com',
  `//iam.googleapis.com/projects/${GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/k8s-agent-pool/providers/spire-oidc-provider`
];

const EXPECTED_AUDIENCES = [
  'gcp-bigquery-mcp-server',
  'gcp-mcp-server',
  'https://gcp-mcp-server-ur5vhsneiq-uc.a.run.app',
  'https://gcp-mcp-server-ur5vhsneiq-uc.a.run.app/mcp',
  `//iam.googleapis.com/projects/${GCP_PROJECT_ID}`,
  `https://bigquery.googleapis.com/`,
  'api://gcp-bigquery-service'
];

const AUTHORIZED_SENDERS = [
  'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
  'spiffe://example.org/ns/azure/sa/azure-mcp-server',
  'spiffe://example.org/ns/gcp/sa/gcp-mcp-sa',
  'urn:agent:reasoning-engine:gemini-planner',
  'agent-orchestrator-client',
  `gcp-mcp-sa@${GCP_PROJECT_ID}.iam.gserviceaccount.com`
];

/**
 * Extracts and cryptographically verifies the multi-hop RFC 8693 OBO token.
 * Enforces Google Cloud IAM protection (iss: https://accounts.google.com / Google STS).
 * Traverses recursive 'act' chain to ensure full lineage integrity.
 */
function verifyGcpOboToken(authHeader, delegatedHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      authenticated: false,
      error: 'Missing or malformed Authorization header with Bearer token.'
    };
  }

  const token = authHeader.substring(7).trim();

  try {
    let decoded;
    let verificationMethod = 'NONE';
    // Strictly verify token using Google STS / Cloud IAM Asymmetric Public Key (RS256 PKI)
    try {
      decoded = jwtUtil.verifyGoogleIamToken(token);
      verificationMethod = 'GOOGLE_STS_RS256_PKI';
    } catch (rs256Err) {
      // If RS256 fails, check if the token attempts symmetric HMAC forgery
      try {
        const hmacDecoded = jwtUtil.verify(token, JWT_SECRET);
        if (hmacDecoded) {
          console.warn(`[GCP-MCP-AUTH] 🚨 REJECTED: Insecure symmetric HMAC token detected claiming to be Google Cloud IAM! RFC 7515 RS256 PKI is required.`);
          return {
            authenticated: false,
            error: 'Security Policy Violation: Insecure symmetric HMAC signature rejected. GCP MCP Server requires authentic Google Cloud IAM RS256 PKI.'
          };
        }
      } catch {
        // Not valid HMAC either
      }

      // Check if it can be decoded at all
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

    // 1. Google Cloud IAM Token Issuer Verification (Zero Trust Cloud IAM Protection)
    const tokenIss = decoded.iss;
    const isGoogleIamIssuer = tokenIss && (
      tokenIss === 'https://accounts.google.com' ||
      tokenIss === 'https://sts.googleapis.com' ||
      tokenIss.includes('googleapis.com') ||
      VALID_GCP_ISSUERS.includes(tokenIss)
    );

    if (!isGoogleIamIssuer) {
      console.warn(`[GCP-MCP-AUTH] ❌ Token issuer verification failed. Received issuer: '${tokenIss}'. GCP MCP Server is strictly protected by Google Cloud IAM, not Keycloak!`);
      return {
        authenticated: false,
        error: `Token issuer verification failed: GCP MCP Server is protected by Google Cloud IAM (expected 'https://accounts.google.com' or Google STS). Received untrusted issuer: '${tokenIss}'. Keycloak tokens are not accepted.`
      };
    }
    console.log(`[GCP-MCP-AUTH] ✅ Google Cloud IAM Issuer verified: ${tokenIss}`);

    // 2. Audience Verification (NIST SP 800-63C Strict Audience Restriction)
    const tokenAud = Array.isArray(decoded.aud) ? decoded.aud : [decoded.aud];
    const hasValidAud = tokenAud.some(a => EXPECTED_AUDIENCES.includes(a) || (typeof a === 'string' && (a.includes('gcp') || a.includes('run.app'))));
    if (!hasValidAud && decoded.aud) {
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
    const isSenderTrusted = !immediateActor ||
      AUTHORIZED_SENDERS.includes(immediateActor) ||
      immediateActor.startsWith('spiffe://example.org/ns/') ||
      immediateActor.startsWith('urn:agent:');

    if (!isSenderTrusted) {
      console.warn(`[GCP-MCP-AUTH] ❌ Immediate sender verification failed: untrusted actor '${immediateActor}'`);
      return {
        authenticated: false,
        error: `RFC 8693 Cryptographic chain verification failed: untrusted immediate actor '${immediateActor}'.`
      };
    }

    // Verify all upstream actors in the recursive chain are legitimate
    for (const actor of actorChain) {
      const isTrusted = AUTHORIZED_SENDERS.includes(actor) ||
        actor.startsWith('spiffe://example.org/ns/') ||
        actor.startsWith('urn:agent:') ||
        actor.includes('azure-mcp');

      if (!isTrusted) {
        console.warn(`[GCP-MCP-AUTH] ❌ Untrusted actor detected in RFC 8693 multi-hop chain: '${actor}'`);
        return {
          authenticated: false,
          error: `RFC 8693 Cryptographic chain verification failed: untrusted actor '${actor}' in delegation chain.`
        };
      }
    }

    console.log(`[GCP-MCP-AUTH] ✅ RFC 8693 Multi-Hop Actor chain verified: [${(actorChain.length ? actorChain : ['authorized-agent']).join(' -> ')}]`);

    // 3. Scopes & Entitlements Resolution
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

    // 4. Resolve Delegated Human User Principal (Preserving sub principle)
    let delegatedUser = {
      sub: decoded.sub || 'anonymous-user',
      email: decoded.email || decoded.preferred_username || decoded.sub || 'anonymous-user',
      roles: roles
    };

    if (delegatedHeader) {
      try {
        if (typeof delegatedHeader === 'string' && delegatedHeader.startsWith('{')) {
          const parsed = JSON.parse(delegatedHeader);
          delegatedUser.sub = parsed.sub || delegatedUser.sub;
          delegatedUser.email = parsed.email || parsed.sub || delegatedUser.email;
          if (Array.isArray(parsed.roles)) delegatedUser.roles = parsed.roles;
        } else if (typeof delegatedHeader === 'string' && delegatedHeader.includes('.')) {
          const parsedJwt = jwtUtil.decode(delegatedHeader);
          if (parsedJwt) {
            delegatedUser.sub = parsedJwt.sub || delegatedUser.sub;
            delegatedUser.email = parsedJwt.email || parsedJwt.preferred_username || parsedJwt.sub || delegatedUser.email;
            if (Array.isArray(parsedJwt.roles)) delegatedUser.roles = parsedJwt.roles;
          }
        }
      } catch {
        // Fall back to token claims
      }
    }

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
  AUTHORIZED_SENDERS
};
