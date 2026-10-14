// Multi-Cloud Workload Identity Federation (WIF) & RFC 8693 Token Exchange Engine
// Bridges External Human User Identity (from Keycloak) and Agent Identity (from SPIRE/K8s)
// into authorized, downscoped Bearer tokens for Microsoft Entra ID (Azure) and Google Cloud STS (GCP).
// Implements RFC 8693 recursive multi-hop delegated actor chains preserving human 'sub' principle.

const https = require('https');
const querystring = require('querystring');
const jwtUtil = require('./jwtUtil');
const { isSimulation } = require('./simulation');
const { ExchangeError } = require('./idpExchange');
const { storageScope, ScopeError } = require('./azureScopes');

// Load .env if present
try {
  const fs = require('fs');
  const path = require('path');
  const envPath = path.resolve(__dirname, '../../../.env');
  if (fs.existsSync(envPath)) {
    const envLines = fs.readFileSync(envPath, 'utf8').split('\n');
    for (const line of envLines) {
      const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
      if (match && !process.env[match[1]]) {
        process.env[match[1]] = match[2].trim().replace(/^['"]|['"]$/g, '');
      }
    }
  }
} catch {}

// Azure Configurations
const ENTRA_TENANT_ID = process.env.ENTRA_TENANT_ID || '81f26b58-159c-4879-80a0-bab30b5b4dd3';
const ENTRA_AGENT_CLIENT_ID = process.env.ENTRA_AGENT_CLIENT_ID || 'a23206e1-2dda-4854-aac7-0536d2da2c4c';
const ENTRA_MCP_APP_ID = process.env.ENTRA_MCP_APP_ID || 'd5850aa0-a667-41c3-8dd0-16f2dee4da25';
const ENTRA_AUDIENCE = process.env.ENTRA_AUDIENCE || `api://${ENTRA_MCP_APP_ID}`;

// GCP Configurations (Workload Identity Federation for Direct Subject IAM Grants + SPIRE Workload Pool)
const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID || 'wifdemoproject-507002';
const GCP_PROJECT_NUMBER = process.env.GCP_PROJECT_NUMBER || '834200279688';
const GCP_POOL_ID = process.env.GCP_POOL_ID || 'k8s-agent-pool';
const GCP_PROVIDER_ID = process.env.GCP_PROVIDER_ID || 'spire-oidc-provider';
const GCP_MCP_AUDIENCE = process.env.GCP_MCP_AUDIENCE || 'gcp-bigquery-mcp-server';
// Client id of the GCP MCP server at the IdP: the single audience of tokens exchanged for BigQuery tools
const GCP_MCP_CLIENT_ID = process.env.GCP_MCP_CLIENT_ID || 'mcp-gcp-service';
const GCP_SERVICE_ACCOUNT = process.env.GCP_SERVICE_ACCOUNT || `gcp-mcp-sa@${GCP_PROJECT_ID}.iam.gserviceaccount.com`;


class TokenExchangeEngine {
  /**
   * Source of the client assertion the orchestrator's Entra application authenticates with: a JWT-SVID issued by SPIRE
   * for the Entra federated-credential audience. There is no client secret anywhere.
   */
  setClientAssertionProvider(provider) {
    this.clientAssertionProvider = provider || null;
  }

  async _clientAssertion() {
    if (this.clientAssertionProvider) return this.clientAssertionProvider();
    const spireClient = require('./spireClient');
    return (await spireClient.fetchJwtSvid('api://AzureADTokenExchange')).token;
  }

  /** Injects the IdP exchange client (created at startup from the environment, or a fake in tests). */
  setIdpClient(client) {
    this.idpClient = client || null;
  }

  /**
   * Performs HTTP request to Microsoft Entra ID Token Endpoint via WIF (RFC 7523)
   */
  async _callEntraWifTokenExchange(params) {
    const postData = querystring.stringify(params);
    const parsedUrl = new URL(`https://login.microsoftonline.com/${ENTRA_TENANT_ID}/oauth2/v2.0/token`);

    return new Promise((resolve, reject) => {
      const req = https.request(
        parsedUrl,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(postData)
          },
          timeout: 2000
        },
        res => {
          let raw = '';
          res.on('data', chunk => (raw += chunk));
          res.on('end', () => {
            try {
              resolve({ statusCode: res.statusCode, body: JSON.parse(raw) });
            } catch {
              resolve({ statusCode: res.statusCode, body: raw });
            }
          });
        }
      );

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Azure Entra token exchange request timed out.'));
      });
      req.write(postData);
      req.end();
    });
  }

  _entraFailure(code, message, { userEmail, agentSpiffeId, requestedTool, requiredScopeForTool, claimsChallenge = null }) {
    return {
      isError: true,
      status: code === 'STEP_UP_REQUIRED' ? 'STEP_UP_REQUIRED' : 'EXCHANGE_FAILED',
      code,
      error: message,
      tokenType: 'TOKEN_EXCHANGE_FAILED',
      ...(claimsChallenge ? { claimsChallenge } : {}),
      audit: { subject: userEmail, actor: agentSpiffeId, requestedTool, requiredScope: requiredScopeForTool, decision: code === 'STEP_UP_REQUIRED' ? 'STEP_UP_REQUIRED' : 'EXCHANGE_FAILED', code }
    };
  }

  /**
   * Strict mode: obtains a token for ONE resource server and ONE agent scope from the identity provider.
   * The orchestrator signs nothing; any failure is returned as an error and halts the step.
   */
  async _exchangeViaIdp({ verifiedUser, userEmail, userRoles, requestedTool, requiredScopeForTool, agentSpiffeId, recursiveAct, actorChain, userEligibleScopes, audience }) {
    const failure = (code, message) => ({
      isError: true,
      status: 'EXCHANGE_FAILED',
      code,
      error: `${message} Refusing to fall back to a locally signed token.`,
      tokenType: 'TOKEN_EXCHANGE_FAILED',
      audit: { subject: userEmail, actor: agentSpiffeId, requestedTool, requiredScope: requiredScopeForTool, decision: 'EXCHANGE_FAILED', code }
    });

    if (!this.idpClient) return failure('IDP_NOT_CONFIGURED', 'The identity provider token-exchange client is not configured.');

    try {
      const result = await this.idpClient.exchange({
        subjectToken: verifiedUser.token,
        audience,
        scope: requiredScopeForTool,
        expectedActor: agentSpiffeId
      });
      return {
        exchangedToken: result.token,
        tokenType: 'IDP_TOKEN_EXCHANGE',
        claims: result.claims,
        delegatedUser: { sub: userEmail, email: userEmail, roles: userRoles },
        audit: {
          subject: userEmail,
          actor: agentSpiffeId,
          // Only the IdP-attested actor above is used for authorization downstream; the fuller lineage is informational.
          unattestedLineage: actorChain,
          userRoles,
          eligibleScopes: userEligibleScopes,
          grantedScopes: [requiredScopeForTool],
          requestedTool,
          tokenIssuer: 'Identity provider (RFC 8693 standard token exchange)'
        },
        lineage: recursiveAct
      };
    } catch (err) {
      return failure(err instanceof ExchangeError ? err.code : 'IDP_EXCHANGE_FAILED', err.message);
    }
  }

  /**
   * Constructs an RFC 8693 recursive actor chain reflecting multi-hop provenance
   */
  _buildRecursiveActorChain(agentSpiffeId, turn = 1, priorHops = []) {
    // Inner-most reasoning planner node
    let currentInnerAct = {
      sub: 'urn:agent:reasoning-engine:gemini-planner',
      role: 'cognitive-reasoner',
      turn
    };

    // If there were prior hops (e.g. Turn 1 was Azure Storage), link them into the recursive chain
    if (priorHops && priorHops.length > 0) {
      const lastHop = priorHops[priorHops.length - 1];
      currentInnerAct.priorHop = {
        tool: lastHop.tool,
        targetResource: lastHop.targetResource,
        status: lastHop.status
      };
      currentInnerAct.act = {
        sub: lastHop.tool === 'tool1' ? 'spiffe://example.org/ns/azure/sa/azure-mcp-server' : (lastHop.tool || 'prior-service'),
        role: 'prior-tool-execution',
        hop: lastHop.stepNumber || 1
      };
    }

    // Outer actor is the immediate orchestrator presenting the token
    return {
      sub: agentSpiffeId,
      role: 'orchestrator',
      hop: (priorHops ? priorHops.length : 0) + 1,
      act: currentInnerAct
    };
  }

  /**
   * Executes Multi-Cloud RFC 8693 Token Exchange with Multi-Hop Lineage and Scope Downscoping
   */
  async exchangeToken({ userToken, verifiedUser = null, userEntraToken, agentSvid, targetAudience = ENTRA_AUDIENCE, requestedTool = 'tool1', toolArgs = {}, priorHops = [], turn = 1 }) {
    // verifiedUser is present in strict mode (user token verified against the IdP and mapped through the directory)
    const strict = Boolean(verifiedUser);
    // 1. Validate & Parse Subject Token (User from Keycloak or incoming Entra user token)
    let userClaims = {};
    if (userToken) {
      userClaims = jwtUtil.decode(userToken) || {};
    } else if (userEntraToken) {
      userClaims = jwtUtil.decode(userEntraToken) || {};
    }

    const userSub = userClaims.sub || userClaims.preferred_username || userClaims.unique_name || 'anonymous-user';
    const userEmail = strict
      ? verifiedUser.identity.keycloakEmail
      : (userClaims.email || userClaims.upn || userClaims.unique_name || userSub);
    const userRoles = strict
      ? verifiedUser.roles
      : (Array.isArray(userClaims.roles)
        ? userClaims.roles
        : (userClaims.realm_access?.roles || ['regular-user']));

    const isAdmin = userRoles.includes('admin') || userRoles.includes('BigQuery.Admin');
    const userScopesFromToken = (userClaims.scope ? userClaims.scope.split(' ') : []);
    const hasMailSend = userScopesFromToken.includes('Mail.Send') || userRoles.includes('Mail.Send');

    // Determine Required Scope for Requested Tool
    let requiredScopeForTool = 'mcp:tool1';
    let isGcpTool = false;

    if (requestedTool === 'tool2') {
      requiredScopeForTool = 'mcp:tool2';
    } else if (requestedTool === 'bigquery_query_sales') {
      requiredScopeForTool = 'mcp:bigquery:query';
      isGcpTool = true;
      if (targetAudience === ENTRA_AUDIENCE) targetAudience = GCP_MCP_AUDIENCE;
    } else if (requestedTool === 'bigquery_audit_compliance') {
      requiredScopeForTool = 'mcp:bigquery:audit';
      isGcpTool = true;
      if (targetAudience === ENTRA_AUDIENCE) targetAudience = GCP_MCP_AUDIENCE;
    } else if (requestedTool === 'microsoft_graph_direct' || requestedTool === 'send_email_graph' || requestedTool === 'Mail.Send' || targetAudience === 'https://graph.microsoft.com') {
      requiredScopeForTool = 'Mail.Send';
      if (targetAudience === ENTRA_AUDIENCE) {
        targetAudience = 'https://graph.microsoft.com';
      }
    }

    // 1. Determine Eligible Scopes for Principal (Strict RFC 8693 Section 2.1 Intersection)
    // Strict mode: eligibility (group membership in the directory) intersected with consent (token scope claim).
    const userEligibleScopes = [];
    if (strict) {
      userEligibleScopes.push(...verifiedUser.eligibleScopes);
    } else {
      if (isAdmin || userScopesFromToken.includes('mcp:tool1') || userRoles.includes('Storage Blob Data Reader') || userRoles.includes('Storage Blob Data Contributor') || userRoles.includes('regular-user')) {
        userEligibleScopes.push('mcp:tool1');
      }
      if (isAdmin || userScopesFromToken.includes('mcp:tool2')) {
        userEligibleScopes.push('mcp:tool2');
      }
      if (isAdmin || userScopesFromToken.includes('mcp:bigquery:query') || userRoles.includes('BigQuery.Admin') || userRoles.includes('BigQuery.User')) {
        userEligibleScopes.push('mcp:bigquery:query');
      }
      if (isAdmin || userScopesFromToken.includes('mcp:bigquery:audit')) {
        userEligibleScopes.push('mcp:bigquery:audit');
      }
      if (hasMailSend) {
        userEligibleScopes.push('Mail.Send');
      }
    }

    const isScopeAuthorized = userEligibleScopes.includes(requiredScopeForTool);

    // GATE 1: Fail-Closed Enforcement of RFC 8693 Section 2.1 (No Scope Escalation)
    if (!isScopeAuthorized) {
      console.warn(`[ORCH-AUTH] ❌ RFC 8693 Scope Escalation Denied: Subject '${userEmail}' lacks required scope '${requiredScopeForTool}' in IdP token.`);
      console.warn(`[ORCH-AUTH]    Granted IdP Scopes: [${userScopesFromToken.join(', ')}], Eligible Scopes: [${userEligibleScopes.join(', ')}]`);
      return {
        isError: true,
        status: 'DENIED_BY_POLICY',
        code: 'SCOPE_ESCALATION_DENIED',
        error: `RFC 8693 Violation: Subject '${userEmail}' lacks required scope '${requiredScopeForTool}' in IdP token. Delegation halted.`,
        requiredScope: requiredScopeForTool,
        userEligibleScopes,
        tokenType: 'TOKEN_EXCHANGE_DENIED',
        audit: {
          subject: userEmail,
          actor: agentSvid?.spiffeId || 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
          userRoles,
          eligibleScopes: userEligibleScopes,
          requestedTool,
          requiredScope: requiredScopeForTool,
          decision: 'DENIED_BY_POLICY',
          code: 'SCOPE_ESCALATION_DENIED'
        }
      };
    }

    const finalScopes = [requiredScopeForTool];
    const agentSpiffeId = agentSvid?.spiffeId || 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa';

    // 2. Build RFC 8693 Recursive Actor Chain
    const recursiveAct = this._buildRecursiveActorChain(agentSpiffeId, turn, priorHops);

    // Flatten actor chain for quick inspection and logging
    const actorChain = [];
    let cur = recursiveAct;
    while (cur && cur.sub) {
      actorChain.push(cur.sub);
      cur = cur.act;
    }

    // 3. GCP target.
    // There is no real Google exchange yet (Phase 4 replaces this with a per-user Google OAuth grant held by
    // the GCP MCP server). Outside the demo profile this fails closed instead of minting a lookalike token.
    if (isGcpTool || targetAudience === GCP_MCP_AUDIENCE || targetAudience.includes('googleapis.com')) {
      if (strict) {
        return this._exchangeViaIdp({
          verifiedUser, userEmail, userRoles, requestedTool, requiredScopeForTool, agentSpiffeId,
          recursiveAct, actorChain, userEligibleScopes, audience: GCP_MCP_CLIENT_ID
        });
      }

      if (!isSimulation()) {
        return {
          isError: true,
          status: 'EXCHANGE_UNAVAILABLE',
          code: 'GCP_EXCHANGE_UNAVAILABLE',
          error: 'No real Google credential exchange is available (simulation disabled). Refusing to mint a locally signed Google token.',
          tokenType: 'TOKEN_EXCHANGE_FAILED',
          audit: {
            subject: userEmail,
            actor: agentSpiffeId,
            requestedTool,
            requiredScope: requiredScopeForTool,
            decision: 'EXCHANGE_UNAVAILABLE',
            code: 'GCP_EXCHANGE_UNAVAILABLE'
          }
        };
      }

      const isAuditTool = requiredScopeForTool === 'mcp:bigquery:audit';
      const targetDataset = isAuditTool ? 'audit_logs' : 'analytics_data';
      const targetTable = isAuditTool ? 'access_audit' : 'regional_sales';

      // Demo-profile description of the intended resource boundary (no STS call is made).
      const credentialAccessBoundary = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: `//bigquery.googleapis.com/projects/${GCP_PROJECT_NUMBER}/datasets/${targetDataset}/tables/${targetTable}`,
              availablePermissions: [
                isAuditTool ? 'inRole:roles/bigquery.admin' : 'inRole:roles/bigquery.dataViewer'
              ],
              availabilityCondition: {
                title: 'TableAccessBoundary',
                expression: `resource.name.startsWith('projects/${GCP_PROJECT_ID}/datasets/${targetDataset}')`
              }
            }
          ]
        }
      };

      // Demo-only, locally signed stand-in for a Google-issued token (clearly flagged as simulated).
      const gcpClaims = {
        iss: 'https://sts.googleapis.com',
        aud: targetAudience || GCP_MCP_AUDIENCE,
        azp: GCP_SERVICE_ACCOUNT,
        sub: userEmail,
        email: userEmail,
        email_verified: true,
        roles: finalScopes,
        scope: finalScopes.join(' '),
        act: recursiveAct,
        actorChain,
        downscoped: true,
        cloudPlatform: 'GCP',
        credentialAccessBoundary,
        x_simulated: true,
        google_cloud_iam: {
          projectId: GCP_PROJECT_ID,
          projectNumber: GCP_PROJECT_NUMBER,
          poolId: GCP_POOL_ID,
          providerId: GCP_PROVIDER_ID,
          federationType: 'WorkloadIdentityFederation',
          principal: `principal://iam.googleapis.com/projects/${GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/${GCP_POOL_ID}/subject/${userEmail}`,
          serviceAccount: GCP_SERVICE_ACCOUNT,
          cabResource: credentialAccessBoundary.accessBoundary.accessBoundaryRules[0].availableResource
        },
        delegationType: 'RFC8693_MULTI_HOP_CHAIN'
      };

      const googleStsPrivateKey = jwtUtil.getGoogleStsPrivateKey();
      const exchangedToken = jwtUtil.signRS256(gcpClaims, googleStsPrivateKey, { expiresInSeconds: 300 });

      return {
        exchangedToken,
        tokenType: 'GCP_IAM_RFC8693_DELEGATION',
        claims: gcpClaims,
        credentialAccessBoundary,
        delegatedUser: {
          sub: userEmail,
          email: userEmail,
          roles: userRoles
        },
        audit: {
          subject: userEmail,
          actor: agentSpiffeId,
          actorChain,
          userRoles,
          eligibleScopes: userEligibleScopes,
          grantedScopes: finalScopes,
          requestedTool,
          tokenIssuer: 'Simulated Google Cloud IAM (demo profile)',
          credentialAccessBoundary
        }
      };
    }

    // 4. Microsoft Entra ID On-Behalf-Of exchange, for exactly the delegated scope this call needs.
    //    - Storage tools: the Azure MCP server's own fine-grained scope, e.g. api://<mcp>/Mcp.Storage.ReadApp1
    //    - Mail: Microsoft Graph Mail.Send
    //    The orchestrator authenticates with a SPIFFE JWT-SVID as the client assertion (no client secret), and there is no
    //    password-grant or client-credentials fallback: a missing assertion would silently turn a user-delegated call
    //    into an app-only one.
    const isGraph = requiredScopeForTool === 'Mail.Send';
    let entraScope;
    try {
      entraScope = isGraph
        ? 'https://graph.microsoft.com/Mail.Send'
        : `api://${ENTRA_MCP_APP_ID}/${storageScope(requestedTool === 'tool2' ? 'read' : (toolArgs.action || 'read'), requestedTool === 'tool2' ? 'app1' : toolArgs.container)}`;
    } catch (err) {
      if (!(err instanceof ScopeError)) throw err;
      return this._entraFailure('INVALID_STORAGE_REQUEST', err.message, { userEmail, agentSpiffeId, requestedTool, requiredScopeForTool });
    }
    const entraScopeName = entraScope.split('/').pop();

    let liveEntraToken = null;
    const assertionToken = userEntraToken || null;
    let oboFailure = null;
    let failureCode = assertionToken ? 'ENTRA_OBO_FAILED' : 'USER_ASSERTION_REQUIRED';
    let claimsChallenge = null;

    // The Entra user must be the same person as the authenticated IdP user (guards against attaching someone else's token)
    if (assertionToken && strict) {
      const assertionClaims = jwtUtil.decode(assertionToken) || {};
      const assertionUser = String(assertionClaims.upn || assertionClaims.preferred_username || '').toLowerCase();
      if (assertionUser !== verifiedUser.identity.entraUpn) {
        return this._entraFailure('ENTRA_IDENTITY_MISMATCH', 'The Entra assertion belongs to a different user than the authenticated session.', { userEmail, agentSpiffeId, requestedTool, requiredScopeForTool });
      }
    }

    if (assertionToken) {
      try {
        console.log(`[ORCH-OBO] Requesting Microsoft Entra ID OBO token (scope: ${entraScopeName}, subject: ${userEmail}, actor: ${agentSpiffeId})`);
        const entraResponse = await this._callEntraWifTokenExchange({
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          client_id: ENTRA_AGENT_CLIENT_ID,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: await this._clientAssertion(),
          assertion: assertionToken,
          scope: entraScope,
          requested_token_use: 'on_behalf_of'
        });
        console.log(`[ORCH-OBO] Entra ID token response: HTTP ${entraResponse.statusCode}`);
        const body = entraResponse.body && typeof entraResponse.body === 'object' ? entraResponse.body : {};
        if (entraResponse.statusCode === 200 && body.access_token) {
          liveEntraToken = body.access_token;
        } else if (body.claims && (body.error === 'interaction_required' || body.error === 'invalid_grant')) {
          failureCode = 'STEP_UP_REQUIRED';
          claimsChallenge = body.claims;
          oboFailure = 'Entra requires additional user interaction (for example MFA) before this action.';
        } else {
          oboFailure = `Entra OBO exchange failed (HTTP ${entraResponse.statusCode}${body.error ? `: ${body.error}` : ''}).`;
        }
      } catch (err) {
        oboFailure = `Entra OBO exchange failed: ${err.message}`;
      }
    } else {
      oboFailure = 'A user Entra assertion is required for the on-behalf-of exchange.';
    }

    // Verify what Entra returned: right resource, the requested delegated scope, and the same user.
    if (liveEntraToken) {
      const claims = jwtUtil.decode(liveEntraToken) || {};
      const aud = String(claims.aud || '');
      const audienceOk = isGraph
        ? ['https://graph.microsoft.com', 'https://graph.microsoft.com/', '00000003-0000-0000-c000-000000000000'].includes(aud)
        : [ENTRA_MCP_APP_ID, `api://${ENTRA_MCP_APP_ID}`].includes(aud);
      const scopeOk = String(claims.scp || '').split(' ').includes(entraScopeName);
      const tokenUser = String(claims.upn || claims.preferred_username || '').toLowerCase();
      const userOk = !strict || !tokenUser || tokenUser === verifiedUser.identity.entraUpn;
      if (!audienceOk || !scopeOk || !userOk) {
        liveEntraToken = null;
        failureCode = 'ENTRA_TOKEN_INVALID';
        oboFailure = !userOk ? 'The Entra token is for a different user than the authenticated session.'
          : !audienceOk ? `The Entra token audience '${aud}' is not the expected resource.`
            : `The Entra token does not carry the requested delegated scope '${entraScopeName}'.`;
      }
    }

    if (!liveEntraToken && (strict || !isSimulation())) {
      return this._entraFailure(failureCode, `${oboFailure} Refusing to fall back to an app-only or locally signed token.`, { userEmail, agentSpiffeId, requestedTool, requiredScopeForTool, claimsChallenge });
    }

    // 5. Build Entra ID RFC 8693 Token Claims (RS256 PKI - Never Symmetric HMAC)
    const entraClaims = {
      iss: `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0`,
      tid: ENTRA_TENANT_ID,
      aud: targetAudience,
      sub: userEmail,
      upn: userEmail,
      unique_name: userEmail,
      email: userEmail,
      appid: ENTRA_AGENT_CLIENT_ID,
      azp: ENTRA_AGENT_CLIENT_ID,
      roles: finalScopes,
      scp: entraScopeName,
      scope: finalScopes.join(' '),
      act: recursiveAct,
      actorChain,
      downscoped: true,
      ...(liveEntraToken ? {} : { x_simulated: true }),
      delegationType: assertionToken ? 'RFC8693_ENTRA_OBO' : 'RFC8693_MULTI_HOP_CHAIN'
    };

    // Demo profile only: locally signed stand-in for an Entra token (the non-simulation path returned above).
    const exchangedToken = liveEntraToken ||
      jwtUtil.signRS256(entraClaims, jwtUtil.getAzureTestPrivateKey(), { kid: 'azure-test-key-1', expiresInSeconds: 300 });

    return {
      exchangedToken,
      tokenType: liveEntraToken ? 'AZURE_ENTRA_OBO_LIVE' : 'AZURE_ENTRA_WIF_RS256_TEST',
      claims: entraClaims,
      delegatedUser: {
        sub: userEmail,
        email: userEmail,
        roles: userRoles
      },
      audit: {
        subject: userEmail,
        actor: agentSpiffeId,
        actorChain,
        userRoles,
        eligibleScopes: userEligibleScopes,
        grantedScopes: finalScopes,
        requestedTool,
        tokenIssuer: assertionToken ? 'Microsoft Entra ID (Native OBO)' : 'Microsoft Entra ID (Azure WIF)'
      }
    };
  }
}

module.exports = new TokenExchangeEngine();
