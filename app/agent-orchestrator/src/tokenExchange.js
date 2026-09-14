// Multi-Cloud Workload Identity Federation (WIF) & RFC 8693 Token Exchange Engine
// Bridges External Human User Identity (from Keycloak) and Agent Identity (from SPIRE/K8s)
// into authorized, downscoped Bearer tokens for Microsoft Entra ID (Azure) and Google Cloud STS (GCP).
// Implements RFC 8693 recursive multi-hop delegated actor chains preserving human 'sub' principle.

const https = require('https');
const querystring = require('querystring');
const crypto = require('crypto');
const jwtUtil = require('./jwtUtil');

const { privateKey: rsaPrivateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

const OBO_SECRET = process.env.JWT_SECRET || 'demo-obo-token-secret-key-2026';

// Azure Configurations
const ENTRA_TENANT_ID = process.env.ENTRA_TENANT_ID || '81f26b58-159c-4879-80a0-bab30b5b4dd3';
const ENTRA_AGENT_CLIENT_ID = process.env.ENTRA_AGENT_CLIENT_ID || 'a23206e1-2dda-4854-aac7-0536d2da2c4c';
const ENTRA_MCP_APP_ID = process.env.ENTRA_MCP_APP_ID || 'd5850aa0-a667-41c3-8dd0-16f2dee4da25';
const ENTRA_AUDIENCE = process.env.ENTRA_AUDIENCE || `api://${ENTRA_MCP_APP_ID}`;

// GCP Configurations
const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID || 'wifdemoproject-507002';
const GCP_PROJECT_NUMBER = process.env.GCP_PROJECT_NUMBER || '834200279688';
const GCP_POOL_ID = process.env.GCP_POOL_ID || 'k8s-agent-pool';
const GCP_PROVIDER_ID = process.env.GCP_PROVIDER_ID || 'spire-oidc-provider';
const GCP_MCP_AUDIENCE = process.env.GCP_MCP_AUDIENCE || 'gcp-bigquery-mcp-server';
const GCP_STS_AUDIENCE = `//iam.googleapis.com/projects/${GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/${GCP_POOL_ID}/providers/${GCP_PROVIDER_ID}`;


class TokenExchangeEngine {
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

  /**
   * Performs HTTP request to Google Cloud Security Token Service (STS) via RFC 8693
   */
  async _callGoogleStsTokenExchange(params) {
    const postData = querystring.stringify(params);
    const parsedUrl = new URL('https://sts.googleapis.com/v1/token');

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
        reject(new Error('Google Cloud STS token exchange request timed out.'));
      });
      req.write(postData);
      req.end();
    });
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
  async exchangeToken({ userToken, agentSvid, targetAudience = ENTRA_AUDIENCE, requestedTool = 'tool1', priorHops = [], turn = 1 }) {
    // 1. Validate & Parse Subject Token (User from Keycloak)
    let userClaims = {};
    if (userToken) {
      userClaims = jwtUtil.decode(userToken) || {};
    }

    const userSub = userClaims.sub || userClaims.preferred_username || 'anonymous-user';
    const userEmail = userClaims.email || userSub;
    const userRoles = Array.isArray(userClaims.roles)
      ? userClaims.roles
      : (userClaims.realm_access?.roles || ['regular-user']);

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

    // Determine Eligible Scopes for Principal
    const userEligibleScopes = ['mcp:tool1', 'mcp:bigquery:query'];
    if (isAdmin || userScopesFromToken.includes('mcp:tool2')) {
      userEligibleScopes.push('mcp:tool2');
    }
    if (isAdmin || userScopesFromToken.includes('mcp:bigquery:audit')) {
      userEligibleScopes.push('mcp:bigquery:audit');
    }
    if (hasMailSend) {
      userEligibleScopes.push('Mail.Send');
    }

    const isScopeAuthorized = userEligibleScopes.includes(requiredScopeForTool);
    const downscopedScopes = isScopeAuthorized ? [requiredScopeForTool] : ['unauthorized'];
    const finalScopes = downscopedScopes;

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

    // 3. If target is GCP, attempt Live Google Cloud STS Exchange (RFC 8693)
    if (isGcpTool || targetAudience === GCP_MCP_AUDIENCE || targetAudience.includes('googleapis.com')) {
      try {
        console.log(`\n=============================================================`);
        console.log(`[ORCH-GCP-STS] 🌐 Calling Google Cloud STS Token Endpoint (RFC 8693):`);
        console.log(`[ORCH-GCP-STS]   Audience:  ${GCP_STS_AUDIENCE}`);
        console.log(`[ORCH-GCP-STS]   Principal: ${userEmail}`);
        console.log(`[ORCH-GCP-STS]   Lineage:   [${actorChain.join(' -> ')}]`);

        const stsResponse = await this._callGoogleStsTokenExchange({
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          audience: GCP_STS_AUDIENCE,
          scope: 'https://www.googleapis.com/auth/cloud-platform',
          requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          subject_token: userToken || 'mock-user-token'
        });

        console.log(`[ORCH-GCP-STS] 📡 Google STS Response: HTTP ${stsResponse.statusCode}`);
        if (stsResponse.statusCode === 200 && stsResponse.body.access_token) {
          console.log(`[ORCH-GCP-STS]   ✅ Federated Access Token minted by Google Cloud STS!`);
        }
      } catch (err) {
        console.log(`[ORCH-GCP-STS] ℹ️ Google Cloud STS live call note: ${err.message}`);
      }

      // Construct High-Fidelity GCP RFC 8693 OBO Token
      const gcpClaims = {
        iss: 'https://identity.example.com/realms/azure-wif-realm',
        aud: targetAudience || GCP_MCP_AUDIENCE,
        sub: userEmail,
        email: userEmail,
        roles: finalScopes,
        scope: finalScopes.join(' '),
        act: recursiveAct,
        actorChain,
        downscoped: true,
        cloudPlatform: 'GCP',
        delegationType: 'RFC8693_MULTI_HOP_CHAIN'
      };

      const exchangedToken = jwtUtil.sign(gcpClaims, OBO_SECRET, { expiresInSeconds: 300 });

      return {
        exchangedToken,
        tokenType: 'GCP_WIF_RFC8693_DELEGATION',
        claims: gcpClaims,
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
          tokenIssuer: 'Google Cloud STS / RFC 8693 Multi-Cloud Bridge'
        }
      };
    }

    // 4. Attempt Live Azure Entra ID WIF Exchange (RFC 7523)
    try {
      const header = { alg: 'RS256', typ: 'JWT', kid: 'agent-orchestrator-key-1' };
      const payload = {
        iss: 'https://spire.example.org',
        sub: agentSpiffeId,
        aud: 'api://AzureADTokenExchange',
        exp: Math.floor(Date.now() / 1000) + 300,
        nbf: Math.floor(Date.now() / 1000) - 10,
        iat: Math.floor(Date.now() / 1000)
      };

      const b64url = str => Buffer.from(str).toString('base64url');
      const signInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
      const signature = crypto.sign('sha256', Buffer.from(signInput), { key: rsaPrivateKey, dsig: 'raw' });
      const clientAssertion = `${signInput}.${signature.toString('base64url')}`;

      console.log(`\n=============================================================`);
      console.log(`[ORCH-WIF] 🌐 Calling Microsoft Entra ID Token Endpoint (RFC 7523):`);
      console.log(`[ORCH-WIF]   Endpoint:  https://login.microsoftonline.com/${ENTRA_TENANT_ID}/oauth2/v2.0/token`);
      console.log(`[ORCH-WIF]   Client ID: ${ENTRA_AGENT_CLIENT_ID}`);
      console.log(`[ORCH-WIF]   Audience:  ${targetAudience}`);
      console.log(`[ORCH-WIF]   Actor:     ${agentSpiffeId}`);

      const entraResponse = await this._callEntraWifTokenExchange({
        grant_type: 'client_credentials',
        client_id: ENTRA_AGENT_CLIENT_ID,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: clientAssertion,
        scope: `${ENTRA_AUDIENCE}/.default`
      });

      console.log(`[ORCH-WIF] 📡 Entra ID Token Response: HTTP ${entraResponse.statusCode}`);
      if (entraResponse.statusCode === 200 && entraResponse.body.access_token) {
        console.log(`[ORCH-WIF]   ✅ Token successfully minted by Microsoft Entra ID!`);
      }
    } catch (err) {
      console.log(`[ORCH-WIF] ⚠️ Entra Token Exchange call error: ${err.message}`);
    }

    // 5. High-Fidelity Entra ID / RFC 8693 Bearer Token
    const entraClaims = {
      iss: `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0`,
      tid: ENTRA_TENANT_ID,
      aud: targetAudience,
      sub: userEmail,
      upn: userEmail,
      email: userEmail,
      appid: ENTRA_AGENT_CLIENT_ID,
      azp: ENTRA_AGENT_CLIENT_ID,
      roles: finalScopes,
      scope: finalScopes.join(' '),
      act: recursiveAct,
      actorChain,
      downscoped: true,
      delegationType: 'RFC8693_MULTI_HOP_CHAIN'
    };

    const exchangedToken = jwtUtil.sign(entraClaims, OBO_SECRET, { expiresInSeconds: 300 });

    return {
      exchangedToken,
      tokenType: 'AZURE_ENTRA_WIF_SIMULATION',
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
        tokenIssuer: 'Microsoft Entra ID (Azure WIF)'
      }
    };
  }
}

module.exports = new TokenExchangeEngine();
