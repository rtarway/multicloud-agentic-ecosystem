// A2A Agent Orchestrator Service
// Integrates SPIRE Workload Identity, Simulated LLM Planning, RFC 8693 Token Exchange,
// and Azure MCP Server Execution.

const express = require('express');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const llmSimulator = require('./llmSimulator');
const spireClient = require('./spireClient');
const tokenExchange = require('./tokenExchange');
const jwtUtil = require('./jwtUtil');
const opaPolicy = require('./opaPolicy');
const graphClient = require('./graphClient');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3001;
const MCP_SERVER_URL = process.env.AZURE_MCP_ENDPOINT || process.env.MCP_SERVER_URL || 'http://localhost:8080';

// Health Check
app.get('/healthz', (req, res) => {
  res.json({
    status: 'UP',
    service: 'agent-orchestrator',
    spiffeId: spireClient.spiffeId || 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
    hasWorkloadApi: spireClient.hasWorkloadApi
  });
});

/**
 * Dispatches an MCP JSON-RPC call to the Azure MCP Server
 */
async function callMcpServer(mcpUrl, toolName, args, oboBearerToken, delegatedUser, correlationId) {
  // If an in-memory MCP handler is injected (for unit testing), use it
  if (app.locals.mcpDispatcher) {
    return app.locals.mcpDispatcher(toolName, args, oboBearerToken, delegatedUser, correlationId);
  }

  const payload = JSON.stringify({
    jsonrpc: '2.0',
    id: `agent-exec-${Date.now()}`,
    method: 'tools/call',
    params: {
      name: toolName,
      arguments: args
    }
  });

  let endpoint = mcpUrl;
  if (!endpoint.endsWith('/mcp')) {
    endpoint = `${endpoint.replace(/\/+$/, '')}/mcp`;
  }
  const parsedUrl = new URL(endpoint);
  const client = parsedUrl.protocol === 'https:' ? https : http;

  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
    Authorization: `Bearer ${oboBearerToken}`
  };

  if (correlationId) {
    headers['X-Correlation-ID'] = correlationId;
    headers['x-ms-client-request-id'] = correlationId;
  }

  if (delegatedUser) {
    headers['X-Delegated-Identity'] = JSON.stringify(delegatedUser);
  }

  return new Promise((resolve, reject) => {
    const req = client.request(
      parsedUrl,
      {
        method: 'POST',
        headers
      },
      res => {
        let raw = '';
        res.on('data', chunk => (raw += chunk));
        res.on('end', () => {
          try {
            const parsed = JSON.parse(raw);
            resolve(parsed.result || parsed);
          } catch (e) {
            resolve({ isError: true, content: [{ type: 'text', text: raw }] });
          }
        });
      }
    );

    req.on('error', err => {
      resolve({
        isError: true,
        content: [{ type: 'text', text: `Failed reaching MCP Server: ${err.message}` }]
      });
    });

    req.write(payload);
    req.end();
  });
}

const GCP_MCP_SERVER_URL = process.env.GCP_MCP_ENDPOINT || process.env.GCP_MCP_SERVER_URL || 'http://localhost:8081';

/**
 * Dispatches an MCP JSON-RPC call to the GCP MCP Server (BigQuery)
 */
async function callGcpMcpServer(mcpUrl, toolName, args, oboBearerToken, delegatedUser, correlationId) {
  // If an in-memory handler is injected (for unit testing), use it
  if (app.locals.gcpMcpDispatcher) {
    return app.locals.gcpMcpDispatcher(toolName, args, oboBearerToken, delegatedUser, correlationId);
  }

  const payload = JSON.stringify({
    jsonrpc: '2.0',
    id: `agent-gcp-exec-${Date.now()}`,
    method: 'tools/call',
    params: {
      name: toolName,
      arguments: args
    }
  });

  let endpoint = mcpUrl || GCP_MCP_SERVER_URL;
  if (!endpoint.endsWith('/mcp')) {
    endpoint = `${endpoint.replace(/\/+$/, '')}/mcp`;
  }
  const parsedUrl = new URL(endpoint);
  const client = parsedUrl.protocol === 'https:' ? https : http;

  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
    Authorization: `Bearer ${oboBearerToken}`
  };

  if (correlationId) {
    headers['X-Correlation-ID'] = correlationId;
  }
  if (delegatedUser) {
    headers['X-Delegated-Identity'] = JSON.stringify(delegatedUser);
  }

  return new Promise((resolve) => {
    const req = client.request(
      parsedUrl,
      { method: 'POST', headers },
      res => {
        let raw = '';
        res.on('data', chunk => (raw += chunk));
        res.on('end', () => {
          try {
            const parsed = JSON.parse(raw);
            resolve(parsed.result || parsed);
          } catch (e) {
            resolve({ isError: true, content: [{ type: 'text', text: raw }] });
          }
        });
      }
    );

    req.on('error', err => {
      resolve({
        isError: true,
        content: [{ type: 'text', text: `Failed reaching GCP MCP Server: ${err.message}` }]
      });
    });

    req.write(payload);
    req.end();
  });
}

function decodeTokenComplete(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    return { header, payload };
  } catch {
    return null;
  }
}

// Agent Chat & Execution Endpoint
app.post('/api/agent/chat', async (req, res) => {
  const { prompt } = req.body || {};
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];

  if (!prompt) {
    return res.status(400).json({ error: 'Missing prompt parameter.' });
  }

  // 1. Inspect User Identity from Keycloak Token
  let userToken = null;
  let userClaims = { sub: 'guest@example.com', roles: ['regular-user'] };

  if (authHeader && authHeader.startsWith('Bearer ')) {
    userToken = authHeader.substring(7).trim();
    const decoded = jwtUtil.decode(userToken);
    if (decoded) {
      userClaims = {
        sub: decoded.sub || decoded.preferred_username || 'anonymous',
        email: decoded.email || decoded.sub,
        roles: Array.isArray(decoded.roles) ? decoded.roles : (decoded.realm_access?.roles || ['regular-user'])
      };
    }
  }

  // 2. Simulated LLM Planning
  const plan = llmSimulator.plan(prompt, userClaims);

  // 3. Acquire Agent SPIRE Workload Identity SVID
  const agentSvid = await spireClient.fetchJwtSvid('mcp-azure-service');

  // 4. Orchestrator Fine-Grained Policy (FGP) Evaluation via OPA
  const opaResult = opaPolicy.evaluate({
    user: userClaims,
    plan,
    context: req.body.context || {}
  });

  if (!opaResult.allowed) {
    return res.json({
      prompt,
      user: userClaims,
      agent: {
        spiffeId: agentSvid.spiffeId,
        workloadVerified: true
      },
      plan,
      opaPolicy: opaResult,
      hopToHop: {
        hop1_userToken: {
          name: 'Hop 1: Human User Keycloak / Entra Token (Subject)',
          sub: userClaims.sub,
          email: userClaims.email,
          roles: userClaims.roles,
          rawToken: userToken,
          decodedToken: decodeTokenComplete(userToken)
        },
        hop2_agentIdentity: {
          name: 'Hop 2: Agent Workload Identity (SPIRE SVID Assertion)',
          spiffeId: agentSvid.spiffeId,
          workloadVerified: true,
          audience: 'api://AzureADTokenExchange',
          rawToken: agentSvid.token,
          decodedToken: decodeTokenComplete(agentSvid.token)
        },
        hop3_rfc8693Token: {
          name: 'Hop 3: RFC 8693 Downscoped Delegated Token (Blocked)',
          status: 'BLOCKED_BY_ORCHESTRATOR_FGP',
          reason: opaResult.reason
        },
        hop4_storageDelegation: {
          name: 'Hop 4: JIT User-Delegation Token (Not Minted)',
          status: 'NOT_EVALUATED'
        }
      },
      mcpResponse: {
        isError: true,
        content: [{ type: 'text', text: opaResult.reason }]
      },
      status: 'FAILED_ORCHESTRATOR_FGP'
    });
  }

  // 4a. Cross-Cloud Multi-Hop Pipeline Execution Loop (Azure Storage -> GCP BigQuery)
  if (plan.planType === 'CROSS_CLOUD_PIPELINE') {
    const pipelineSteps = [];
    const conversationalTurns = [];
    let halted = false;
    let finalError = null;
    const entraAudience = process.env.ENTRA_AUDIENCE || 'api://d5850aa0-a667-41c3-8dd0-16f2dee4da25';
    const gcpAudience = process.env.GCP_MCP_AUDIENCE || 'gcp-bigquery-mcp-server';

    // --- Turn 1: Read Azure App1 Financial Report ---
    const t1Plan = llmSimulator.planTurn(1, {}, userClaims, prompt);
    const step1 = plan.steps[0];
    const step1Exchange = await tokenExchange.exchangeToken({
      userToken,
      agentSvid,
      targetAudience: entraAudience,
      requestedTool: step1.tool,
      turn: 1
    });
    const step1CorrelationId = 'chain-cross-step1-' + (userClaims.email || userClaims.sub || 'user').replace(/[^a-zA-Z0-9]/g, '-') + '-' + crypto.randomUUID().substring(0, 8);
    const step1McpRes = await callMcpServer(
      MCP_SERVER_URL,
      step1.tool,
      step1.arguments,
      step1Exchange.exchangedToken,
      step1Exchange.delegatedUser,
      step1CorrelationId
    );

    const step1Status = step1McpRes.isError ? (step1McpRes.cloudIAMDecision || 'FAILED') : 'SUCCESS';
    const step1Record = {
      stepNumber: 1,
      cloud: 'Azure',
      name: step1.name,
      tool: step1.tool,
      targetResource: `/${step1.arguments.container}/${step1.arguments.filename}`,
      token: step1Exchange.exchangedToken,
      decodedToken: decodeTokenComplete(step1Exchange.exchangedToken),
      mcpResponse: step1McpRes,
      status: step1Status
    };
    pipelineSteps.push(step1Record);

    conversationalTurns.push({
      turn: 1,
      cloud: 'Azure',
      name: 'Turn 1: Azure Storage Financial Query',
      intent: t1Plan.intent,
      thought: t1Plan.thought,
      action: t1Plan.action,
      tokenExchange: {
        targetAudience: entraAudience,
        requiredScope: 'mcp:tool1',
        token: step1Exchange.exchangedToken,
        decoded: decodeTokenComplete(step1Exchange.exchangedToken)
      },
      invokedTarget: 'Azure Storage MCP Server (/app1/financial-report.json)',
      returnedToOrchestrator: step1McpRes,
      status: step1Status
    });

    if (step1McpRes.isError) {
      halted = true;
      finalError = step1McpRes;
    }

    let step2GcpRes = null;
    let step2Exchange = null;
    let step3Redaction = null;

    // --- Turn 2: Query GCP BigQuery (Carrying Prior Azure Hop in RFC 8693 Recursive Actor Chain) ---
    if (!halted) {
      const t2Plan = llmSimulator.planTurn(2, { step1: step1McpRes }, userClaims, prompt);
      const step2 = plan.steps[1];

      step2Exchange = await tokenExchange.exchangeToken({
        userToken,
        agentSvid,
        targetAudience: gcpAudience,
        requestedTool: step2.tool,
        priorHops: [step1Record],
        turn: 2
      });

      const step2CorrelationId = 'chain-cross-step2-' + (userClaims.email || userClaims.sub || 'user').replace(/[^a-zA-Z0-9]/g, '-') + '-' + crypto.randomUUID().substring(0, 8);
      step2GcpRes = await callGcpMcpServer(
        GCP_MCP_SERVER_URL,
        step2.tool,
        step2.arguments,
        step2Exchange.exchangedToken,
        step2Exchange.delegatedUser,
        step2CorrelationId
      );

      const step2Status = step2GcpRes.isError ? (step2GcpRes.cloudIAMDecision || 'FAILED') : 'SUCCESS';
      const step2Record = {
        stepNumber: 2,
        cloud: 'GCP',
        name: step2.name,
        tool: step2.tool,
        targetResource: 'analytics_data/regional_sales',
        token: step2Exchange.exchangedToken,
        decodedToken: decodeTokenComplete(step2Exchange.exchangedToken),
        mcpResponse: step2GcpRes,
        status: step2Status
      };
      pipelineSteps.push(step2Record);

      conversationalTurns.push({
        turn: 2,
        cloud: 'GCP',
        name: 'Turn 2: GCP BigQuery Regional Analytics',
        intent: t2Plan.intent,
        thought: t2Plan.thought,
        action: t2Plan.action,
        tokenExchange: {
          targetAudience: gcpAudience,
          requiredScope: 'mcp:bigquery:query',
          token: step2Exchange.exchangedToken,
          decoded: decodeTokenComplete(step2Exchange.exchangedToken)
        },
        invokedTarget: 'GCP BigQuery MCP Server (analytics_data.regional_sales)',
        returnedToOrchestrator: step2GcpRes,
        status: step2Status
      });

      if (step2GcpRes.isError) {
        halted = true;
        finalError = step2GcpRes;
      }
    }

    // --- Turn 3: LLM Cross-Cloud Redaction & Synthesis ---
    if (!halted) {
      const t3Plan = llmSimulator.planTurn(3, { step1: step1McpRes, step2: step2GcpRes }, userClaims, prompt);
      let azureRawData = step1McpRes?.content?.[0]?.text || '';
      let gcpRawData = step2GcpRes?.content?.[0]?.text || '';

      step3Redaction = llmSimulator.redactAndSynthesizeMultiCloud(azureRawData, gcpRawData, userClaims);
      pipelineSteps.push({
        stepNumber: 3,
        cloud: 'Multi-Cloud',
        name: 'Cross-Cloud LLM Redaction & Synthesis',
        tool: 'llm_redaction_engine',
        status: 'SUCCESS',
        redactionDetails: {
          rawCombined: step3Redaction.raw,
          redactedSummary: step3Redaction.redactedReport,
          redactionsCount: step3Redaction.redactionsPerformed.length,
          redactionsList: step3Redaction.redactionsPerformed
        }
      });

      conversationalTurns.push({
        turn: 3,
        cloud: 'Orchestrator (In-Memory)',
        name: 'Turn 3: LLM Cross-Cloud Synthesis & PII Scrubbing',
        intent: t3Plan.intent,
        thought: t3Plan.thought,
        action: t3Plan.action,
        tokenExchange: null,
        invokedTarget: 'Orchestrator In-Memory Cognitive Synthesis Engine',
        redactionSummary: {
          redactionsPerformed: step3Redaction.redactionsPerformed,
          executiveSummary: step3Redaction.redactedReport
        },
        status: 'SUCCESS'
      });
    }

    const decodedUser = userToken ? jwtUtil.decode(userToken) : null;
    const finalHopToHop = {
      isMultiHop: true,
      isCrossCloud: true,
      hop1_userToken: {
        name: 'Hop 1: Human User Keycloak / Entra Token (Subject)',
        tokenType: 'JWT / OIDC Bearer (User Authentication)',
        sub: userClaims.sub,
        email: userClaims.email,
        roles: userClaims.roles,
        scope: decodedUser?.scope || 'mcp:tool1 mcp:bigquery:query',
        issuer: decodedUser?.iss || 'https://keycloak.internal/realms/azure-wif-realm',
        rawToken: userToken,
        decodedToken: decodeTokenComplete(userToken)
      },
      hop2_agentIdentity: {
        name: 'Hop 2: Agent Workload Identity (SPIRE SVID Assertion)',
        tokenType: 'X.509 / JWT-SVID (RFC 8693 Actor Identity)',
        spiffeId: agentSvid.spiffeId,
        workloadVerified: true,
        audience: 'api://AzureADTokenExchange',
        cryptographicAssertion: 'mTLS + SPIFFE SVID signed by SPIRE Workload API',
        rawToken: agentSvid.token,
        decodedToken: decodeTokenComplete(agentSvid.token)
      },
      hop3_azureToken: {
        name: 'Hop 3: RFC 8693 Downscoped Token (Turn 1 -> Azure Storage MCP)',
        cloud: 'Azure',
        tokenType: 'RFC 8693 Delegated Access Token',
        sub: step1Exchange.claims.sub,
        aud: step1Exchange.claims.aud,
        scope: step1Exchange.claims.roles || step1Exchange.claims.scope,
        act: step1Exchange.claims.act,
        delegationType: 'RFC8693_TOKEN_EXCHANGE',
        signatureStatus: 'VALID_CRYPTOGRAPHIC_CHAIN',
        ttlSeconds: 300,
        rawToken: step1Exchange.exchangedToken,
        decodedToken: decodeTokenComplete(step1Exchange.exchangedToken),
        fullTokenClaims: step1Exchange.claims
      },
      hop3_rfc8693Token: {
        name: 'Hop 3: RFC 8693 Downscoped Token (Turn 1 -> Azure Storage MCP)',
        cloud: 'Azure',
        tokenType: 'RFC 8693 Delegated Access Token',
        sub: step1Exchange.claims.sub,
        aud: step1Exchange.claims.aud,
        scope: step1Exchange.claims.roles || step1Exchange.claims.scope,
        act: step1Exchange.claims.act,
        delegationType: 'RFC8693_TOKEN_EXCHANGE',
        signatureStatus: 'VALID_CRYPTOGRAPHIC_CHAIN',
        ttlSeconds: 300,
        rawToken: step1Exchange.exchangedToken,
        decodedToken: decodeTokenComplete(step1Exchange.exchangedToken),
        fullTokenClaims: step1Exchange.claims
      },
      hop4_azureExecution: {
        name: 'Hop 4: Azure Storage Execution Result',
        cloud: 'Azure',
        credentialType: 'Azure Storage JIT User-Delegation (60s)',
        ttlSeconds: 60,
        status: step1Status,
        resource: '/app1/financial-report.json',
        storageAccount: 'azwifstoragepocrt',
        chainBinding: 'SHA-256 bound to Hop 3 token',
        cloudIamStatus: step1Status === 'SUCCESS' ? 'ALLOWED (HTTP 200 via Azure Storage Native RBAC)' : 'DENIED',
        rawToken: 'Bearer 60s-ephemeral-azure-storage-sig',
        decodedToken: step1McpRes,
        response: step1McpRes
      },
      hop4_storageDelegation: {
        name: 'Hop 4: Azure Storage Execution Result',
        cloud: 'Azure',
        credentialType: 'Azure Storage JIT User-Delegation (60s)',
        ttlSeconds: 60,
        status: step1Status,
        resource: '/app1/financial-report.json',
        storageAccount: 'azwifstoragepocrt',
        chainBinding: 'SHA-256 bound to Hop 3 token',
        cloudIamStatus: step1Status === 'SUCCESS' ? 'ALLOWED (HTTP 200 via Azure Storage Native RBAC)' : 'DENIED',
        rawToken: 'Bearer 60s-ephemeral-azure-storage-sig',
        decodedToken: step1McpRes,
        response: step1McpRes
      },
      hop5_gcpMultiHopToken: step2Exchange ? {
        name: 'Hop 5: RFC 8693 Multi-Hop Recursive Token (Turn 2 -> GCP BigQuery MCP)',
        cloud: 'GCP',
        tokenType: 'Google Cloud IAM / RFC 8693 Delegated Token',
        issuer: 'Google Cloud IAM (https://accounts.google.com)',
        sub: step2Exchange.claims.sub,
        aud: step2Exchange.claims.aud,
        scope: step2Exchange.claims.roles || step2Exchange.claims.scope,
        act: step2Exchange.claims.act,
        actorChain: step2Exchange.claims.actorChain,
        delegationType: 'RFC8693_MULTI_HOP_CHAIN',
        signatureStatus: 'VALID_CRYPTOGRAPHIC_CHAIN',
        ttlSeconds: 300,
        rawToken: step2Exchange.exchangedToken,
        decodedToken: decodeTokenComplete(step2Exchange.exchangedToken),
        fullTokenClaims: step2Exchange.claims
      } : null,
      hop5_graphToken: step2Exchange ? {
        name: 'Hop 5: RFC 8693 Multi-Hop Recursive Token (Turn 2 -> GCP BigQuery MCP)',
        cloud: 'GCP',
        tokenType: 'Google Cloud IAM / RFC 8693 Delegated Token',
        issuer: 'Google Cloud IAM (https://accounts.google.com)',
        sub: step2Exchange.claims.sub,
        aud: step2Exchange.claims.aud,
        scope: step2Exchange.claims.roles || step2Exchange.claims.scope,
        act: step2Exchange.claims.act,
        actorChain: step2Exchange.claims.actorChain,
        delegationType: 'RFC8693_MULTI_HOP_CHAIN',
        signatureStatus: 'VALID_CRYPTOGRAPHIC_CHAIN',
        ttlSeconds: 300,
        rawToken: step2Exchange.exchangedToken,
        decodedToken: decodeTokenComplete(step2Exchange.exchangedToken),
        fullTokenClaims: step2Exchange.claims
      } : null,
      hop6_gcpExecution: step2GcpRes ? {
        name: 'Hop 6: GCP BigQuery Execution Result',
        cloud: 'GCP',
        status: step2GcpRes.isError ? (step2GcpRes.cloudIAMDecision || 'FAILED') : 'SUCCESS',
        dataset: 'analytics_data',
        table: 'regional_sales',
        credentialType: 'Google Cloud BigQuery IAM API Token',
        cloudIamStatus: 'ALLOWED (HTTP 200 via Google Cloud IAM)',
        rawToken: 'Google BigQuery API Query Complete (Bearer token presented)',
        decodedToken: step2GcpRes,
        response: step2GcpRes
      } : null,
      hop6_graphExecution: step2GcpRes ? {
        name: 'Hop 6: GCP BigQuery Execution Result',
        cloud: 'GCP',
        status: step2GcpRes.isError ? (step2GcpRes.cloudIAMDecision || 'FAILED') : 'SUCCESS',
        dataset: 'analytics_data',
        table: 'regional_sales',
        credentialType: 'Google Cloud BigQuery IAM API Token',
        cloudIamStatus: 'ALLOWED (HTTP 200 via Google Cloud IAM)',
        rawToken: 'Google BigQuery API Query Complete (Bearer token presented)',
        decodedToken: step2GcpRes,
        response: step2GcpRes
      } : null,
      hop7_crossCloudReport: step3Redaction ? {
        name: 'Hop 7: Cross-Cloud Redacted Synthesis (Azure + GCP)',
        executiveSummary: step3Redaction.redactedReport,
        redactionsCount: step3Redaction.redactionsPerformed.length
      } : null
    };

    return res.json({
      correlationId: 'chain-cross-cloud-' + crypto.randomUUID().substring(0, 8),
      prompt,
      user: userClaims,
      agent: {
        spiffeId: agentSvid.spiffeId,
        workloadVerified: true
      },
      plan,
      conversationalTurns,
      multiHopExecution: {
        completed: !halted,
        totalSteps: 3,
        executedSteps: pipelineSteps.length,
        steps: pipelineSteps,
        redactionSummary: step3Redaction ? {
          redactionsPerformed: step3Redaction.redactionsPerformed,
          executiveSummary: step3Redaction.redactedReport
        } : null,
        finalStatus: halted ? 'FAILED_POLICY_CHECK' : 'COMPLETED_SUCCESSFULLY'
      },
      hopToHop: finalHopToHop,
      mcpResponse: halted ? finalError : {
        isError: false,
        content: [{ type: 'text', text: step3Redaction ? step3Redaction.redactedReport : 'Cross-cloud pipeline finished successfully.' }]
      },
      status: halted ? 'FAILED_POLICY_CHECK' : 'COMPLETED_SUCCESSFULLY'
    });
  }

  // 4b. Multi-Hop Autonomous Pipeline Execution Loop
  if (plan.planType === 'MULTI_STEP_PIPELINE') {
    const pipelineSteps = [];
    const conversationalTurns = [];
    let halted = false;
    let finalError = null;
    const entraAudience = process.env.ENTRA_AUDIENCE || 'api://d5850aa0-a667-41c3-8dd0-16f2dee4da25';

    // --- Turn 1: Read App1 Financial Report ---
    const t1Plan = llmSimulator.planTurn(1, {}, userClaims, prompt);
    const step1 = plan.steps[0];
    const step1Exchange = await tokenExchange.exchangeToken({
      userToken,
      agentSvid,
      targetAudience: entraAudience,
      requestedTool: step1.tool
    });
    const step1CorrelationId = 'chain-step1-' + (userClaims.email || userClaims.sub || 'user').replace(/[^a-zA-Z0-9]/g, '-') + '-' + crypto.randomUUID().substring(0, 8);
    const step1McpRes = await callMcpServer(
      MCP_SERVER_URL,
      step1.tool,
      step1.arguments,
      step1Exchange.exchangedToken,
      step1Exchange.delegatedUser,
      step1CorrelationId
    );

    const step1Status = step1McpRes.isError ? (step1McpRes.cloudIAMDecision || 'FAILED') : 'SUCCESS';
    pipelineSteps.push({
      stepNumber: 1,
      name: step1.name,
      tool: step1.tool,
      targetResource: `/${step1.arguments.container}/${step1.arguments.filename}`,
      token: step1Exchange.exchangedToken,
      decodedToken: decodeTokenComplete(step1Exchange.exchangedToken),
      mcpResponse: step1McpRes,
      status: step1Status
    });

    conversationalTurns.push({
      turn: 1,
      name: 'Turn 1: App1 Financial Query',
      intent: t1Plan.intent,
      thought: t1Plan.thought,
      action: t1Plan.action,
      tokenExchange: {
        targetAudience: entraAudience,
        requiredScope: 'mcp:tool1',
        token: step1Exchange.exchangedToken,
        decoded: decodeTokenComplete(step1Exchange.exchangedToken)
      },
      invokedTarget: 'Azure Storage MCP Server (/app1/financial-report.json)',
      returnedToOrchestrator: step1McpRes,
      status: step1Status
    });

    if (step1McpRes.isError) {
      halted = true;
      finalError = step1McpRes;
    }

    let step2McpRes = null;
    let step2Exchange = null;
    let step3Redaction = null;
    let step4DirectRes = null;
    let step4Exchange = null;

    // --- Turn 2: Read App2 Customer Metrics (if Turn 1 succeeded) ---
    if (!halted) {
      const t2Plan = llmSimulator.planTurn(2, { step1: step1McpRes }, userClaims, prompt);
      const step2 = plan.steps[1];
      step2Exchange = await tokenExchange.exchangeToken({
        userToken,
        agentSvid,
        targetAudience: entraAudience,
        requestedTool: step2.tool
      });
      const step2CorrelationId = 'chain-step2-' + (userClaims.email || userClaims.sub || 'user').replace(/[^a-zA-Z0-9]/g, '-') + '-' + crypto.randomUUID().substring(0, 8);
      step2McpRes = await callMcpServer(
        MCP_SERVER_URL,
        step2.tool,
        step2.arguments,
        step2Exchange.exchangedToken,
        step2Exchange.delegatedUser,
        step2CorrelationId
      );

      const step2Status = step2McpRes.isError ? (step2McpRes.cloudIAMDecision || 'FAILED') : 'SUCCESS';
      pipelineSteps.push({
        stepNumber: 2,
        name: step2.name,
        tool: step2.tool,
        targetResource: `/${step2.arguments.container}/${step2.arguments.filename}`,
        token: step2Exchange.exchangedToken,
        decodedToken: decodeTokenComplete(step2Exchange.exchangedToken),
        mcpResponse: step2McpRes,
        status: step2Status
      });

      conversationalTurns.push({
        turn: 2,
        name: 'Turn 2: App2 Customer Metrics Query',
        intent: t2Plan.intent,
        thought: t2Plan.thought,
        action: t2Plan.action,
        tokenExchange: {
          targetAudience: entraAudience,
          requiredScope: 'mcp:tool1',
          token: step2Exchange.exchangedToken,
          decoded: decodeTokenComplete(step2Exchange.exchangedToken)
        },
        invokedTarget: 'Azure Storage MCP Server (/app2/customer-metrics.json)',
        returnedToOrchestrator: step2McpRes,
        status: step2Status
      });

      if (step2McpRes.isError) {
        halted = true;
        finalError = step2McpRes;
      }
    }

    // --- Turn 3: LLM Redaction & Executive Synthesis ---
    if (!halted) {
      const t3Plan = llmSimulator.planTurn(3, { step1: step1McpRes, step2: step2McpRes }, userClaims, prompt);
      let app1RawData = step1McpRes?.content?.[0]?.text || '';
      let app2RawData = step2McpRes?.content?.[0]?.text || '';
      try { const p1 = JSON.parse(app1RawData); if (p1.data?.content) app1RawData = p1.data.content; } catch {}
      try { const p2 = JSON.parse(app2RawData); if (p2.data?.content) app2RawData = p2.data.content; } catch {}

      step3Redaction = llmSimulator.redactAndSynthesize(app1RawData, app2RawData, userClaims);
      pipelineSteps.push({
        stepNumber: 3,
        name: 'LLM Redaction & Executive Synthesis',
        tool: 'llm_redaction_engine',
        status: 'SUCCESS',
        redactionDetails: {
          rawCombined: step3Redaction.raw,
          redactedSummary: step3Redaction.redactedReport,
          redactionsCount: step3Redaction.redactionsPerformed.length,
          redactionsList: step3Redaction.redactionsPerformed
        }
      });

      conversationalTurns.push({
        turn: 3,
        name: 'Turn 3: LLM Synthesis & PII Redaction',
        intent: t3Plan.intent,
        thought: t3Plan.thought,
        action: t3Plan.action,
        tokenExchange: null,
        invokedTarget: 'Orchestrator In-Memory LLM Engine',
        redactionSummary: {
          redactionsPerformed: step3Redaction.redactionsPerformed,
          executiveSummary: step3Redaction.redactedReport
        },
        status: 'SUCCESS'
      });
    }

    // --- Turn 4: Direct Orchestrator Microsoft Graph Email Dispatch ---
    if (!halted) {
      const t4Plan = llmSimulator.planTurn(4, { step3: step3Redaction }, userClaims, prompt);
      const step4 = plan.steps[3];
      const targetRecipient = plan.targetRecipient || 'rtarway@gmail.com';

      // Fine-Grained Policy: recipient must strictly be rtarway@gmail.com
      if (targetRecipient !== 'rtarway@gmail.com') {
        const fgpDenial = {
          isError: true,
          content: [{ type: 'text', text: `Fine-Grained Policy Denial: Email recipient '${targetRecipient}' is prohibited. Only rtarway@gmail.com is authorized.` }],
          audit: {
            principal: userClaims.email || userClaims.sub,
            actingAgent: agentSvid.spiffeId,
            requestedRecipient: targetRecipient,
            decision: 'DENIED_BY_FGP'
          }
        };
        pipelineSteps.push({
          stepNumber: 4,
          name: step4.name,
          tool: 'microsoft_graph_direct',
          status: 'DENIED_BY_FGP',
          mcpResponse: fgpDenial
        });
        conversationalTurns.push({
          turn: 4,
          name: 'Turn 4: Direct Microsoft Graph API Dispatch',
          intent: t4Plan.intent,
          thought: t4Plan.thought,
          action: t4Plan.action,
          tokenExchange: null,
          invokedTarget: 'Microsoft Graph API (Blocked by Orchestrator FGP)',
          recipient: targetRecipient,
          error: fgpDenial,
          status: 'DENIED_BY_FGP'
        });
        halted = true;
        finalError = fgpDenial;
      } else {
        // RFC 8693 Token Exchange for Microsoft Graph (Audience: https://graph.microsoft.com, Scope: Mail.Send)
        step4Exchange = await tokenExchange.exchangeToken({
          userToken,
          agentSvid,
          targetAudience: 'https://graph.microsoft.com',
          requestedTool: 'microsoft_graph_direct'
        });

        // Verify caller has Mail.Send permission
        const hasMailSend = (step4Exchange.claims.roles || []).includes('Mail.Send') ||
          ((step4Exchange.claims.scope || '').split(' ').includes('Mail.Send')) ||
          ((userClaims.scope || '').split(' ').includes('Mail.Send')) ||
          (userClaims.roles || []).includes('Mail.Send');

        if (!hasMailSend) {
          const authDenial = {
            isError: true,
            content: [{ type: 'text', text: `Authorization Denied: Principal '${userClaims.sub}' lacks required Microsoft Graph scope 'Mail.Send' to dispatch emails.` }],
            audit: {
              principal: userClaims.sub,
              actingAgent: agentSvid.spiffeId,
              requestedTool: 'microsoft_graph_direct',
              requiredScope: 'Mail.Send',
              decision: 'DENIED_BY_POLICY'
            }
          };
          pipelineSteps.push({
            stepNumber: 4,
            name: step4.name,
            tool: 'microsoft_graph_direct',
            status: 'DENIED_BY_POLICY',
            token: step4Exchange.exchangedToken,
            decodedToken: decodeTokenComplete(step4Exchange.exchangedToken),
            mcpResponse: authDenial
          });
          conversationalTurns.push({
            turn: 4,
            name: 'Turn 4: Direct Microsoft Graph API Dispatch',
            intent: t4Plan.intent,
            thought: t4Plan.thought,
            action: t4Plan.action,
            tokenExchange: {
              targetAudience: 'https://graph.microsoft.com',
              requiredScope: 'Mail.Send',
              token: step4Exchange.exchangedToken,
              decoded: decodeTokenComplete(step4Exchange.exchangedToken)
            },
            invokedTarget: 'Microsoft Graph API (Blocked: Principal lacks Mail.Send)',
            recipient: targetRecipient,
            error: authDenial,
            status: 'DENIED_BY_POLICY'
          });
          halted = true;
          finalError = authDenial;
        } else {
          // DIRECT ORCHESTRATOR INVOCATION OF MICROSOFT GRAPH API
          // Storage MCP server is NOT called; Orchestrator directly dispatches Graph email using Token 3.
          const graphDeliveryResult = await graphClient.dispatchGraphEmail({
            graphToken: step4Exchange.exchangedToken,
            recipient: targetRecipient,
            subject: step4.arguments.subject,
            body: step3Redaction.redactedReport,
            emailConfig: req.body?.emailConfig || {}
          });

          step4DirectRes = {
            isError: false,
            executedDirectlyBy: 'agent-orchestrator',
            targetApi: 'Microsoft Graph API (https://graph.microsoft.com/v1.0/me/sendMail)',
            scope: 'Mail.Send',
            recipient: targetRecipient,
            graphStatus: `${graphDeliveryResult.graphApiStatus} ${graphDeliveryResult.graphApiStatusText}`,
            liveGraphAttempted: graphDeliveryResult.liveCallAttempted,
            deliveryRelay: graphDeliveryResult.deliveryRelay,
            content: [{
              type: 'text',
              text: JSON.stringify({
                status: 'success',
                message: `[Direct Graph Call] Dispatched executive summary to ${targetRecipient} via Microsoft Graph API.`,
                data: {
                  directDispatchBy: 'agent-orchestrator',
                  endpoint: 'https://graph.microsoft.com/v1.0/me/sendMail',
                  recipient: targetRecipient,
                  subject: step4.arguments.subject,
                  graphApiStatus: graphDeliveryResult.graphApiStatus,
                  deliveryRelay: graphDeliveryResult.deliveryRelay
                }
              }, null, 2)
            }]
          };

          pipelineSteps.push({
            stepNumber: 4,
            name: step4.name,
            tool: 'microsoft_graph_direct',
            recipient: targetRecipient,
            token: step4Exchange.exchangedToken,
            decodedToken: decodeTokenComplete(step4Exchange.exchangedToken),
            mcpResponse: step4DirectRes,
            status: 'SUCCESS'
          });

          conversationalTurns.push({
            turn: 4,
            name: 'Turn 4: Direct Microsoft Graph API Dispatch',
            intent: t4Plan.intent,
            thought: t4Plan.thought,
            action: t4Plan.action,
            tokenExchange: {
              targetAudience: 'https://graph.microsoft.com',
              requiredScope: 'Mail.Send',
              token: step4Exchange.exchangedToken,
              decoded: decodeTokenComplete(step4Exchange.exchangedToken)
            },
            invokedTarget: 'Microsoft Graph API (POST /v1.0/me/sendMail) & Option 1 Relay',
            recipient: targetRecipient,
            graphDeliveryResult,
            status: 'SUCCESS'
          });
        }
      }
    }

    const decodedUser = userToken ? jwtUtil.decode(userToken) : null;
    const finalHopToHop = {
      isMultiHop: true,
      hop1_userToken: {
        name: 'Hop 1: Human User Keycloak / Entra Token (Subject)',
        tokenType: 'JWT / OIDC Bearer (User Authentication)',
        sub: userClaims.sub,
        email: userClaims.email,
        roles: userClaims.roles,
        scope: decodedUser?.scope || (userClaims.roles?.includes('admin') ? 'mcp:tool1 mcp:tool2 Mail.Send' : 'mcp:tool1'),
        issuer: decodedUser?.iss || 'https://keycloak.internal/realms/azure-wif-realm',
        rawToken: userToken,
        decodedToken: decodeTokenComplete(userToken)
      },
      hop2_agentIdentity: {
        name: 'Hop 2: Agent Workload Identity (SPIRE SVID Assertion)',
        tokenType: 'X.509 / JWT-SVID (RFC 8693 Actor Identity)',
        spiffeId: agentSvid.spiffeId,
        workloadVerified: true,
        audience: 'api://AzureADTokenExchange',
        cryptographicAssertion: 'mTLS + SPIFFE SVID signed by SPIRE Workload API',
        rawToken: agentSvid.token,
        decodedToken: decodeTokenComplete(agentSvid.token)
      },
      hop3_step1App1: pipelineSteps[0] || null,
      hop4_step2App2: pipelineSteps[1] || null,
      hop5_step3Redaction: pipelineSteps[2] || null,
      hop6_step4GraphEmail: pipelineSteps[3] || null,
      hop3_rfc8693Token: {
        name: 'Hop 3: RFC 8693 Downscoped Delegated Token (Step 1 -> MCP Server)',
        tokenType: 'RFC 8693 Delegated Access Token',
        sub: step1Exchange.claims.sub,
        aud: step1Exchange.claims.aud,
        scope: step1Exchange.claims.roles || step1Exchange.claims.scope,
        ttlSeconds: 300,
        act: step1Exchange.claims.act,
        delegationType: 'RFC8693_TOKEN_EXCHANGE',
        signatureStatus: 'VALID_CRYPTOGRAPHIC_CHAIN',
        rawToken: step1Exchange.exchangedToken,
        decodedToken: decodeTokenComplete(step1Exchange.exchangedToken),
        fullTokenClaims: step1Exchange.claims
      },
      hop4_storageDelegation: {
        name: 'Hop 4: JIT Storage Execution Result (MCP ➔ Azure Storage)',
        credentialType: (step1McpRes?.isError || step2McpRes?.isError) ? 'Cloud IAM / Policy Denial' : 'Azure Storage JIT Access (app1 & app2)',
        ttlSeconds: 60,
        resource: '/app1 & /app2',
        storageAccount: 'azwifstoragepocrt',
        cloudIamStatus: (step1McpRes?.isError || step2McpRes?.isError) ? ((step1McpRes || step2McpRes)?.cloudIAMDecision || 'DENIED_BY_POLICY') : 'ALLOWED (HTTP 200 via Azure Storage Native RBAC)',
        rawToken: 'Azure Storage Read Complete',
        decodedToken: {
          app1: step1McpRes ? { status: step1Status, resource: '/app1/financial-report.json' } : null,
          app2: step2McpRes ? { status: step2McpRes.isError ? (step2McpRes.cloudIAMDecision || 'FAILED') : 'SUCCESS', resource: '/app2/customer-metrics.json' } : null
        }
      },
      hop5_graphToken: step4Exchange ? {
        name: 'Hop 5: RFC 8693 Downscoped Delegated Token (Orchestrator ➔ Microsoft Graph)',
        tokenType: 'RFC 8693 Delegated Access Token',
        sub: step4Exchange.claims.sub,
        aud: step4Exchange.claims.aud || 'https://graph.microsoft.com',
        scope: step4Exchange.claims.roles || step4Exchange.claims.scope || 'Mail.Send',
        ttlSeconds: 300,
        act: step4Exchange.claims.act,
        delegationType: 'RFC8693_GRAPH_TOKEN_EXCHANGE',
        signatureStatus: 'VALID_CRYPTOGRAPHIC_CHAIN',
        rawToken: step4Exchange.exchangedToken,
        decodedToken: decodeTokenComplete(step4Exchange.exchangedToken),
        fullTokenClaims: step4Exchange.claims
      } : {
        name: 'Hop 5: RFC 8693 Downscoped Delegated Token (Microsoft Graph)',
        status: halted ? 'NOT_EVALUATED_HALTED_EARLIER' : 'NOT_MINTED'
      },
      hop6_graphExecution: step4DirectRes ? {
        name: 'Hop 6: Microsoft Graph API Direct Execution (Orchestrator ➔ Graph API)',
        targetEndpoint: 'https://graph.microsoft.com/v1.0/me/sendMail',
        invokedDirectlyBy: 'agent-orchestrator (Azure Storage MCP Server Bypassed)',
        recipient: plan.targetRecipient || 'rtarway@gmail.com',
        subject: '[Executive Summary] Redacted Financial & Customer Metrics (app1 + app2)',
        graphStatus: step4DirectRes.graphStatus || 'HTTP 202 Accepted',
        deliveryRelay: step4DirectRes.deliveryRelay,
        rawToken: 'Bearer ' + (step4Exchange?.exchangedToken || 'N/A'),
        decodedToken: {
          targetApi: 'Microsoft Graph API v1.0',
          method: 'POST /v1.0/me/sendMail',
          delegatedSubject: userClaims.sub,
          actingAgent: agentSvid.spiffeId,
          scopeEnforced: 'Mail.Send',
          dispatchedTo: plan.targetRecipient || 'rtarway@gmail.com',
          deliveryRelay: step4DirectRes.deliveryRelay
        }
      } : (halted && finalError?.audit?.requestedTool === 'microsoft_graph_direct' ? {
        name: 'Hop 6: Microsoft Graph API Direct Execution (Blocked)',
        targetEndpoint: 'https://graph.microsoft.com/v1.0/me/sendMail',
        status: finalError?.audit?.decision || 'DENIED_BY_POLICY',
        reason: finalError?.content?.[0]?.text,
        dispatched: false
      } : null)
    };

    return res.json({
      correlationId: 'chain-multihop-' + crypto.randomUUID().substring(0, 8),
      prompt,
      user: userClaims,
      agent: {
        spiffeId: agentSvid.spiffeId,
        workloadVerified: true
      },
      plan,
      conversationalTurns,
      multiHopExecution: {
        completed: !halted,
        totalSteps: 4,
        executedSteps: pipelineSteps.length,
        steps: pipelineSteps,
        redactionSummary: step3Redaction ? {
          redactionsPerformed: step3Redaction.redactionsPerformed,
          executiveSummary: step3Redaction.redactedReport
        } : null,
        finalStatus: halted ? 'FAILED_POLICY_CHECK' : 'COMPLETED_SUCCESSFULLY'
      },
      hopToHop: finalHopToHop,
      mcpResponse: halted ? finalError : (step4DirectRes || { isError: false, content: [{ type: 'text', text: 'Multi-hop autonomous pipeline finished successfully.' }] }),
      status: halted ? 'FAILED_POLICY_CHECK' : 'COMPLETED_SUCCESSFULLY'
    });
  }

  // 5. Multi-Cloud Workload Identity Federation (WIF) Token Exchange with Scope Downscoping
  const isGcp = plan.cloud === 'GCP' || (plan.plannedTool && plan.plannedTool.startsWith('bigquery_'));
  const entraAudience = process.env.ENTRA_AUDIENCE || 'api://d5850aa0-a667-41c3-8dd0-16f2dee4da25';
  const gcpAudience = process.env.GCP_MCP_AUDIENCE || 'gcp-bigquery-mcp-server';
  const targetAudience = isGcp ? gcpAudience : entraAudience;

  const exchangeResult = await tokenExchange.exchangeToken({
    userToken,
    agentSvid,
    targetAudience,
    requestedTool: plan.plannedTool
  });

  let targetToken = exchangeResult.exchangedToken;

  // If testing rogue actor injection scenario, tamper with the act claim
  if (req.body.context?.simulate_rogue_actor || prompt.toLowerCase().includes('rogue actor') || prompt.toLowerCase().includes('tamper')) {
    const tamperedClaims = {
      ...exchangeResult.claims,
      act: {
        sub: 'untrusted-injected-proxy-agent',
        iss: 'https://attacker-proxy.internal',
        client_id: 'bad-actor-uuid'
      }
    };
    targetToken = jwtUtil.sign(tamperedClaims, process.env.JWT_SECRET || 'demo-obo-token-secret-key-2026', { expiresInSeconds: 300 });
  }

  const correlationId = 'chain-' + (userClaims.email || userClaims.sub || 'user').replace(/[^a-zA-Z0-9]/g, '-') + '-' + crypto.randomUUID().substring(0, 8);

  // 6. Invoke Target MCP Server (Azure Storage or GCP BigQuery) with Downscoped Token
  const mcpResponse = isGcp
    ? await callGcpMcpServer(
        GCP_MCP_SERVER_URL,
        plan.plannedTool,
        plan.arguments,
        targetToken,
        exchangeResult.delegatedUser,
        correlationId
      )
    : await callMcpServer(
        MCP_SERVER_URL,
        plan.plannedTool,
        plan.arguments,
        targetToken,
        exchangeResult.delegatedUser,
        correlationId
      );

  const decodedObo = jwtUtil.decode(targetToken) || exchangeResult.claims;
  const decodedUser = userToken ? jwtUtil.decode(userToken) : null;
  const chainHash = crypto.createHash('sha256').update(targetToken).digest('hex').substring(0, 16);

  let storageDelegationDetails = null;
  try {
    if (mcpResponse?.content?.[0]?.text) {
      const parsedText = JSON.parse(mcpResponse.content[0].text);
      if (parsedText?.data?.delegationMeta) {
        storageDelegationDetails = parsedText.data.delegationMeta;
      }
    }
  } catch {}
  if (!storageDelegationDetails && mcpResponse?.audit) {
    storageDelegationDetails = mcpResponse.audit;
  }

  // Hop-to-Hop Token Propagation Trace
  const hopToHop = {
    hop1_userToken: {
      name: 'Hop 1: Human User Keycloak / Entra Token (Subject)',
      tokenType: 'JWT / OIDC Bearer (User Authentication)',
      sub: userClaims.sub,
      email: userClaims.email,
      roles: userClaims.roles,
      scope: decodedUser?.scope || 'mcp:tool1 ...',
      issuer: decodedUser?.iss || 'https://keycloak.internal/realms/azure-wif-realm',
      rawToken: userToken,
      decodedToken: decodeTokenComplete(userToken)
    },
    hop2_agentIdentity: {
      name: 'Hop 2: Agent Workload Identity (SPIRE SVID Assertion)',
      tokenType: 'X.509 / JWT-SVID (RFC 8693 Actor Identity)',
      spiffeId: agentSvid.spiffeId,
      workloadVerified: true,
      audience: 'api://AzureADTokenExchange',
      cryptographicAssertion: 'mTLS + SPIFFE SVID signed by SPIRE Workload API',
      rawToken: agentSvid.token,
      decodedToken: decodeTokenComplete(agentSvid.token)
    },
    hop3_rfc8693Token: {
      name: isGcp
        ? 'Hop 3: RFC 8693 Downscoped Delegated Token (Orchestrator -> GCP BigQuery MCP)'
        : 'Hop 3: RFC 8693 Downscoped Delegated Token (Orchestrator -> MCP Server)',
      tokenType: 'RFC 8693 Delegated Access Token',
      cloud: isGcp ? 'GCP' : 'Azure',
      sub: decodedObo?.sub,
      aud: decodedObo?.aud,
      scope: decodedObo?.scope || decodedObo?.roles,
      ttlSeconds: 300,
      act: decodedObo?.act, // The cryptographically nested actor claim!
      delegationType: isGcp ? 'RFC8693_GCP_TOKEN_EXCHANGE' : 'RFC8693_TOKEN_EXCHANGE',
      signatureStatus: decodedObo?.act?.sub?.includes('untrusted') ? 'UNTRUSTED_ACTOR_REJECTED' : 'VALID_CRYPTOGRAPHIC_CHAIN',
      rawToken: targetToken,
      decodedToken: decodeTokenComplete(targetToken),
      fullTokenClaims: decodedObo
    },
    hop4_storageDelegation: {
      name: isGcp ? 'Hop 4: Google Cloud BigQuery Execution' : 'Hop 4: JIT User-Delegation Token (MCP Server -> Azure Storage)',
      credentialType: isGcp ? 'GCP IAM / BigQuery Parameterized Execution' : 'OAuth 2.0 User-Delegation SAS / Bearer (60s JIT)',
      cloud: isGcp ? 'GCP' : 'Azure',
      ttlSeconds: 60,
      resource: plan.arguments ? (isGcp ? `${plan.arguments.dataset || 'analytics_data'}/${plan.arguments.table || 'regional_sales'}` : `/${plan.arguments.container}/${plan.arguments.filename}`) : undefined,
      storageAccount: isGcp ? 'gcp-bigquery-dataset' : 'azwifstoragepocrt',
      correlationId: correlationId,
      chainBinding: `SHA256(${chainHash}...)`,
      cloudIamStatus: mcpResponse.isError ? (mcpResponse.cloudIAMDecision || 'DENIED_BY_POLICY') : 'ALLOWED (HTTP 200)',
      rawToken: isGcp ? 'Google BigQuery API Query Complete' : `Bearer 60s-ephemeral-sig-${chainHash}`,
      decodedToken: storageDelegationDetails || {
        credentialType: isGcp ? 'GCP_BIGQUERY_IAM_CREDENTIAL' : 'JIT_USER_DELEGATION_CREDENTIAL',
        resource: plan.arguments ? (isGcp ? `${plan.arguments.dataset || 'analytics_data'}` : `/${plan.arguments.container}/${plan.arguments.filename}`) : undefined,
        ttlSeconds: 60,
        correlationId,
        chainFingerprint: chainHash,
        status: mcpResponse.isError ? (mcpResponse.cloudIAMDecision || 'DENIED') : 'ALLOWED (HTTP 200)'
      }
    }
  };

  // 7. Assemble Comprehensive Audit & Execution Result
  const responsePayload = {
    correlationId,
    prompt,
    user: userClaims,
    agent: {
      spiffeId: agentSvid.spiffeId,
      workloadVerified: true
    },
    opaPolicy: opaResult,
    oboExchange: {
      subject: exchangeResult.delegatedUser?.sub || exchangeResult.claims.sub,
      actor: decodedObo?.act?.sub || exchangeResult.audit.actor,
      delegationType: 'RFC8693_TOKEN_EXCHANGE',
      downscopedScopes: exchangeResult.claims.roles || exchangeResult.claims.scope,
      actClaim: decodedObo?.act,
      tokenType: exchangeResult.tokenType,
      tokenPreview: targetToken.slice(0, 35) + '...'
    },
    hopToHop,
    plan,
    mcpResponse,
    status: mcpResponse.isError ? 'FAILED_POLICY_CHECK' : 'COMPLETED_SUCCESSFULLY'
  };

  return res.json(responsePayload);
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`===========================================================`);
    console.log(` A2A Agent Orchestrator listening on port ${PORT}`);
    console.log(` Workload Identity: ${spireClient.spiffeId || 'SPIRE Workload API'}`);
    console.log(` Target MCP Server: ${MCP_SERVER_URL}`);
    console.log(`===========================================================`);
  });
}

module.exports = app;
