// GCP Low-Code Declarative MCP Server (July 2026 Protocol Version)
// Implements Model Context Protocol for Google Cloud Platform (BigQuery)
// Supports RFC 8693 Multi-Hop Recursive Actor Chain Verification

const express = require('express');
const DeclarativeEngine = require('./declarativeEngine');
const { verifyGcpOboToken } = require('./auth');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8081;
const PROTOCOL_VERSION = process.env.MCP_PROTOCOL_VERSION || '2026-07-15';

const engine = new DeclarativeEngine();

// Health probe for Cloud Run, GKE, and local Kubernetes
app.get('/healthz', (req, res) => {
  res.json({
    status: 'UP',
    platform: 'Google Cloud Run / GKE Container',
    cloud: 'Google Cloud Platform (GCP)',
    protocolVersion: PROTOCOL_VERSION,
    toolsRegistered: engine.listTools().length
  });
});

// MCP JSON-RPC 2.0 Endpoint
app.post('/mcp', async (req, res) => {
  const { jsonrpc, id, method, params } = req.body || {};

  if (jsonrpc !== '2.0') {
    return res.status(400).json({
      jsonrpc: '2.0',
      id: id || null,
      error: { code: -32600, message: 'Invalid Request: jsonrpc must be "2.0"' }
    });
  }

  // 1. MCP Protocol Handshake: initialize
  if (method === 'initialize') {
    const clientVersion = params?.protocolVersion || '2024-11-05';
    console.log(`[GCP MCP Server] Initializing MCP connection with client (clientRequested: ${clientVersion}, serverOffering: ${PROTOCOL_VERSION}).`);

    return res.json({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {
          tools: {
            listChanged: false
          }
        },
        serverInfo: {
          name: 'gcp-bigquery-lowcode-mcp-server',
          version: '1.0.0',
          deploymentPlatform: 'Google Cloud Run / Kubernetes'
        }
      }
    });
  }

  // 2. List Declarative Tools: tools/list
  if (method === 'tools/list') {
    const tools = engine.listTools();
    return res.json({
      jsonrpc: '2.0',
      id,
      result: {
        tools
      }
    });
  }

  // 3. Call Tool: tools/call (Requires RFC 8693 Multi-Hop Token)
  if (method === 'tools/call') {
    const { name, arguments: toolArgs } = params || {};
    const authHeader = req.headers['authorization'];
    const delegatedHeader = req.headers['x-delegated-identity'];

    const clientIp = (req.socket && req.socket.remoteAddress) || (req.connection && req.connection.remoteAddress) || 'mock-client';
    console.log(`\n=============================================================`);
    console.log(`[GCP-MCP-RPC] Received 'tools/call' for GCP tool: '${name}'`);
    console.log(`[GCP-MCP-RPC] Client IP: ${clientIp}`);
    console.log(`[GCP-MCP-RPC] Has Authorization Header: ${!!authHeader}`);

    const correlationId = req.headers['x-correlation-id'] || ('chain-' + Date.now());
    console.log(`[GCP-MCP-RPC] Correlation ID: ${correlationId}`);

    const authContext = verifyGcpOboToken(authHeader, delegatedHeader);
    authContext.correlationId = correlationId;

    if (!authContext.authenticated) {
      console.warn(`[GCP-MCP-RPC] ❌ Authentication failed: ${authContext.error}`);
      console.log(`=============================================================\n`);
      return res.json({
        jsonrpc: '2.0',
        id,
        result: {
          isError: true,
          content: [
            {
              type: 'text',
              text: `GCP MCP Authentication Failure: ${authContext.error}`
            }
          ]
        }
      });
    }

    console.log(`[GCP-MCP-RPC] Authenticated Principal: ${authContext.sub} | Actor: ${authContext.act?.sub} | Multi-Hop Chain: [${(authContext.actorChain || []).join(' -> ')}]`);
    const toolResult = await engine.executeTool(name, toolArgs, authContext);
    console.log(`[GCP-MCP-RPC] Completed 'tools/call' -> isError: ${toolResult.isError}`);
    console.log(`=============================================================\n`);

    return res.json({
      jsonrpc: '2.0',
      id,
      result: toolResult
    });
  }

  // Unsupported Method
  return res.json({
    jsonrpc: '2.0',
    id,
    error: {
      code: -32601,
      message: `Method '${method}' not found.`
    }
  });
});

// Helper REST APIs
app.get('/api/tools', (req, res) => {
  res.json({
    protocolVersion: PROTOCOL_VERSION,
    tools: engine.listTools()
  });
});

app.post('/api/tools/:name', async (req, res) => {
  const toolName = req.params.name;
  const authHeader = req.headers['authorization'];
  const authContext = verifyGcpOboToken(authHeader);

  if (!authContext.authenticated) {
    return res.json({
      isError: true,
      content: [{ type: 'text', text: `Authentication Failure: ${authContext.error}` }]
    });
  }

  const result = await engine.executeTool(toolName, req.body, authContext);
  res.json(result);
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`===========================================================`);
    console.log(` GCP BigQuery Low-Code MCP Server listening on ${PORT}`);
    console.log(` Protocol Version: ${PROTOCOL_VERSION} (July 2026)`);
    console.log(` Cloud Platform: Google Cloud Platform (BigQuery)`);
    console.log(`===========================================================`);
  });
}

module.exports = app;
