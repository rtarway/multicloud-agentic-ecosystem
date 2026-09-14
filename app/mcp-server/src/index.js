// Azure MCP Server (July 2026 Protocol Version)
// Low-Code Declarative Architecture for Azure Storage Services

const express = require('express');
const DeclarativeEngine = require('./declarativeEngine');
const { verifyOboToken } = require('./auth');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8080;
const PROTOCOL_VERSION = process.env.MCP_PROTOCOL_VERSION || '2026-07-15';

const engine = new DeclarativeEngine();

// Health probe for Azure App Service & Kubernetes
app.get('/healthz', (req, res) => {
  res.json({
    status: 'UP',
    platform: 'Azure App Service / Container',
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
    console.log(`[MCP Server] Initializing MCP connection with client (clientRequested: ${clientVersion}, serverOffering: ${PROTOCOL_VERSION}).`);

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
          name: 'azure-lowcode-mcp-server',
          version: '1.0.0',
          deploymentPlatform: 'Azure App Service / Container'
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

  // 3. Call Tool: tools/call (Requires OBO Downscoped Token)
  if (method === 'tools/call') {
    const { name, arguments: toolArgs } = params || {};
    const authHeader = req.headers['authorization'];
    const delegatedHeader = req.headers['x-delegated-identity'];

    const clientIp = (req.socket && req.socket.remoteAddress) || (req.connection && req.connection.remoteAddress) || 'mock-client';
    console.log(`\n=============================================================`);
    console.log(`[MCP-RPC] Received 'tools/call' for tool: '${name}'`);
    console.log(`[MCP-RPC] Client IP: ${clientIp}`);
    console.log(`[MCP-RPC] Has Authorization Header: ${!!authHeader}`);
    console.log(`[MCP-RPC] Has X-Delegated-Identity: ${!!delegatedHeader}`);

    const correlationId = req.headers['x-correlation-id'] || req.headers['x-ms-client-request-id'] || ('chain-' + Date.now());
    console.log(`[MCP-RPC] Correlation ID: ${correlationId}`);

    const authContext = verifyOboToken(authHeader, delegatedHeader);
    authContext.correlationId = correlationId;

    if (!authContext.authenticated) {
      console.warn(`[MCP-RPC] ❌ Authentication failed: ${authContext.error}`);
      console.log(`=============================================================\n`);
      // Return MCP tool error maintaining MCP specification
      return res.json({
        jsonrpc: '2.0',
        id,
        result: {
          isError: true,
          content: [
            {
              type: 'text',
              text: `MCP Authentication Failure: ${authContext.error}`
            }
          ]
        }
      });
    }

    console.log(`[MCP-RPC] Authenticated Principal: ${authContext.sub} | Actor: ${authContext.act?.sub} | Chain: [${(authContext.actorChain || []).join(' -> ')}]`);
    const toolResult = await engine.executeTool(name, toolArgs, authContext);
    console.log(`[MCP-RPC] Completed 'tools/call' -> isError: ${toolResult.isError}`);
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

// Helper REST API for convenience
app.get('/api/tools', (req, res) => {
  res.json({
    protocolVersion: PROTOCOL_VERSION,
    tools: engine.listTools()
  });
});

app.post('/api/tools/:name', async (req, res) => {
  const toolName = req.params.name;
  const authHeader = req.headers['authorization'];
  const authContext = verifyOboToken(authHeader);

  if (!authContext.authenticated) {
    return res.json({
      isError: true,
      content: [{ type: 'text', text: `Authentication Failure: ${authContext.error}` }]
    });
  }

  const result = await engine.executeTool(toolName, req.body, authContext);
  res.json(result);
});

// Start Server if invoked directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`===========================================================`);
    console.log(` Azure Low-Code Declarative MCP Server listening on ${PORT}`);
    console.log(` Protocol Version: ${PROTOCOL_VERSION} (July 2026)`);
    console.log(`===========================================================`);
  });
}

module.exports = app;
