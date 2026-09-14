// scripts/start-ui.js
// Launches Web Frontend (port 3000), Agent Orchestrator (port 3001), and MCP Server (port 8080)
// for quick, interactive browser-based testing of the full end-to-end flow.

const path = require('path');

process.env.PORT = '8080';
const mcpApp = require('../app/mcp-server/src/index');

process.env.PORT = '3001';
process.env.AZURE_MCP_ENDPOINT = 'http://localhost:8080';
const agentApp = require('../app/agent-orchestrator/src/index');

process.env.PORT = '3000';
process.env.AGENT_ORCHESTRATOR_URL = 'http://localhost:3001';
const frontendApp = require('../app/web-frontend/src/index');

const mcpServer = mcpApp.listen(8080, () => {
  console.log('✅ [1/3] Azure MCP Server running at:        http://localhost:8080');
});

const agentServer = agentApp.listen(3001, () => {
  console.log('✅ [2/3] Agent Orchestrator running at:     http://localhost:3001');
});

const frontendServer = frontendApp.listen(3000, () => {
  console.log('✅ [3/3] Web Frontend UI running at:        http://localhost:3000');
  console.log('\n=================================================================');
  console.log(' 🚀 Azure WIF + Agentic MCP UI is Ready!');
  console.log(' 👉 Open your browser at: http://localhost:3000');
  console.log('=================================================================\n');
});

function shutdown() {
  console.log('\nShutting down all services...');
  frontendServer.close();
  agentServer.close();
  mcpServer.close();
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
