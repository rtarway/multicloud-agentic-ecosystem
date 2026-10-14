// SPIRE Workload API Client for Agent Orchestrator
// Acquires SPIFFE JWT-SVIDs representing the agent workload identity

const fs = require('fs');
const jwtUtil = require('./jwtUtil');
const { requireSimulation, getDemoSecret } = require('./simulation');
const spiffe = require('./spiffe');

const DEFAULT_SOCKET_PATH = '/run/spire/sockets/agent.sock';
const AGENT_SPIFFE_ID = process.env.AGENT_SPIFFE_ID || 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa';

class SpireClient {
  constructor(socketPath) {
    this.socketPath = socketPath || process.env.SPIRE_AGENT_SOCKET || DEFAULT_SOCKET_PATH;
  }

  /** True when the SPIRE agent's Workload API socket is mounted (checked on every call). */
  get hasWorkloadApi() {
    return fs.existsSync(this.socketPath);
  }

  /**
   * Fetches a JWT-SVID for the agent workload, scoped to one audience.
   *
   * With the SPIRE agent socket present the SVID comes from the Workload API; any failure is an error (no fallback to a
   * locally signed token). Without a socket, a locally signed stand-in exists for the demo profile only.
   */
  async fetchJwtSvid(audience = 'azure-mcp-server') {
    if (this.hasWorkloadApi) {
      const svid = await spiffe.fetchJwtSvid({
        socketPath: this.socketPath,
        audience: [audience],
        spiffeId: process.env.AGENT_SPIFFE_ID || undefined
      });
      return { spiffeId: svid.spiffeId, token: svid.token, audience, isSimulated: false };
    }

    requireSimulation('locally signed JWT-SVID (SPIRE agent socket not available)');

    const svidPayload = {
      sub: AGENT_SPIFFE_ID,
      aud: audience,
      iss: 'https://spire.example.org',
      x_simulated: true,
      spiffe: {
        trustDomain: 'example.org',
        namespace: 'agent-system',
        serviceAccount: 'orchestrator-sa'
      }
    };

    const token = jwtUtil.sign(svidPayload, getDemoSecret('SPIRE_SECRET'), { expiresInSeconds: 300 });

    return {
      spiffeId: AGENT_SPIFFE_ID,
      token,
      audience,
      isSimulated: true
    };
  }
}

module.exports = new SpireClient();
module.exports.SpireClient = SpireClient;
