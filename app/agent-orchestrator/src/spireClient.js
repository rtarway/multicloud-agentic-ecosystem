// SPIRE Workload API Client for Agent Orchestrator
// Acquires SPIFFE JWT-SVIDs representing the agent workload identity

const fs = require('fs');
const jwtUtil = require('./jwtUtil');
const { requireSimulation, getDemoSecret } = require('./simulation');

const DEFAULT_SOCKET_PATH = '/run/spire/sockets/agent.sock';
const AGENT_SPIFFE_ID = process.env.AGENT_SPIFFE_ID || 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa';

class SpireClient {
  constructor(socketPath) {
    this.socketPath = socketPath || process.env.SPIRE_AGENT_SOCKET || DEFAULT_SOCKET_PATH;
    this.hasWorkloadApi = fs.existsSync(this.socketPath);
    if (this.hasWorkloadApi) {
      console.log(`[SPIRE Client] Detected live SPIRE Workload API socket at ${this.socketPath}`);
    } else {
      console.log(`[SPIRE Client] Running in standalone/simulated mode. Workload identity: ${AGENT_SPIFFE_ID}`);
    }
  }

  /**
   * Fetches a JWT-SVID for the agent workload.
   *
   * The SPIRE Workload API is not called yet (Phase 2). Until it is, the only available SVID is a
   * locally signed stand-in, which exists solely for the demo profile and is refused otherwise.
   */
  async fetchJwtSvid(audience = 'azure-mcp-server') {
    requireSimulation('locally signed JWT-SVID (SPIRE Workload API client not implemented)');

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
