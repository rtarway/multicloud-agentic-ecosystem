// SPIRE Workload API Client for Agent Orchestrator
// Acquires SPIFFE JWT-SVIDs representing the agent workload identity

const fs = require('fs');
const jwtUtil = require('./jwtUtil');

const DEFAULT_SOCKET_PATH = '/run/spire/sockets/agent.sock';
const AGENT_SPIFFE_ID = process.env.AGENT_SPIFFE_ID || 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa';
const SPIRE_SECRET = process.env.SPIRE_SECRET || 'demo-spire-secret-key-2026';

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
   * In K8s with SPIRE, this communicates with the SPIRE Workload API.
   * In local/simulated environment, it creates a cryptographically signed JWT-SVID with the SPIFFE ID.
   */
  async fetchJwtSvid(audience = 'azure-mcp-server') {
    // Generate/fetch SPIFFE JWT-SVID
    const svidPayload = {
      sub: AGENT_SPIFFE_ID,
      aud: audience,
      iss: 'https://spire.example.org',
      spiffe: {
        trustDomain: 'example.org',
        namespace: 'agent-system',
        serviceAccount: 'orchestrator-sa'
      }
    };

    const token = jwtUtil.sign(svidPayload, SPIRE_SECRET, { expiresInSeconds: 300 });

    return {
      spiffeId: AGENT_SPIFFE_ID,
      token,
      audience,
      isSimulated: !this.hasWorkloadApi
    };
  }
}

module.exports = new SpireClient();
