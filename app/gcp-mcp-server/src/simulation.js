// Simulation guard (canonical copy: shared/simulation.js; synced into each app by scripts/sync-shared.sh).
//
// The POC can run in a "demo" mode where identity providers, SPIRE and cloud IAM are simulated with
// locally generated keys and tokens. That mode must be an explicit opt-in: with ALLOW_SIMULATION unset
// (the default) nothing in this repo may produce, accept or fall back to a locally minted credential.

class SimulationDisabledError extends Error {
  constructor(feature) {
    super(`SIMULATION_DISABLED: '${feature}' requires ALLOW_SIMULATION=true (demo profile only). Refusing to fall back to a locally generated credential or fixture.`);
    this.name = 'SimulationDisabledError';
    this.code = 'SIMULATION_DISABLED';
  }
}

function isSimulation() {
  return String(process.env.ALLOW_SIMULATION || '').toLowerCase() === 'true';
}

function requireSimulation(feature) {
  if (!isSimulation()) throw new SimulationDisabledError(feature);
}

/**
 * Returns a named secret for demo use only. Reads the environment first; in simulation mode a random
 * per-process value is generated (and cached in process.env) when none is configured. Never has a
 * hard-coded default and never works outside simulation mode.
 */
function getDemoSecret(name) {
  if (process.env[name]) return process.env[name];
  requireSimulation(`secret ${name}`);
  const generated = require('crypto').randomBytes(32).toString('hex');
  process.env[name] = generated;
  return generated;
}

/**
 * Call once when a service starts. Throws if the service cannot run safely in the current mode.
 *  - Simulation is never allowed when DEPLOYMENT_ENV=production (the marker real deployments set;
 *    NODE_ENV is not used because the container images always set it to "production").
 *  - Outside simulation, any entry in `realModeBlockers` (capabilities that are not implemented yet)
 *    stops the service from starting instead of silently degrading.
 */
function assertStartupSafe(serviceName, { realModeBlockers = [] } = {}) {
  const sim = isSimulation();
  if (sim && process.env.DEPLOYMENT_ENV === 'production') {
    throw new Error(`[${serviceName}] ALLOW_SIMULATION=true is not permitted when DEPLOYMENT_ENV=production.`);
  }
  if (sim) {
    console.warn(`[${serviceName}] ⚠️  DEMO PROFILE: ALLOW_SIMULATION=true. Identity, SPIRE and cloud IAM are simulated. Do not use with real data.`);
    return;
  }
  if (realModeBlockers.length > 0) {
    throw new Error(
      `[${serviceName}] Cannot start without ALLOW_SIMULATION=true: ${realModeBlockers.join('; ')}.`
    );
  }
}

module.exports = { isSimulation, requireSimulation, getDemoSecret, assertStartupSafe, SimulationDisabledError };
