// Wiring of the strict (non-simulated) identity path from the environment, and the list of things that must be
// configured before the orchestrator may start without ALLOW_SIMULATION=true.

const fs = require('fs');
const { createUserAuthenticator, readConfig, isStrict } = require('./userAuth');
const { createIdpClient } = require('./idpExchange');

const DEFAULT_SOCKET = '/run/spire/sockets/agent.sock';

/** Human-readable reasons the real identity path cannot run yet (empty when it can). */
function realModeBlockers(env = process.env, fileExists = fs.existsSync) {
  const blockers = [];
  const config = readConfig(env);
  if (!isStrict(config)) blockers.push('OIDC_ISSUER is not set (user tokens cannot be verified)');
  if (!config.identityMapPath || !fileExists(config.identityMapPath)) blockers.push('IDENTITY_MAP_PATH does not point to an identity map file');
  if (!env.ORCHESTRATOR_CLIENT_SECRET) blockers.push('ORCHESTRATOR_CLIENT_SECRET is not set (token exchange at the IdP cannot authenticate)');
  if (!fileExists(env.SPIRE_AGENT_SOCKET || DEFAULT_SOCKET)) blockers.push('the SPIRE agent socket is not available (no workload identity)');
  return blockers;
}

/**
 * Builds the verifier for user tokens and the client for token exchange when OIDC_ISSUER is configured.
 * Returns null in demo mode (no OIDC_ISSUER). Misconfiguration throws so the service fails loudly at startup.
 */
function buildStrictRuntime(env = process.env, overrides = {}) {
  const config = readConfig(env);
  if (!isStrict(config)) return null;

  const authenticator = createUserAuthenticator({ config, ...overrides });
  const idpClient = createIdpClient({
    issuer: config.issuer,
    tokenEndpoint: env.OIDC_TOKEN_ENDPOINT || `${config.issuer.replace(/\/+$/, '')}/protocol/openid-connect/token`,
    clientId: env.ORCHESTRATOR_CLIENT_ID || 'agent-orchestrator-client',
    clientSecret: env.ORCHESTRATOR_CLIENT_SECRET,
    knownAgentScopes: [...authenticator.resolver.allAgentScopes],
    maxTtlSec: Number(env.MAX_EXCHANGED_TOKEN_TTL_SEC || 300),
    ...overrides.idp
  });
  return { authenticator, idpClient };
}

module.exports = { realModeBlockers, buildStrictRuntime };
