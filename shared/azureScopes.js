// Fine-grained delegated scopes of the Azure MCP server's Entra application (canonical copy: shared/azureScopes.js;
// vendored into the orchestrator and the Azure MCP server by scripts/sync-shared.sh).
//
// Instead of one broad `user_impersonation` scope, each (action, container) pair has its own delegated permission, so an
// OBO token can be requested for exactly what one tool call needs:
//   Mcp.Storage.ReadApp1  Mcp.Storage.ReadApp2  Mcp.Storage.WriteApp1  Mcp.Storage.WriteApp2
// Azure RBAC on the container remains the final authority over what the user can actually do.

const CONTAINERS = Object.freeze({ app1: 'App1', app2: 'App2' });
const ACTIONS = Object.freeze({ read: 'Read', write: 'Write' });

class ScopeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScopeError';
    this.code = 'INVALID_STORAGE_REQUEST';
  }
}

/** The delegated scope needed for one storage operation. Throws for anything outside the known containers/actions. */
function storageScope(action, container) {
  if (!Object.prototype.hasOwnProperty.call(ACTIONS, action)) throw new ScopeError(`Unsupported storage action '${action}'.`);
  if (!Object.prototype.hasOwnProperty.call(CONTAINERS, container)) throw new ScopeError(`Unsupported storage container '${container}'.`);
  return `Mcp.Storage.${ACTIONS[action]}${CONTAINERS[container]}`;
}

const ALL_STORAGE_SCOPES = Object.freeze(
  Object.values(ACTIONS).flatMap(a => Object.values(CONTAINERS).map(c => `Mcp.Storage.${a}${c}`))
);

module.exports = { storageScope, ALL_STORAGE_SCOPES, ScopeError };
