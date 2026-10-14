// Client assertion for the Azure MCP server's confidential Entra application, WITHOUT a client secret.
//
// The MCP app registration trusts a federated identity credential whose subject is this App Service's managed identity
// (or, on Kubernetes, its workload-identity service account). To authenticate to Entra the server presents a token that
// identity provider issued for the audience api://AzureADTokenExchange, as an RFC 7523 client assertion.

const fs = require('fs');

const AUDIENCE = 'api://AzureADTokenExchange';

class AssertionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AssertionError';
    this.code = 'CLIENT_ASSERTION_UNAVAILABLE';
  }
}

/** True when this process can obtain a federated client assertion. */
function hasFederatedSource(env = process.env) {
  return Boolean(env.AZURE_FEDERATED_TOKEN_FILE || (env.IDENTITY_ENDPOINT && env.IDENTITY_HEADER));
}

async function getClientAssertion({ env = process.env, fetchImpl = fetch, readFile = fs.readFileSync } = {}) {
  if (env.AZURE_FEDERATED_TOKEN_FILE) {
    // Kubernetes workload identity: a projected service-account token, refreshed on disk by the kubelet
    return readFile(env.AZURE_FEDERATED_TOKEN_FILE, 'utf8').trim();
  }
  if (env.IDENTITY_ENDPOINT && env.IDENTITY_HEADER) {
    // App Service / Functions managed identity endpoint
    const url = new URL(env.IDENTITY_ENDPOINT);
    url.searchParams.set('resource', AUDIENCE);
    url.searchParams.set('api-version', '2019-08-01');
    if (env.AZURE_MI_CLIENT_ID) url.searchParams.set('client_id', env.AZURE_MI_CLIENT_ID);
    const res = await fetchImpl(url, { headers: { 'X-IDENTITY-HEADER': env.IDENTITY_HEADER }, signal: AbortSignal.timeout(5000) });
    if (!res.ok) throw new AssertionError(`The managed identity endpoint refused the request (HTTP ${res.status}).`);
    const json = await res.json();
    if (!json.access_token) throw new AssertionError('The managed identity endpoint returned no token.');
    return json.access_token;
  }
  throw new AssertionError('No federated credential source is available (managed identity or workload identity token file).');
}

module.exports = { getClientAssertion, hasFederatedSource, AssertionError, AUDIENCE };
