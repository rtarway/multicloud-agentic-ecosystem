#!/usr/bin/env node

/**
 * Automates Keycloak Token Exchange setup for Azure WIF POC
 * Grants agent-orchestrator-client permission to exchange tokens for mcp-azure-service.
 */

const http = require('http');
const querystring = require('querystring');

const KEYCLOAK_HOST = process.env.KEYCLOAK_HOST || 'keycloak-service.keycloak.svc.cluster.local';
const KEYCLOAK_PORT = parseInt(process.env.KEYCLOAK_PORT || '8080', 10);
const ADMIN_USER = process.env.KEYCLOAK_ADMIN || 'admin';
const ADMIN_PASS = process.env.KEYCLOAK_ADMIN_PASSWORD || 'admin';

function req(path, method = 'GET', body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    let payload = '';
    if (headers['Content-Type'] === 'application/x-www-form-urlencoded') {
      payload = querystring.stringify(body);
    } else if (body) {
      payload = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
    }
    if (payload) {
      headers['Content-Length'] = Buffer.byteLength(payload);
    }

    const request = http.request(
      {
        hostname: KEYCLOAK_HOST,
        port: KEYCLOAK_PORT,
        path,
        method,
        headers
      },
      res => {
        let data = '';
        res.on('data', c => (data += c));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, body: JSON.parse(data) });
          } catch {
            resolve({ status: res.statusCode, body: data });
          }
        });
      }
    );
    request.on('error', reject);
    if (payload) request.write(payload);
    request.end();
  });
}

async function setup() {
  console.log(`[Keycloak Setup] Connecting to Keycloak at ${KEYCLOAK_HOST}:${KEYCLOAK_PORT}...`);

  // 1. Get Admin Token
  const adminRes = await req(
    '/realms/master/protocol/openid-connect/token',
    'POST',
    {
      grant_type: 'password',
      client_id: 'admin-cli',
      username: ADMIN_USER,
      password: ADMIN_PASS
    },
    { 'Content-Type': 'application/x-www-form-urlencoded' }
  );

  if (adminRes.status !== 200 || !adminRes.body.access_token) {
    throw new Error(`Failed authenticating admin: ${JSON.stringify(adminRes.body)}`);
  }

  const auth = { Authorization: `Bearer ${adminRes.body.access_token}` };
  console.log('[Keycloak Setup] Admin authenticated successfully.');

  // 2. Fetch clients in azure-wif-realm
  const clients = (await req('/admin/realms/azure-wif-realm/clients', 'GET', null, auth)).body;
  if (!Array.isArray(clients)) {
    throw new Error(`Failed listing clients: ${JSON.stringify(clients)}`);
  }

  const mcpClient = clients.find(c => c.clientId === 'mcp-azure-service');
  const orchClient = clients.find(c => c.clientId === 'agent-orchestrator-client');
  const realmMgmt = clients.find(c => c.clientId === 'realm-management');

  if (!mcpClient || !orchClient || !realmMgmt) {
    throw new Error('Required clients not found in azure-wif-realm.');
  }

  // 3. Enable management permissions on mcp-azure-service
  await req(`/admin/realms/azure-wif-realm/clients/${mcpClient.id}/management/permissions`, 'PUT', { enabled: true }, auth);

  // 4. Fetch permission IDs
  const perms = (await req(`/admin/realms/azure-wif-realm/clients/${mcpClient.id}/management/permissions`, 'GET', null, auth)).body;
  const tokenExchangePermId = perms.scopePermissions?.['token-exchange'];

  if (!tokenExchangePermId) {
    throw new Error('Could not find token-exchange scope permission ID.');
  }

  // 5. Ensure client policy allow-orchestrator-exchange exists in realm-management
  const existingPolicies = (
    await req(`/admin/realms/azure-wif-realm/clients/${realmMgmt.id}/authz/resource-server/policy`, 'GET', null, auth)
  ).body;

  let policy = Array.isArray(existingPolicies) && existingPolicies.find(p => p.name === 'allow-orchestrator-exchange');
  if (!policy) {
    await req(
      `/admin/realms/azure-wif-realm/clients/${realmMgmt.id}/authz/resource-server/policy/client`,
      'POST',
      {
        name: 'allow-orchestrator-exchange',
        clients: [orchClient.id]
      },
      auth
    );

    const updated = (
      await req(`/admin/realms/azure-wif-realm/clients/${realmMgmt.id}/authz/resource-server/policy`, 'GET', null, auth)
    ).body;
    policy = updated.find(p => p.name === 'allow-orchestrator-exchange');
  }

  // 6. Bind policy to token-exchange permission
  await req(
    `/admin/realms/azure-wif-realm/clients/${realmMgmt.id}/authz/resource-server/permission/scope/${tokenExchangePermId}`,
    'PUT',
    {
      id: tokenExchangePermId,
      name: `token-exchange.permission.client.${mcpClient.id}`,
      policies: [policy.id]
    },
    auth
  );

  console.log('[Keycloak Setup] Token exchange permission successfully bound to agent-orchestrator-client.');
}

if (require.main === module) {
  setup()
    .then(() => {
      console.log('[Keycloak Setup] Setup complete.');
      process.exit(0);
    })
    .catch(err => {
      console.error('[Keycloak Setup] Error:', err.message);
      process.exit(1);
    });
}

module.exports = { setup };
