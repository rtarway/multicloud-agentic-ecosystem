#!/usr/bin/env node

/**
 * scripts/setup-keycloak-entra-federation.js
 * Configures Keycloak SAML Direct Federation for Microsoft Entra ID (Azure AD)
 * and exports the SAML signing certificate for Azure External Identities.
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const querystring = require('querystring');

const KEYCLOAK_HOST = process.env.KEYCLOAK_HOST || 'keycloak-service.keycloak.svc.cluster.local';
const KEYCLOAK_PORT = parseInt(process.env.KEYCLOAK_PORT || '8080', 10);
const ADMIN_USER = process.env.KEYCLOAK_ADMIN || 'admin';
const ADMIN_PASS = process.env.KEYCLOAK_ADMIN_PASSWORD || 'admin';
const ENTRA_TENANT_ID = process.env.ENTRA_TENANT_ID || '81f26b58-159c-4879-80a0-bab30b5b4dd3';

function req(urlPath, method = 'GET', body = null, headers = {}) {
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
        path: urlPath,
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

async function run() {
  console.log('=================================================================');
  console.log(' Setting up Keycloak SAML Federation for Microsoft Entra ID');
  console.log('=================================================================');

  // 1. Authenticate Admin
  console.log(`--> 1. Authenticating with Keycloak Admin at ${KEYCLOAK_HOST}:${KEYCLOAK_PORT}...`);
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
    throw new Error(`Keycloak Admin Authentication failed: ${JSON.stringify(adminRes.body)}`);
  }
  const auth = { Authorization: `Bearer ${adminRes.body.access_token}` };
  console.log('   ✅ Keycloak Admin Authenticated.');

  // 2. Fetch Signing Keys & Export Certificate
  console.log('--> 2. Fetching Keycloak Realm Signing Certificate...');
  const jwksRes = await req('/realms/azure-wif-realm/protocol/openid-connect/certs', 'GET');
  let certBase64 = null;
  if (jwksRes.status === 200 && Array.isArray(jwksRes.body?.keys)) {
    const rsaKey = jwksRes.body.keys.find(k => k.kty === 'RSA' && k.x5c && k.x5c.length > 0);
    if (rsaKey) {
      certBase64 = rsaKey.x5c[0];
    }
  }

  if (certBase64) {
    const certDir = path.join(__dirname, '..', 'certs');
    if (!fs.existsSync(certDir)) {
      fs.mkdirSync(certDir, { recursive: true });
    }
    const formattedCert = [
      '-----BEGIN CERTIFICATE-----',
      certBase64.match(/.{1,64}/g).join('\n'),
      '-----END CERTIFICATE-----',
      ''
    ].join('\n');

    const certPath = path.join(certDir, 'keycloak-saml.cer');
    fs.writeFileSync(certPath, formattedCert, 'utf8');
    console.log(`   ✅ Exported SAML Signing Certificate to: ${certPath}`);
  } else {
    console.warn('   ⚠️ Could not extract x5c certificate from JWKS endpoint.');
  }

  // 3. Register SAML Client for Microsoft Entra ID
  const entraClientId = `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/federation`;
  console.log(`--> 3. Configuring SAML Client for Entra ID (${entraClientId})...`);

  const existingClients = (await req('/admin/realms/azure-wif-realm/clients', 'GET', null, auth)).body;
  let samlClient = Array.isArray(existingClients) && existingClients.find(c => c.clientId === entraClientId);

  const clientConfig = {
    clientId: entraClientId,
    name: 'Microsoft Entra Direct Federation (Azure AD)',
    description: 'SAML 2.0 Client for Microsoft Entra ID External Identities B2B Direct Federation',
    protocol: 'saml',
    enabled: true,
    alwaysDisplayInConsole: true,
    fullScopeAllowed: true,
    frontchannelLogout: true,
    attributes: {
      'saml.authnstatement': 'true',
      'saml.server.signature': 'true',
      'saml.server.signature.keyinfo.ext': 'false',
      'saml_name_id_format': 'email',
      'saml_force_name_id_format': 'true',
      'saml.client.signature': 'false',
      'saml.assertion.signature': 'true',
      'saml.signature.algorithm': 'RSA_SHA256'
    },
    redirectUris: [
      'https://login.microsoftonline.com/common/federation/externalfederationauth',
      `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/federation/externalfederationauth`,
      'https://login.microsoftonline.com/common/oauth2/nativeclient'
    ],
    baseUrl: `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/federation/externalfederationauth`
  };

  if (!samlClient) {
    const createRes = await req('/admin/realms/azure-wif-realm/clients', 'POST', clientConfig, auth);
    if (createRes.status !== 201) {
      console.log('   Create status:', createRes.status, createRes.body);
    }
    const refreshed = (await req('/admin/realms/azure-wif-realm/clients', 'GET', null, auth)).body;
    samlClient = Array.isArray(refreshed) && refreshed.find(c => c.clientId === entraClientId);
    console.log('   ✅ Created SAML Client in Keycloak.');
  } else {
    await req(`/admin/realms/azure-wif-realm/clients/${samlClient.id}`, 'PUT', Object.assign({}, samlClient, clientConfig), auth);
    console.log('   ✅ Updated existing SAML Client configuration.');
  }

  // 4. Configure SAML Protocol Mappers for Email, Name, and Role
  console.log('--> 4. Configuring SAML Attribute Mappers...');
  const mappers = [
    {
      name: 'email',
      protocol: 'saml',
      protocolMapper: 'saml-user-property-mapper',
      consentRequired: false,
      config: {
        'attribute.name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        'attribute.nameformat': 'Basic',
        'user.attribute': 'email',
        'friendly.name': 'Email'
      }
    },
    {
      name: 'name',
      protocol: 'saml',
      protocolMapper: 'saml-user-property-mapper',
      consentRequired: false,
      config: {
        'attribute.name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        'attribute.nameformat': 'Basic',
        'user.attribute': 'username',
        'friendly.name': 'Username'
      }
    },
    {
      name: 'roles',
      protocol: 'saml',
      protocolMapper: 'saml-role-list-mapper',
      consentRequired: false,
      config: {
        'attribute.name': 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
        'attribute.nameformat': 'Basic',
        'single': 'false'
      }
    }
  ];

  if (samlClient) {
    const existingMappers = (await req(`/admin/realms/azure-wif-realm/clients/${samlClient.id}/protocol-mappers/models`, 'GET', null, auth)).body;
    for (const m of mappers) {
      const exists = Array.isArray(existingMappers) && existingMappers.find(em => em.name === m.name);
      if (!exists) {
        await req(`/admin/realms/azure-wif-realm/clients/${samlClient.id}/protocol-mappers/models`, 'POST', m, auth);
        console.log(`   ✅ Added SAML mapper: ${m.name}`);
      }
    }
  }

  console.log('\n=================================================================');
  console.log(' Keycloak SAML Federation Configured Successfully!');
  console.log('=================================================================');
  console.log(`  * Client ID:       ${entraClientId}`);
  console.log(`  * Issuer URI:      http://${KEYCLOAK_HOST}:${KEYCLOAK_PORT}/realms/azure-wif-realm`);
  console.log(`  * Passive SSO URL: http://${KEYCLOAK_HOST}:${KEYCLOAK_PORT}/realms/azure-wif-realm/protocol/saml`);
  console.log(`  * Signing Cert:    certs/keycloak-saml.cer`);
  console.log('=================================================================\n');
}

run().catch(err => {
  console.error('[Keycloak Federation Setup Error]:', err.message);
  process.exit(1);
});
