// Web Frontend Server (Kept Outside SPIRE)
// Provides Browser-facing UI, Keycloak OIDC authentication proxy, and Agent Orchestrator dispatching.

const express = require('express');
const http = require('http');
const path = require('path');
const jwtUtil = require('./jwtUtil');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

const PORT = process.env.PORT || 3000;
const AGENT_URL = process.env.AGENT_ORCHESTRATOR_URL || 'http://localhost:3001';
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://localhost:8080';
const JWT_SECRET = process.env.JWT_SECRET || 'demo-obo-token-secret-key-2026';

// Health Check
app.get('/healthz', (req, res) => {
  res.json({
    status: 'UP',
    service: 'web-frontend',
    spireManaged: false, // Explicitly outside SPIRE
    agentEndpoint: AGENT_URL,
    keycloakEndpoint: KEYCLOAK_URL
  });
});

const ENTRA_TENANT_ID = process.env.ENTRA_TENANT_ID || '81f26b58-159c-4879-80a0-bab30b5b4dd3';
const ENTRA_CLIENT_ID = process.env.ENTRA_CLIENT_ID || 'a23206e1-2dda-4854-aac7-0536d2da2c4c';
const ENTRA_AUDIENCE = process.env.ENTRA_AUDIENCE || 'api://d5850aa0-a667-41c3-8dd0-16f2dee4da25';

const USER_CONFIGS = {
  alice: {
    username: 'alice',
    password: 'Password123!',
    email: 'alice@rtarwaygmail.onmicrosoft.com',
    displayName: 'Alice (Auditor / Storage Reader / Mail.Send)',
    roles: ['admin', 'auditor', 'Storage Blob Data Reader', 'Mail.Send'],
    scopes: ['mcp:tool1', 'mcp:tool2', 'Mail.Send'],
    azureRole: 'Storage Blob Data Reader (app1 & app2) + Entra Mail.Send',
    description: 'Authorized on Storage (app1 & app2) AND Microsoft Graph Mail.Send.'
  },
  bob: {
    username: 'bob',
    password: 'Password123!',
    email: 'bob@rtarwaygmail.onmicrosoft.com',
    displayName: 'Bob (Data Contributor on app2 / No app1 Role)',
    roles: ['regular-user', 'Storage Blob Data Contributor'],
    scopes: ['mcp:tool1'],
    azureRole: 'Storage Blob Data Contributor (app2 ONLY; No app1 role; No Graph access)',
    description: 'Contributor on app2 only. Blocked on app1 by Azure Storage Cloud IAM; No Graph access.'
  },
  charlie: {
    username: 'charlie',
    password: 'Password123!',
    email: 'charlie@rtarwaygmail.onmicrosoft.com',
    displayName: 'Charlie (Storage Reader / NO Graph Mail.Send)',
    roles: ['auditor', 'Storage Blob Data Reader'],
    scopes: ['mcp:tool1', 'mcp:tool2'],
    azureRole: 'Storage Blob Data Reader (app1 & app2) - Zero Microsoft Graph Permissions',
    description: 'Storage reader on app1 & app2, but strictly lacks Microsoft Graph Mail.Send scope on Keycloak and Entra ID.'
  }
};
// Backward compatibility alias
USER_CONFIGS['alice-no-mail'] = USER_CONFIGS.charlie;

// Pre-configured Users List Endpoint for POC Login Screen
app.get('/api/users', (req, res) => {
  res.json({
    users: [USER_CONFIGS.alice, USER_CONFIGS.bob, USER_CONFIGS.charlie]
  });
});

// Authentication Endpoint: Keycloak Login Simulation & Direct Grant
app.post('/api/login', async (req, res) => {
  const { username, password, userType } = req.body || {};

  let resolvedUser = 'bob';
  if (userType === 'charlie' || username === 'charlie' || userType === 'alice-no-mail' || username === 'alice-no-mail') {
    resolvedUser = 'charlie';
  } else if (userType === 'admin' || userType === 'alice' || username === 'alice') {
    resolvedUser = 'alice';
  } else if (username === 'bob' || userType === 'regular-user' || userType === 'bob') {
    resolvedUser = 'bob';
  }

  const user = USER_CONFIGS[resolvedUser] || USER_CONFIGS.bob;

  // 1. Mint Keycloak OIDC Bearer Token
  const keycloakToken = jwtUtil.sign(
    {
      iss: `${KEYCLOAK_URL}/realms/azure-wif-realm`,
      sub: user.email,
      preferred_username: user.username,
      email: user.email,
      name: user.displayName,
      realm_access: {
        roles: user.roles
      },
      roles: user.roles,
      scope: user.scopes.join(' ')
    },
    JWT_SECRET,
    { expiresInSeconds: 3600 }
  );

  // 2. Mint Microsoft Entra ID User Subject Token
  const entraToken = jwtUtil.sign(
    {
      iss: `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0`,
      tid: ENTRA_TENANT_ID,
      aud: ENTRA_AUDIENCE,
      sub: user.email,
      upn: user.email,
      email: user.email,
      name: user.displayName,
      appid: ENTRA_CLIENT_ID,
      azp: ENTRA_CLIENT_ID,
      roles: user.roles,
      scp: user.scopes.join(' '),
      scope: user.scopes.join(' '),
      identityProvider: 'EntraID'
    },
    JWT_SECRET,
    { expiresInSeconds: 3600 }
  );

  return res.json({
    authenticated: true,
    user,
    token: keycloakToken, // Primary token used by orchestrator
    keycloakToken,
    entraToken
  });
});

// Proxy Chat/Prompt to Agent Orchestrator
app.post('/api/chat', async (req, res) => {
  const { prompt } = req.body || {};
  const token = (req.body && req.body.token) || (req.headers.authorization ? req.headers.authorization.replace(/^Bearer\s+/i, '') : null);

  if (!prompt) {
    return res.status(400).json({ error: 'Missing prompt.' });
  }

  const payload = JSON.stringify({
    prompt,
    token,
    context: req.body && req.body.context,
    emailConfig: req.body && req.body.emailConfig
  });
  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload)
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // If local test dispatcher injected, use it
  if (app.locals.agentDispatcher) {
    const result = await app.locals.agentDispatcher(prompt, token);
    return res.json(result);
  }

  const agentUrl = new URL('/api/agent/chat', AGENT_URL);

  const request = http.request(agentUrl, { method: 'POST', headers }, agentRes => {
    let data = '';
    agentRes.on('data', chunk => (data += chunk));
    agentRes.on('end', () => {
      try {
        res.status(agentRes.statusCode).json(JSON.parse(data));
      } catch {
        res.status(agentRes.statusCode).send(data);
      }
    });
  });

  request.on('error', err => {
    res.status(502).json({
      error: 'Agent Orchestrator unreachable',
      details: err.message,
      agentEndpoint: AGENT_URL
    });
  });

  request.write(payload);
  request.end();
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`===========================================================`);
    console.log(` Web Frontend running on http://localhost:${PORT}`);
    console.log(` Architecture: OUTSIDE SPIRE (Browser-friendly)`);
    console.log(` Connected Agent: ${AGENT_URL}`);
    console.log(`===========================================================`);
  });
}

module.exports = app;
