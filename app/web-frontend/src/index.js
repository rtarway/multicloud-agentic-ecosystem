// Web Frontend Server (Kept Outside SPIRE)
// Provides Browser-facing UI, Keycloak OIDC authentication proxy, and Agent Orchestrator dispatching.

const express = require('express');
const http = require('http');
const path = require('path');
const jwtUtil = require('./jwtUtil');
const { isSimulation, getDemoSecret, assertStartupSafe } = require('./simulation');
const { redactDeep } = require('./redact');
const { readLoginConfig, createOidcLogin } = require('./oidcLogin');
const { readEntraConfig, createEntraLogin } = require('./entraLogin');
const { createResolver } = require('./identityMapping');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

const PORT = process.env.PORT || 3000;
const AGENT_URL = process.env.AGENT_ORCHESTRATOR_URL || 'http://localhost:3001';
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://localhost:8080';

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

// ---- real login: OIDC authorization code + PKCE, server-side session (BFF) ----
const loginConfig = readLoginConfig();
app.locals.oidcLogin = loginConfig ? createOidcLogin({ config: loginConfig }) : null;

// ---- Entra sign-in for the same user (needed for Azure tools) ----
const entraConfig = readEntraConfig();
app.locals.entraLogin = entraConfig && app.locals.oidcLogin ? createEntraLogin({ config: entraConfig }) : null;
app.locals.identityResolver = process.env.IDENTITY_MAP_PATH ? createResolver(process.env.IDENTITY_MAP_PATH) : null;

/** The Entra identity the directory maps the signed-in IdP user to, or null (fail closed). */
function expectedEntraUpn(session) {
  const resolver = app.locals.identityResolver;
  if (!resolver) return null;
  try {
    return resolver.requireEntraUpn(resolver.resolveFromClaims({ email: session.email, email_verified: session.emailVerified === true }));
  } catch {
    return null;
  }
}

function authMode() {
  if (app.locals.oidcLogin) return 'oidc';
  return isSimulation() ? 'demo' : 'none';
}

app.get('/auth/login', (req, res) => {
  if (!app.locals.oidcLogin) return res.status(503).json({ error: 'LOGIN_DISABLED', message: 'OIDC login is not configured (OIDC_ISSUER / OIDC_CLIENT_ID).' });
  return app.locals.oidcLogin.login(req, res);
});

app.get('/auth/callback', async (req, res) => {
  if (!app.locals.oidcLogin) return res.status(503).json({ error: 'LOGIN_DISABLED' });
  return app.locals.oidcLogin.callback(req, res);
});

app.post('/auth/logout', (req, res) => {
  const login = app.locals.oidcLogin;
  if (!login) return res.status(503).json({ error: 'LOGIN_DISABLED' });
  if (!login.sameOrigin(req)) return res.status(403).json({ error: 'CROSS_ORIGIN_REQUEST_REFUSED' });
  return login.logout(req, res);
});

app.get('/auth/entra/login', (req, res) => {
  const entra = app.locals.entraLogin;
  const login = app.locals.oidcLogin;
  if (!entra || !login) return res.status(503).json({ error: 'ENTRA_LOGIN_DISABLED', message: 'Entra sign-in is not configured.' });
  const session = login.getSession(req);
  if (!session) return res.redirect(302, '/auth/login');
  const upn = expectedEntraUpn(session);
  if (!upn) return res.status(403).json({ error: 'NO_ENTRA_IDENTITY', message: 'The directory has no Azure identity for this user.' });
  return entra.start(req, res, { session, expectedUpn: upn });
});

app.get('/auth/entra/callback', async (req, res) => {
  const entra = app.locals.entraLogin;
  const login = app.locals.oidcLogin;
  if (!entra || !login) return res.status(503).json({ error: 'ENTRA_LOGIN_DISABLED' });
  const session = login.getSession(req);
  if (!session) return res.redirect(302, '/auth/login');
  return entra.callback(req, res, { session });
});

// What the browser may know: the auth mode and, when signed in, the user's identity and consented scopes (no tokens).
app.get('/api/session', (req, res) => {
  const mode = authMode();
  const login = app.locals.oidcLogin;
  const session = login ? login.getSession(req) : null;
  res.json({
    mode,
    authenticated: Boolean(session),
    signInUrl: login ? '/auth/login' : null,
    user: session ? login.sessionInfo(session) : null,
    entra: app.locals.entraLogin ? { ...app.locals.entraLogin.info(session), signInUrl: '/auth/entra/login' } : { configured: false }
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
    displayName: 'Alice (Multi-Cloud Admin / Azure Storage & Graph + GCP BigQuery Query & Audit)',
    roles: ['admin', 'auditor', 'Storage Blob Data Reader', 'Mail.Send', 'BigQuery.Admin'],
    scopes: ['mcp:tool1', 'mcp:tool2', 'mcp:bigquery:query', 'mcp:bigquery:audit', 'Mail.Send'],
    azureRole: 'Storage Blob Data Reader (app1 & app2) + Entra Mail.Send + GCP BigQuery Admin',
    description: 'Full multi-cloud privileges: Azure Storage, Graph Mail.Send, and GCP BigQuery Query & Audit.'
  },
  bob: {
    username: 'bob',
    password: 'Password123!',
    email: 'bob@rtarwaygmail.onmicrosoft.com',
    displayName: 'Bob (Analyst: Azure app2 + GCP BigQuery Sales Query)',
    roles: ['regular-user', 'Storage Blob Data Contributor'],
    scopes: ['mcp:tool1', 'mcp:bigquery:query'],
    azureRole: 'Storage Contributor (app2) + GCP BigQuery Query (No Audit / No Graph)',
    description: 'Contributor on app2 and BigQuery sales queries. Blocked on Azure app1, BigQuery audit, and Graph.'
  },
  charlie: {
    username: 'charlie',
    password: 'Password123!',
    email: 'charlie@rtarwaygmail.onmicrosoft.com',
    displayName: 'Charlie (Azure-Only Auditor / ZERO BigQuery & Graph Scopes)',
    roles: ['auditor', 'Storage Blob Data Reader'],
    scopes: ['mcp:tool1', 'mcp:tool2'],
    azureRole: 'Storage Reader (app1 & app2) ONLY - Strictly Lacks BigQuery & Graph Scopes',
    description: 'Azure storage auditor. Strictly lacks GCP BigQuery and Graph scopes. Demonstrates Gate 1 Fail-Closed.'
  }
};
// Backward compatibility alias
USER_CONFIGS['alice-no-mail'] = USER_CONFIGS.charlie;

// Pre-configured Users List Endpoint for POC Login Screen
// The login below mints tokens itself and lists demo credentials. That is acceptable only in the demo profile;
// the real OIDC login replaces it in Phase 2.
function requireDemoLogin(req, res, next) {
  if (isSimulation()) return next();
  return res.status(503).json({
    error: 'LOGIN_DISABLED',
    message: 'Demo login is disabled (ALLOW_SIMULATION is not true). Real OIDC login is not implemented yet.'
  });
}

app.get('/api/users', requireDemoLogin, (req, res) => {
  res.json({
    users: [USER_CONFIGS.alice, USER_CONFIGS.bob, USER_CONFIGS.charlie]
  });
});

// Authentication Endpoint: Keycloak Login Simulation & Direct Grant
app.post('/api/login', requireDemoLogin, async (req, res) => {
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
    getDemoSecret('JWT_SECRET'),
    { expiresInSeconds: 3600 }
  );

  // 2. Acquire Microsoft Entra ID User Subject Token (Authentic RS256 PKI for Orchestrator Audience)
  const azureTestKey = jwtUtil.getAzureTestPrivateKey();
  const orchestratorAudience = `api://${ENTRA_CLIENT_ID}`;
  let liveEntraUserToken = null;

  // Optional live Entra sign-in for the demo profile. The password must be supplied explicitly through the
  // environment; no default credential exists. (Replaced by an auth-code + PKCE flow in Phase 3.)
  try {
    if (!process.env.DEMO_ENTRA_USER_PASSWORD) throw new Error('DEMO_ENTRA_USER_PASSWORD not set');
    const postData = require('querystring').stringify({
      grant_type: 'password',
      client_id: ENTRA_CLIENT_ID,
      username: user.email,
      password: process.env.DEMO_ENTRA_USER_PASSWORD,
      scope: `${orchestratorAudience}/access_as_user openid profile`
    });

    const parsedUrl = new URL(`https://login.microsoftonline.com/${ENTRA_TENANT_ID}/oauth2/v2.0/token`);
    const entraUserRes = await new Promise((resolve, reject) => {
      const https = require('https');
      const req = https.request(parsedUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postData)
        },
        timeout: 2500
      }, res => {
        let raw = '';
        res.on('data', chunk => raw += chunk);
        res.on('end', () => {
          try { resolve({ statusCode: res.statusCode, body: JSON.parse(raw) }); }
          catch { resolve({ statusCode: res.statusCode, body: raw }); }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Entra user token request timed out')); });
      req.write(postData);
      req.end();
    });

    if (entraUserRes.statusCode === 200 && entraUserRes.body.access_token) {
      liveEntraUserToken = entraUserRes.body.access_token;
      console.log(`[FRONTEND-AUTH] ✅ Real Microsoft Entra ID user token acquired for ${user.email}`);
    }
  } catch (err) {
    // Offline / test fallback
  }

  const entraPayload = {
    iss: `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0`,
    tid: ENTRA_TENANT_ID,
    aud: orchestratorAudience,
    sub: user.email,
    upn: user.email,
    unique_name: user.email,
    email: user.email,
    name: user.displayName,
    appid: ENTRA_CLIENT_ID,
    azp: ENTRA_CLIENT_ID,
    roles: user.roles,
    scp: 'access_as_user',
    scope: 'access_as_user',
    identityProvider: 'EntraID'
  };

  const entraToken = liveEntraUserToken || (azureTestKey
    ? jwtUtil.signRS256(entraPayload, azureTestKey, { kid: 'azure-test-key-1', expiresInSeconds: 3600 })
    : jwtUtil.sign(entraPayload, getDemoSecret('JWT_SECRET'), { expiresInSeconds: 3600 }));

  // 3. Mint Google Cloud IAM / Google STS Subject Token (RS256 PKI - Option 3 Workload Identity Pool)
  const googlePrivateKey = jwtUtil.getGoogleStsPrivateKey();
  const gcpProjectNumber = process.env.GCP_PROJECT_NUMBER || '834200279688';
  const gcpProjectId = process.env.GCP_PROJECT_ID || 'wifdemoproject-507002';
  const gcpPoolId = process.env.GCP_POOL_ID || 'k8s-agent-pool';
  const gcpProviderId = process.env.GCP_PROVIDER_ID || 'spire-oidc-provider';
  const gcpAudience = `//iam.googleapis.com/projects/${gcpProjectNumber}/locations/global/workloadIdentityPools/${gcpPoolId}/providers/${gcpProviderId}`;

  const gcpPayload = {
    iss: 'https://sts.googleapis.com',
    aud: gcpAudience,
    sub: user.email,
    email: user.email,
    email_verified: true,
    name: user.displayName,
    roles: user.roles,
    scope: user.scopes.filter(s => s.startsWith('mcp:bigquery:')).join(' ') || 'mcp:bigquery:query',
    identityProvider: 'GoogleCloudIAM_WorkloadSTS',
    google_cloud_iam: {
      projectId: gcpProjectId,
      projectNumber: gcpProjectNumber,
      poolId: gcpPoolId,
      providerId: gcpProviderId,
      federationType: 'WorkloadIdentityFederation',
      principal: `principal://iam.googleapis.com/projects/${gcpProjectNumber}/locations/global/workloadIdentityPools/${gcpPoolId}/subject/${user.email}`
    }
  };

  const googleIamToken = googlePrivateKey
    ? jwtUtil.signRS256(gcpPayload, googlePrivateKey, { expiresInSeconds: 3600 })
    : jwtUtil.sign(gcpPayload, getDemoSecret('JWT_SECRET'), { expiresInSeconds: 3600 });

  return res.json({
    authenticated: true,
    user,
    token: keycloakToken, // Primary token used by orchestrator
    keycloakToken,
    entraToken,
    googleIamToken
  });
});

// Proxy Chat/Prompt to Agent Orchestrator
app.post('/api/chat', async (req, res) => {
  const { prompt, userEntraToken, entraToken } = req.body || {};
  let entraAssertion = null;

  if (!prompt) {
    return res.status(400).json({ error: 'Missing prompt.' });
  }

  // The bearer token comes from the server-side session in OIDC mode; a token supplied by the browser is ignored.
  // Without OIDC the legacy demo behaviour (token supplied by the page) exists only in the demo profile.
  let token = null;
  const login = app.locals.oidcLogin;
  if (login) {
    if (!login.sameOrigin(req)) return res.status(403).json({ error: 'CROSS_ORIGIN_REQUEST_REFUSED' });
    const session = login.getSession(req);
    if (!session) return res.status(401).json({ error: 'NOT_SIGNED_IN', signInUrl: '/auth/login' });
    token = await login.accessTokenFor(session);
    if (!token) return res.status(401).json({ error: 'SESSION_EXPIRED', signInUrl: '/auth/login' });
    // The Entra assertion comes from the server-side session only; one supplied by the browser is ignored.
    entraAssertion = app.locals.entraLogin ? await app.locals.entraLogin.accessTokenFor(session) : null;
  } else if (isSimulation()) {
    token = (req.body && req.body.token) || (req.headers.authorization ? req.headers.authorization.replace(/^Bearer\s+/i, '') : null);
    entraAssertion = userEntraToken || entraToken || req.headers['x-user-entra-token'] || null;
  } else {
    return res.status(503).json({ error: 'LOGIN_DISABLED', message: 'No login is configured and the demo profile is off.' });
  }

  const activeEntraToken = entraAssertion;
  const payload = JSON.stringify({
    prompt,
    userEntraToken: activeEntraToken,
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
  if (activeEntraToken) {
    headers['X-User-Entra-Token'] = activeEntraToken;
  }

  // If local test dispatcher injected, use it
  if (app.locals.agentDispatcher) {
    const result = await app.locals.agentDispatcher(prompt, token);
    return res.json(redactDeep(result));
  }

  const agentUrl = new URL('/api/agent/chat', AGENT_URL);

  const request = http.request(agentUrl, { method: 'POST', headers }, agentRes => {
    let data = '';
    agentRes.on('data', chunk => (data += chunk));
    agentRes.on('end', () => {
      try {
        res.status(agentRes.statusCode).json(redactDeep(JSON.parse(data)));
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
  assertStartupSafe('web-frontend', {
    realModeBlockers: app.locals.oidcLogin ? [] : ['OIDC_ISSUER and OIDC_CLIENT_ID are not set (no way to sign users in)']
  });
  app.listen(PORT, () => {
    console.log(`===========================================================`);
    console.log(` Web Frontend running on http://localhost:${PORT}`);
    console.log(` Architecture: OUTSIDE SPIRE (Browser-friendly)`);
    console.log(` Connected Agent: ${AGENT_URL}`);
    console.log(`===========================================================`);
  });
}

module.exports = app;
