// Real-mode storage access: the user's own Storage token (OBO with a federated client assertion), no shared credentials.

process.env.ALLOW_SIMULATION = 'false';

const { test, describe, beforeEach } = require('node:test');
const assert = require('node:assert');
const { createStorageTokenProvider, StorageAuthError, STORAGE_SCOPE } = require('../src/storageTokens');
const { getClientAssertion, hasFederatedSource, AssertionError } = require('../src/federatedAssertion');
const { AzureStorageService } = require('../src/azureStorage');

const jwt = claims => `h.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.s`;
const USER_ASSERTION = jwt({ aud: 'api://mcp', oid: 'oid-bob', upn: 'bob@rtarwaygmail.onmicrosoft.com' });
const STORAGE_TOKEN = jwt({ aud: 'https://storage.azure.com', oid: 'oid-bob', exp: Math.floor(Date.now() / 1000) + 3600 });
const ENV = { ENTRA_TENANT_ID: 'tenant-1', ENTRA_CLIENT_ID: 'mcp-app-id' };

const entraOk = body => ({ ok: true, status: 200, json: async () => body });
const entraFail = (status, body) => ({ ok: false, status, json: async () => body });

describe('storage on-behalf-of token provider', () => {
  let calls;
  beforeEach(() => { calls = []; });

  const provider = (response, overrides = {}) => createStorageTokenProvider({
    env: ENV,
    assertionProvider: async () => 'federated-assertion',
    fetchImpl: async (url, opts) => { calls.push({ url, params: Object.fromEntries(opts.body) }); return response; },
    ...overrides
  });

  test('exchanges the incoming user token for a Storage token with a client assertion and no client secret', async () => {
    const result = await provider(entraOk({ access_token: STORAGE_TOKEN })).acquire(USER_ASSERTION);
    assert.strictEqual(result.token, STORAGE_TOKEN);
    const { url, params } = calls[0];
    assert.strictEqual(url, 'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token');
    assert.strictEqual(params.grant_type, 'urn:ietf:params:oauth:grant-type:jwt-bearer');
    assert.strictEqual(params.requested_token_use, 'on_behalf_of');
    assert.strictEqual(params.assertion, USER_ASSERTION);
    assert.strictEqual(params.scope, STORAGE_SCOPE);
    assert.strictEqual(params.client_id, 'mcp-app-id');
    assert.strictEqual(params.client_assertion, 'federated-assertion');
    assert.strictEqual(params.client_assertion_type, 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    assert.strictEqual(params.client_secret, undefined);
  });

  test('maps a Conditional Access / MFA challenge to INTERACTION_REQUIRED with the claims to replay', async () => {
    await assert.rejects(
      provider(entraFail(400, { error: 'interaction_required', claims: '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}' })).acquire(USER_ASSERTION),
      err => err instanceof StorageAuthError && err.code === 'INTERACTION_REQUIRED' && err.claims.includes('acrs')
    );
  });

  test('other Entra rejections are OBO_REJECTED; network failures are ENTRA_UNREACHABLE', async () => {
    await assert.rejects(provider(entraFail(400, { error: 'invalid_grant' })).acquire(USER_ASSERTION), err => err.code === 'OBO_REJECTED');
    const unreachable = createStorageTokenProvider({ env: ENV, assertionProvider: async () => 'a', fetchImpl: async () => { throw new Error('ECONNREFUSED'); } });
    await assert.rejects(unreachable.acquire(USER_ASSERTION), err => err.code === 'ENTRA_UNREACHABLE');
  });

  test('rejects a token that is not for Storage, or that belongs to a different user', async () => {
    await assert.rejects(provider(entraOk({ access_token: jwt({ aud: 'api://other', oid: 'oid-bob' }) })).acquire(USER_ASSERTION), err => err.code === 'BAD_TOKEN');
    await assert.rejects(provider(entraOk({ access_token: jwt({ aud: 'https://storage.azure.com', oid: 'oid-mallory' }) })).acquire(USER_ASSERTION), err => err.code === 'IDENTITY_MISMATCH');
  });

  test('fails closed without configuration or without a federated credential source', async () => {
    await assert.rejects(createStorageTokenProvider({ env: {}, assertionProvider: async () => 'a' }).acquire(USER_ASSERTION), err => err.code === 'NOT_CONFIGURED');
    const noSource = createStorageTokenProvider({ env: ENV, assertionProvider: async () => { throw new AssertionError('none'); }, fetchImpl: async () => { throw new Error('must not call Entra'); } });
    await assert.rejects(noSource.acquire(USER_ASSERTION), err => err.code === 'CLIENT_ASSERTION_UNAVAILABLE');
  });
});

describe('federated client assertion sources', () => {
  test('App Service managed identity: asks the identity endpoint for the token-exchange audience', async () => {
    let seen;
    const token = await getClientAssertion({
      env: { IDENTITY_ENDPOINT: 'http://169.254.129.4:8081/msi/token', IDENTITY_HEADER: 'secret-header', AZURE_MI_CLIENT_ID: 'mi-client' },
      fetchImpl: async (url, opts) => { seen = { url: new URL(url), headers: opts.headers }; return { ok: true, json: async () => ({ access_token: 'mi-token' }) }; }
    });
    assert.strictEqual(token, 'mi-token');
    assert.strictEqual(seen.url.searchParams.get('resource'), 'api://AzureADTokenExchange');
    assert.strictEqual(seen.url.searchParams.get('client_id'), 'mi-client');
    assert.strictEqual(seen.headers['X-IDENTITY-HEADER'], 'secret-header');
  });

  test('Kubernetes workload identity: reads the projected token file', async () => {
    const token = await getClientAssertion({ env: { AZURE_FEDERATED_TOKEN_FILE: '/var/run/secrets/azure/tokens/azure-identity-token' }, readFile: () => 'file-token\n' });
    assert.strictEqual(token, 'file-token');
  });

  test('no source, or a refusing endpoint, is an error (there is no secret fallback)', async () => {
    assert.strictEqual(hasFederatedSource({}), false);
    assert.strictEqual(hasFederatedSource({ IDENTITY_ENDPOINT: 'x', IDENTITY_HEADER: 'y' }), true);
    await assert.rejects(getClientAssertion({ env: { AZURE_CLIENT_SECRET: 'ignored' } }), AssertionError);
    await assert.rejects(getClientAssertion({ env: { IDENTITY_ENDPOINT: 'http://x/', IDENTITY_HEADER: 'y' }, fetchImpl: async () => ({ ok: false, status: 400 }) }), AssertionError);
  });
});

describe('Azure Storage data plane with the user\'s own token', () => {
  const upstream = { tokens: { acquire: async () => ({ token: STORAGE_TOKEN, expiresAt: Date.now() + 3600e3 }) } };
  const authContext = { email: 'bob@rtarwaygmail.onmicrosoft.com', rawToken: USER_ASSERTION, correlationId: 'corr-1', actorChain: ['spiffe://example.org/ns/agent-system/sa/orchestrator-sa'] };

  function service(storageResponse, extra = {}) {
    const requests = [];
    const svc = new AzureStorageService({
      ...upstream, ...extra, baseUrl: 'http://storage.test',
      fetchImpl: async (url, init) => { requests.push({ url, init }); return storageResponse; }
    });
    return { svc, requests };
  }
  const blob = (status, text = '') => ({ status, ok: status >= 200 && status < 300, text: async () => text, headers: { get: () => null } });

  test('reads with the Storage token only: the caller\'s token is never forwarded; no key, SAS or actor header', async () => {
    const { svc, requests } = service(blob(200, '{"ok":true}'));
    const result = await svc.readBlob('app2', 'customer-metrics.json', authContext);
    assert.strictEqual(result.content, '{"ok":true}');
    assert.strictEqual(requests[0].url, 'http://storage.test/app2/customer-metrics.json');
    assert.strictEqual(requests[0].init.method, 'GET');
    assert.strictEqual(requests[0].init.headers.authorization, `Bearer ${STORAGE_TOKEN}`);
    assert.ok(!JSON.stringify(requests[0].init.headers).includes(USER_ASSERTION));
    assert.strictEqual(requests[0].init.headers['x-actor-chain'], undefined);
    assert.ok(!requests[0].url.includes('sig='), 'no SAS');
    assert.strictEqual(result.accessMeta.credentialType, 'ENTRA_OBO_USER_TOKEN');
  });

  test('writes as a block blob with the Storage token', async () => {
    const { svc, requests } = service(blob(201));
    const result = await svc.writeBlob('app2', 'agent-notes.txt', 'hello', authContext);
    assert.strictEqual(requests[0].init.method, 'PUT');
    assert.strictEqual(requests[0].init.headers['x-ms-blob-type'], 'BlockBlob');
    assert.strictEqual(result.bytesWritten, 5);
  });

  test('a 403 from Azure Storage is final: Azure RBAC denied this user', async () => {
    const { svc } = service(blob(403));
    await assert.rejects(svc.readBlob('app1', 'financial-report.json', authContext), err => err.statusCode === 403 && err.code === 'AuthorizationPermissionMismatch');
  });

  test('token acquisition failures surface; they never fall back to an emulation outside the demo profile', async () => {
    for (const code of ['CLIENT_ASSERTION_UNAVAILABLE', 'ENTRA_UNREACHABLE', 'OBO_REJECTED', 'INTERACTION_REQUIRED']) {
      const svc = new AzureStorageService({
        tokens: { acquire: async () => { throw new StorageAuthError(code, `boom ${code}`, { claims: code === 'INTERACTION_REQUIRED' ? '{"c":1}' : null }); } },
        fetchImpl: async () => { throw new Error('storage must not be called'); }
      });
      await assert.rejects(svc.readBlob('app1', 'financial-report.json', authContext), err => err.code === code);
    }
  });

  test('a network failure to storage is an error, not a fixture', async () => {
    const svc = new AzureStorageService({ ...upstream, baseUrl: 'http://storage.test', fetchImpl: async () => { throw new Error('fetch failed'); } });
    await assert.rejects(svc.readBlob('app1', 'financial-report.json', authContext), /fetch failed/);
  });

  test('blob names that are not a single safe segment never reach the network', async () => {
    const { svc, requests } = service(blob(200));
    for (const name of ['../x.json', 'a/b.json', '%2e%2e%2fx.json']) {
      await assert.rejects(svc.readBlob('app1', name, authContext), err => err.statusCode === 400, name);
    }
    assert.strictEqual(requests.length, 0);
  });
});

describe('engine: Conditional Access challenge from storage becomes a step-up result', () => {
  test('an INTERACTION_REQUIRED from the OBO exchange is returned with the claims challenge, not as a generic failure', async () => {
    const azureStorage = require('../src/azureStorage');
    const DeclarativeEngine = require('../src/declarativeEngine');
    azureStorage.configure({
      tokens: { acquire: async () => { throw new StorageAuthError('INTERACTION_REQUIRED', 'MFA needed', { claims: '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}' }); } },
      fetchImpl: async () => { throw new Error('storage must not be called'); }
    });
    const engine = new DeclarativeEngine();
    const result = await engine.executeTool('tool1', { container: 'app1', action: 'read', filename: 'financial-report.json' }, {
      sub: 'alice@rtarwaygmail.onmicrosoft.com', email: 'alice@rtarwaygmail.onmicrosoft.com', scopes: ['Mcp.Storage.ReadApp1'], rawToken: USER_ASSERTION, actorChain: []
    });
    assert.strictEqual(result.isError, true);
    assert.strictEqual(result.stepUp.required, true);
    assert.ok(result.stepUp.claims.includes('acrs'));
    assert.strictEqual(result.audit.decision, 'STEP_UP_REQUIRED');
  });
});
