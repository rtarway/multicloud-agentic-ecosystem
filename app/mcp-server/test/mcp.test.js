// Unit and Integration Tests for Low-Code Declarative MCP Server
// Uses Node.js native test runner (node:test, node:assert) with in-process Express execution

// Demo profile: tokens are signed with locally generated demo keys and storage may use its in-memory fixture.
process.env.ALLOW_SIMULATION = 'true';
process.env.STORAGE_OFFLINE = 'true';
process.env.IDENTITY_MAP_PATH = require('path').resolve(__dirname, '../../../identity/identity-map.json');

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { Readable, Writable } = require('stream');
const jwtUtil = require('../src/jwtUtil');
const app = require('../src/index');

const azureTestKey = jwtUtil.getAzureTestKey();

const ORCH_APP = 'a23206e1-2dda-4854-aac7-0536d2da2c4c';
const ORCH_SPIFFE = 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa';
const ALICE = 'alice@rtarwaygmail.onmicrosoft.com';
const BOB = 'bob@rtarwaygmail.onmicrosoft.com';
const CHARLIE = 'charlie@rtarwaygmail.onmicrosoft.com';

// An Entra-shaped, user-delegated token for the Azure MCP server, signed with the demo key
function mintOboToken({ upn, actSub, scp, appid = ORCH_APP, extra = {} }) {
  const payload = {
    iss: 'https://login.microsoftonline.com/81f26b58-159c-4879-80a0-bab30b5b4dd3/v2.0',
    tid: '81f26b58-159c-4879-80a0-bab30b5b4dd3',
    aud: 'api://d5850aa0-a667-41c3-8dd0-16f2dee4da25',
    sub: `entra-sub-${upn}`,
    oid: `oid-${upn}`,
    upn,
    appid,
    scp: Array.isArray(scp) ? scp.join(' ') : scp,
    ...(actSub ? { act: { sub: actSub } } : {}),
    ...extra
  };
  return jwtUtil.signRS256(payload, azureTestKey, { kid: 'azure-test-key-1', expiresInSeconds: 300 });
}

function invokeApp(appInstance, { method = 'POST', url = '/mcp', headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const req = new Readable();
    req._read = () => {};
    req.method = method;
    req.url = url;

    const normalizedHeaders = {};
    for (const [k, v] of Object.entries(headers)) {
      normalizedHeaders[k.toLowerCase()] = v;
    }

    const data = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : '';
    req.headers = {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(data).toString(),
      ...normalizedHeaders
    };

    let responseData = '';
    const res = new Writable();
    res.statusCode = 200;
    res._headers = {};
    res.setHeader = (k, v) => { res._headers[k.toLowerCase()] = v; };
    res.getHeader = (k) => res._headers[k.toLowerCase()];
    res.removeHeader = (k) => { delete res._headers[k.toLowerCase()]; };
    res.writeHead = (code, h = {}) => {
      res.statusCode = code;
      Object.assign(res._headers, h);
    };
    res._write = (chunk, enc, cb) => {
      responseData += chunk.toString();
      cb();
    };
    res.end = (chunk) => {
      if (chunk) responseData += chunk.toString();
      try {
        resolve({ statusCode: res.statusCode, body: JSON.parse(responseData) });
      } catch {
        resolve({ statusCode: res.statusCode, body: responseData });
      }
    };

    appInstance.handle(req, res, reject);

    process.nextTick(() => {
      if (data) req.push(data);
      req.push(null);
    });
  });
}

async function rpcRequest(method, params, token, extraHeaders = {}) {
  const headers = { ...extraHeaders };
  if (token) {
    headers['authorization'] = `Bearer ${token}`;
  }

  const res = await invokeApp(app, {
    method: 'POST',
    url: '/mcp',
    headers,
    body: {
      jsonrpc: '2.0',
      id: 'test-req-1',
      method,
      params
    }
  });

  return res.body;
}

describe('Azure Low-Code MCP Server Tests (Protocol Spec July 2026)', () => {
  const call = (token, args, tool = 'tool1', headers = {}) => rpcRequest('tools/call', { name: tool, arguments: args }, token, headers);

  test('MCP initialize handshake negotiates protocol version 2026-07-15', async () => {
    const res = await rpcRequest('initialize', { protocolVersion: '2026-07-15' });
    assert.strictEqual(res.jsonrpc, '2.0');
    assert.ok(res.result, 'Response must have result');
    assert.strictEqual(res.result.protocolVersion, '2026-07-15');
    assert.strictEqual(res.result.serverInfo.name, 'azure-lowcode-mcp-server');
  });

  test('MCP tools/list returns declarative tools (tool1 and tool2)', async () => {
    const res = await rpcRequest('tools/list', {});
    assert.ok(Array.isArray(res.result.tools));
    assert.strictEqual(res.result.tools.length, 2);
    const toolNames = res.result.tools.map(t => t.name);
    assert.ok(toolNames.includes('tool1') && toolNames.includes('tool2'));
  });

  test('Missing Authorization header returns MCP authentication error', async () => {
    const res = await call(null, { container: 'app1', action: 'read', filename: 'config.yaml' });
    assert.strictEqual(res.result.isError, true);
    assert.ok(res.result.content[0].text.includes('MCP Authentication Failure'));
  });

  // ---- delegated scope per operation ----

  test('A token without the exact delegated scope is refused by the MCP layer (Bob has only ReadApp2)', async () => {
    const bob = mintOboToken({ upn: BOB, actSub: ORCH_SPIFFE, scp: ['Mcp.Storage.ReadApp2'] });
    const res = await call(bob, { container: 'app1', action: 'read', filename: 'financial-report.json' });
    assert.strictEqual(res.result.isError, true);
    assert.ok(res.result.content[0].text.includes("lacks required scope 'Mcp.Storage.ReadApp1'"));
    assert.strictEqual(res.result.audit.decision, 'DENIED_BY_POLICY');
    assert.strictEqual(res.result.audit.requiredScope, 'Mcp.Storage.ReadApp1');
    assert.strictEqual(res.result.audit.principal, BOB);
    assert.strictEqual(res.result.audit.actingAgent, ORCH_SPIFFE);
  });

  test('Read and write need different scopes: ReadApp2 does not allow a write to app2', async () => {
    const bob = mintOboToken({ upn: BOB, scp: ['Mcp.Storage.ReadApp2'] });
    const res = await call(bob, { container: 'app2', action: 'write', filename: 'agent-notes.txt', content: 'x' });
    assert.strictEqual(res.result.isError, true);
    assert.strictEqual(res.result.audit.requiredScope, 'Mcp.Storage.WriteApp2');
  });

  test('The legacy broad user_impersonation scope grants nothing', async () => {
    const token = mintOboToken({ upn: ALICE, scp: ['user_impersonation'] });
    const res = await call(token, { container: 'app2', action: 'read', filename: 'customer-metrics.json' });
    assert.strictEqual(res.result.isError, true);
    assert.strictEqual(res.result.audit.decision, 'DENIED_BY_POLICY');
  });

  test('App-only tokens (roles, no scp) are rejected', async () => {
    const token = mintOboToken({ upn: ALICE, scp: undefined, extra: { roles: ['Mcp.Storage.ReadApp1'], idtyp: 'app' } });
    const res = await call(token, { container: 'app1', action: 'read', filename: 'financial-report.json' });
    assert.strictEqual(res.result.isError, true);
    assert.ok(res.result.content[0].text.includes('delegated user token'));
  });

  // ---- Azure RBAC decides (emulated from the identity directory in the demo profile) ----

  test('Scope is not enough: Bob holds ReadApp1 but has no Azure role on app1 -> 403 from storage', async () => {
    const bob = mintOboToken({ upn: BOB, actSub: ORCH_SPIFFE, scp: ['Mcp.Storage.ReadApp1'] });
    const res = await call(bob, { container: 'app1', action: 'read', filename: 'financial-report.json' });
    assert.strictEqual(res.result.isError, true);
    assert.strictEqual(res.result.cloudIAMDecision, 'DENIED_BY_AZURE_STORAGE_IAM');
    assert.ok(res.result.content[0].text.includes('Azure Storage Cloud IAM Access Denied (HTTP 403)'));
    assert.strictEqual(res.result.audit.decision, 'DENIED_BY_AZURE_STORAGE_IAM');
  });

  test('Alice (Reader on app1 and app2) can read both containers, tool1 and tool2', async () => {
    const alice = mintOboToken({ upn: ALICE, actSub: ORCH_SPIFFE, scp: ['Mcp.Storage.ReadApp1', 'Mcp.Storage.ReadApp2'] });
    const r1 = await call(alice, { container: 'app2', action: 'read', filename: 'customer-metrics.json' });
    assert.strictEqual(r1.result.isError, false);
    const r2 = await call(alice, { container: 'app1', action: 'read', filename: 'compliance.txt' }, 'tool2');
    assert.strictEqual(r2.result.isError, false);
    assert.ok(r2.result.content[0].text.includes('ISO27001'));
  });

  test('Write needs a Contributor role too: Alice holds WriteApp2 but is only a Reader -> 403; Bob (Contributor on app2) may write', async () => {
    const alice = mintOboToken({ upn: ALICE, scp: ['Mcp.Storage.WriteApp2'] });
    const denied = await call(alice, { container: 'app2', action: 'write', filename: 'notes.txt', content: 'x' });
    assert.strictEqual(denied.result.isError, true);
    assert.strictEqual(denied.result.cloudIAMDecision, 'DENIED_BY_AZURE_STORAGE_IAM');

    const bob = mintOboToken({ upn: BOB, scp: ['Mcp.Storage.WriteApp2', 'Mcp.Storage.WriteApp1'] });
    const ok = await call(bob, { container: 'app2', action: 'write', filename: 'agent-notes.txt', content: 'hello' });
    assert.strictEqual(ok.result.isError, false);
    const wrongContainer = await call(bob, { container: 'app1', action: 'write', filename: 'agent-notes.txt', content: 'hello' });
    assert.strictEqual(wrongContainer.result.cloudIAMDecision, 'DENIED_BY_AZURE_STORAGE_IAM');
  });

  test('Nothing is decided from names: a look-alike user with every scope but no directory entry is denied', async () => {
    const mallory = mintOboToken({ upn: 'alice@evil.example', scp: ['Mcp.Storage.ReadApp1', 'Mcp.Storage.ReadApp2', 'Mcp.Storage.WriteApp1', 'Mcp.Storage.WriteApp2'] });
    const res = await call(mallory, { container: 'app1', action: 'read', filename: 'financial-report.json' });
    assert.strictEqual(res.result.isError, true);
    assert.strictEqual(res.result.cloudIAMDecision, 'DENIED_BY_AZURE_STORAGE_IAM');
  });

  test('Charlie (Reader on both, no write role) cannot write even with the write scope', async () => {
    const charlie = mintOboToken({ upn: CHARLIE, scp: ['Mcp.Storage.WriteApp1'] });
    const res = await call(charlie, { container: 'app1', action: 'write', filename: 'notes.txt', content: 'x' });
    assert.strictEqual(res.result.cloudIAMDecision, 'DENIED_BY_AZURE_STORAGE_IAM');
  });

  // ---- declarative constraints ----

  test('Tool2 rejects write attempts or invalid container (strictly app1 read-only)', async () => {
    const alice = mintOboToken({ upn: ALICE, scp: ['Mcp.Storage.ReadApp1', 'Mcp.Storage.ReadApp2', 'Mcp.Storage.WriteApp1'] });
    const writeRes = await call(alice, { container: 'app1', action: 'write', filename: 'test.txt' }, 'tool2');
    assert.strictEqual(writeRes.result.isError, true);
    assert.ok(writeRes.result.content[0].text.includes("Invalid parameter 'action'"));
    const app2Res = await call(alice, { container: 'app2', action: 'read', filename: 'test.txt' }, 'tool2');
    assert.strictEqual(app2Res.result.isError, true);
    assert.ok(app2Res.result.content[0].text.includes("Invalid parameter 'container'"));
  });

  test('Blob names are single safe path segments: traversal and separators are rejected', async () => {
    const alice = mintOboToken({ upn: ALICE, scp: ['Mcp.Storage.ReadApp1', 'Mcp.Storage.ReadApp2'] });
    for (const filename of ['../app2/customer-metrics.json', 'a/b.json', '..\\x.json', '.hidden.json', 'x'.repeat(200) + '.json', 'bad name.json']) {
      const res = await call(alice, { container: 'app1', action: 'read', filename });
      assert.strictEqual(res.result.isError, true, filename);
      assert.ok(res.result.content[0].text.includes("Invalid parameter 'filename'"), filename);
    }
  });

  test('FGP in tools.yaml: Denies write to compliance or audit files (in-process FGP)', async () => {
    const token = mintOboToken({ upn: ALICE, scp: ['Mcp.Storage.WriteApp1'] });
    const res = await call(token, { container: 'app1', action: 'write', filename: 'compliance-bypass.txt', content: 'fake' });
    assert.strictEqual(res.result.isError, true);
    assert.ok(res.result.content[0].text.includes('immutable and cannot be overwritten'));
    assert.strictEqual(res.result.audit.decision, 'DENIED_BY_FGP');
  });

  test('FGP in tools.yaml: Denies unsupported file extension (.exe)', async () => {
    const token = mintOboToken({ upn: ALICE, scp: ['Mcp.Storage.ReadApp1'] });
    const res = await call(token, { container: 'app1', action: 'read', filename: 'malicious.exe' });
    assert.strictEqual(res.result.isError, true);
    assert.ok(res.result.content[0].text.includes('Only .json, .txt, and .yaml files are permitted'));
    assert.strictEqual(res.result.audit.decision, 'DENIED_BY_FGP');
  });

  test('FGP: tool2 cannot read credential-like files', async () => {
    const token = mintOboToken({ upn: ALICE, scp: ['Mcp.Storage.ReadApp1'] });
    const res = await call(token, { container: 'app1', action: 'read', filename: 'secret-key.json' }, 'tool2');
    assert.strictEqual(res.result.audit.decision, 'DENIED_BY_FGP');
  });

  // ---- access record (no pseudo "JIT delegation") ----

  test('The result records how storage was accessed: the user\'s own identity, decided by RBAC; no minted credential', async () => {
    const token = mintOboToken({ upn: ALICE, actSub: ORCH_SPIFFE, scp: ['Mcp.Storage.ReadApp1'] });
    const res = await call(token, { container: 'app1', action: 'read', filename: 'financial-report.json' });
    assert.strictEqual(res.result.isError, false);
    const parsed = JSON.parse(res.result.content[0].text);
    const meta = parsed.data.accessMeta;
    assert.ok(meta, 'accessMeta present');
    assert.strictEqual(meta.permissions, 'r');
    assert.strictEqual(meta.userUpn, ALICE);
    assert.ok(meta.correlationId);
    assert.ok(/EMULATED_RBAC/.test(meta.credentialType), 'the demo profile says it is emulated');
    assert.strictEqual(parsed.data.delegationMeta, undefined);
    assert.ok(!JSON.stringify(parsed).includes('JIT_USER_DELEGATION'));
    assert.strictEqual(parsed.audit.authorizedScope, 'Mcp.Storage.ReadApp1');
  });

  // ---- caller-supplied identity and delegation chain ----

  test('RFC 8693 Cryptographic Delegation Chain: Rejects tokens with untrusted or rogue actors', async () => {
    const rogue = mintOboToken({ upn: ALICE, actSub: 'spiffe://rogue-cluster.evil.com/ns/hack/sa/rogue-pod', scp: ['Mcp.Storage.ReadApp1'] });
    const res = await call(rogue, { container: 'app1', action: 'read', filename: 'financial-report.json' });
    assert.strictEqual(res.result.isError, true);
    assert.ok(res.result.content[0].text.includes('RFC 8693 Cryptographic chain verification failed'));
  });

  test('The user comes from the token; a forged X-Delegated-Identity header grants nothing', async () => {
    const bob = mintOboToken({ upn: BOB, scp: ['Mcp.Storage.ReadApp1'] });
    const forged = JSON.stringify({ sub: ALICE, email: ALICE, roles: ['admin', 'Storage Blob Data Reader'] });
    const res = await call(bob, { container: 'app1', action: 'read', filename: 'financial-report.json' }, 'tool1', { 'x-delegated-identity': forged });
    assert.strictEqual(res.result.isError, true);
    assert.strictEqual(res.result.audit.principal, BOB);
    assert.ok(!JSON.stringify(res.result).includes(ALICE));
  });

  test('Audience is mandatory and compared exactly', async () => {
    const base = { upn: ALICE, scp: ['Mcp.Storage.ReadApp1'] };
    const noAud = mintOboToken({ ...base, extra: { aud: undefined } });
    const r1 = await call(noAud, { container: 'app1', action: 'read', filename: 'financial-report.json' });
    assert.ok(r1.result.content[0].text.includes('aud claim is required'));
    const wrong = mintOboToken({ ...base, extra: { aud: 'api://attacker-app' } });
    const r2 = await call(wrong, { container: 'app1', action: 'read', filename: 'financial-report.json' });
    assert.ok(r2.result.content[0].text.includes('audience verification failed'));
  });

  test('Issuer must match the configured tenant exactly (lookalike microsoftonline hosts rejected)', async () => {
    const token = mintOboToken({ upn: ALICE, scp: ['Mcp.Storage.ReadApp1'], extra: { iss: 'https://login.microsoftonline.com.attacker.example/81f26b58-159c-4879-80a0-bab30b5b4dd3/v2.0' } });
    const res = await call(token, { container: 'app1', action: 'read', filename: 'financial-report.json' });
    assert.ok(res.result.content[0].text.includes('issuer verification failed'));
  });

  test('Without simulation: demo-signed tokens are rejected and no storage fixture is served', async () => {
    const previousSim = process.env.ALLOW_SIMULATION;
    process.env.ALLOW_SIMULATION = 'false';
    try {
      const token = mintOboToken({ upn: ALICE, scp: ['Mcp.Storage.ReadApp1'] });
      const res = await call(token, { container: 'app1', action: 'read', filename: 'financial-report.json' });
      assert.strictEqual(res.result.isError, true);
      const storage = require('../src/azureStorage');
      await assert.rejects(() => storage.listBlobs('app1'), err => err.code === 'SIMULATION_DISABLED');
      assert.strictEqual(require('../src/jwtUtil').getAzureTestKey(), null);
    } finally {
      process.env.ALLOW_SIMULATION = previousSim;
    }
  });
});
