// Unit and Integration Tests for Low-Code Declarative MCP Server
// Uses Node.js native test runner (node:test, node:assert) with in-process Express execution

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { Readable, Writable } = require('stream');
const jwtUtil = require('../src/jwtUtil');
const app = require('../src/index');

const TEST_SECRET = 'demo-obo-token-secret-key-2026';

function mintOboToken({ sub, actSub, scopes, roles }) {
  return jwtUtil.sign(
    {
      sub,
      email: sub,
      roles: roles || (sub?.includes('alice') ? ['auditor', 'Storage Blob Data Reader'] : ['regular-user']),
      act: {
        sub: actSub || 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa'
      },
      scope: Array.isArray(scopes) ? scopes.join(' ') : scopes
    },
    TEST_SECRET,
    { expiresInSeconds: 300 }
  );
}

function invokeApp(appInstance, { method = 'POST', url = '/mcp', headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const req = new Readable();
    req._read = () => {};
    req.method = method;
    req.url = url;

    const data = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : '';
    req.headers = {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(data).toString(),
      ...headers
    };

    let responseData = '';
    const res = new Writable();
    res.statusCode = 200;
    res._headers = {};
    res.setHeader = (k, v) => { res._headers[k.toLowerCase()] = v; };
    res.getHeader = (k) => res._headers[k.toLowerCase()];
    res._write = (chunk, enc, cb) => {
      responseData += chunk.toString();
      cb();
    };
    res.writeHead = (code, headers = {}) => {
      res.statusCode = code;
      Object.assign(res._headers, headers);
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
  test('MCP initialize handshake negotiates protocol version 2026-07-15', async () => {
    const res = await rpcRequest('initialize', { protocolVersion: '2026-07-15' });
    assert.strictEqual(res.jsonrpc, '2.0');
    assert.ok(res.result, 'Response must have result');
    assert.strictEqual(res.result.protocolVersion, '2026-07-15');
    assert.strictEqual(res.result.serverInfo.name, 'azure-lowcode-mcp-server');
  });

  test('MCP tools/list returns declarative tools (tool1 and tool2)', async () => {
    const res = await rpcRequest('tools/list', {});
    assert.strictEqual(res.jsonrpc, '2.0');
    assert.ok(Array.isArray(res.result.tools));
    assert.strictEqual(res.result.tools.length, 2);

    const toolNames = res.result.tools.map(t => t.name);
    assert.ok(toolNames.includes('tool1'), 'Must include tool1');
    assert.ok(toolNames.includes('tool2'), 'Must include tool2');
  });

  test('Regular User (Bob): Tool-level RBAC passes (mcp:tool1), but Cloud IAM denies storage access (HTTP 403 / AuthorizationPermissionMismatch)', async () => {
    const bobToken = mintOboToken({
      sub: 'bob@example.com',
      actSub: 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
      scopes: ['mcp:tool1'],
      roles: ['regular-user'] // Bob has NO storage RBAC role
    });

    // 1. Read app1 -> Fails at Layer 2 Cloud Native IAM
    const readRes = await rpcRequest(
      'tools/call',
      {
        name: 'tool1',
        arguments: { container: 'app1', action: 'read', filename: 'financial-report.json' }
      },
      bobToken
    );

    assert.strictEqual(readRes.result.isError, true);
    assert.strictEqual(readRes.result.cloudIAMDecision, 'DENIED_BY_AZURE_STORAGE_IAM');
    assert.ok(readRes.result.content[0].text.includes('Azure Storage Cloud IAM Access Denied (HTTP 403)'));
    assert.strictEqual(readRes.result.audit.decision, 'DENIED_BY_AZURE_STORAGE_IAM');
  });

  test('Regular User (Bob): Fails tool2 with native MCP Error (isError: true, lacks mcp:tool2)', async () => {
    // Bob has only mcp:tool1 scope
    const bobToken = mintOboToken({
      sub: 'bob@example.com',
      actSub: 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
      scopes: ['mcp:tool1']
    });

    const res = await rpcRequest(
      'tools/call',
      {
        name: 'tool2',
        arguments: { container: 'app1', action: 'read', filename: 'financial-report.json' }
      },
      bobToken
    );

    // Native MCP error handling (instead of raw 403)
    assert.strictEqual(res.result.isError, true);
    assert.ok(res.result.content[0].text.includes('MCP Authorization Denied'));
    assert.ok(res.result.content[0].text.includes("lacks required scope 'mcp:tool2'"));
    assert.strictEqual(res.result.audit.decision, 'DENIED_BY_POLICY');
    assert.strictEqual(res.result.audit.principal, 'bob@example.com');
    assert.strictEqual(res.result.audit.actingAgent, 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa');
  });

  test('Administrator (Alice): Can execute both tool1 and tool2', async () => {
    // Alice has both mcp:tool1 and mcp:tool2
    const aliceToken = mintOboToken({
      sub: 'alice@example.com',
      actSub: 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
      scopes: ['mcp:tool1', 'mcp:tool2']
    });

    // tool1
    const res1 = await rpcRequest(
      'tools/call',
      {
        name: 'tool1',
        arguments: { container: 'app2', action: 'read', filename: 'customer-metrics.json' }
      },
      aliceToken
    );
    assert.strictEqual(res1.result.isError, false);

    // tool2 (restricted to app1 read-only)
    const res2 = await rpcRequest(
      'tools/call',
      {
        name: 'tool2',
        arguments: { container: 'app1', action: 'read', filename: 'compliance.txt' }
      },
      aliceToken
    );
    assert.strictEqual(res2.result.isError, false);
    assert.ok(res2.result.content[0].text.includes('ISO27001'));
  });

  test('Tool2 rejects write attempts or invalid container (strictly app1 read-only)', async () => {
    const aliceToken = mintOboToken({
      sub: 'alice@example.com',
      scopes: ['mcp:tool1', 'mcp:tool2']
    });

    // Try write on tool2
    const writeRes = await rpcRequest(
      'tools/call',
      {
        name: 'tool2',
        arguments: { container: 'app1', action: 'write', filename: 'test.txt' }
      },
      aliceToken
    );
    assert.strictEqual(writeRes.result.isError, true);
    assert.ok(writeRes.result.content[0].text.includes("Invalid parameter 'action'"));

    // Try app2 on tool2
    const app2Res = await rpcRequest(
      'tools/call',
      {
        name: 'tool2',
        arguments: { container: 'app2', action: 'read', filename: 'test.txt' }
      },
      aliceToken
    );
    assert.strictEqual(app2Res.result.isError, true);
    assert.ok(app2Res.result.content[0].text.includes("Invalid parameter 'container'"));
  });

  test('Missing Authorization header returns MCP authentication error', async () => {
    const res = await rpcRequest('tools/call', {
      name: 'tool1',
      arguments: { container: 'app1', action: 'read', filename: 'config.yaml' }
    });

    assert.strictEqual(res.result.isError, true);
    assert.ok(res.result.content[0].text.includes('MCP Authentication Failure'));
  });

  test('FGP in tools.yaml: Denies write to compliance or audit files (in-process FGP)', async () => {
    const token = mintOboToken({
      sub: 'alice@example.com',
      scopes: ['mcp:tool1']
    });

    const res = await rpcRequest(
      'tools/call',
      {
        name: 'tool1',
        arguments: { container: 'app1', action: 'write', filename: 'compliance-bypass.txt', content: 'fake' }
      },
      token
    );

    assert.strictEqual(res.result.isError, true);
    assert.ok(res.result.content[0].text.includes('immutable and cannot be overwritten'));
    assert.strictEqual(res.result.audit.decision, 'DENIED_BY_FGP');
  });

  test('FGP in tools.yaml: Denies unsupported file extension (.exe)', async () => {
    const token = mintOboToken({
      sub: 'alice@example.com',
      scopes: ['mcp:tool1']
    });

    const res = await rpcRequest(
      'tools/call',
      {
        name: 'tool1',
        arguments: { container: 'app1', action: 'read', filename: 'malicious.exe' }
      },
      token
    );

    assert.strictEqual(res.result.isError, true);
    assert.ok(res.result.content[0].text.includes('Only .json, .txt, and .yaml files are permitted'));
    assert.strictEqual(res.result.audit.decision, 'DENIED_BY_FGP');
  });

  test('JIT User Delegation: Operation dynamically mints 60s JIT credential with SHA-256 chain fingerprint binding', async () => {
    const token = mintOboToken({
      sub: 'alice@example.com',
      scopes: ['mcp:tool1'],
      roles: ['auditor', 'Storage Blob Data Reader']
    });

    const res = await rpcRequest(
      'tools/call',
      {
        name: 'tool1',
        arguments: { container: 'app1', action: 'read', filename: 'financial-report.json' }
      },
      token
    );

    assert.strictEqual(res.result.isError, false);
    const parsedData = JSON.parse(res.result.content[0].text);
    assert.ok(parsedData.data.delegationMeta, 'Response must include JIT delegation metadata');
    assert.strictEqual(parsedData.data.delegationMeta.credentialType, 'JIT_USER_DELEGATION_CREDENTIAL');
    assert.strictEqual(parsedData.data.delegationMeta.permissions, 'r');
    assert.strictEqual(parsedData.data.delegationMeta.ttlSeconds, 60);
    assert.ok(parsedData.data.delegationMeta.chainFingerprint);
    assert.ok(parsedData.data.delegationMeta.correlationId);
  });

  test('RFC 8693 Cryptographic Delegation Chain: Rejects tokens with untrusted or rogue actors', async () => {
    const rogueToken = jwtUtil.sign(
      {
        sub: 'alice@example.com',
        aud: 'api://d5850aa0-a667-41c3-8dd0-16f2dee4da25',
        act: {
          sub: 'untrusted-bad-actor-proxy'
        },
        scope: 'mcp:tool1'
      },
      TEST_SECRET,
      { expiresInSeconds: 300 }
    );

    const res = await rpcRequest(
      'tools/call',
      {
        name: 'tool1',
        arguments: { container: 'app1', action: 'read', filename: 'financial-report.json' }
      },
      rogueToken
    );

    assert.strictEqual(res.result.isError, true);
    assert.ok(res.result.content[0].text.includes('RFC 8693 Cryptographic chain verification failed'));
  });

  test('Azure WIF & Entra ID Protection: Validates Microsoft Entra token with app roles and delegated user identity', async () => {
    const entraToken = jwtUtil.sign({
      iss: 'https://login.microsoftonline.com/81f26b58-159c-4879-80a0-bab30b5b4dd3/v2.0',
      tid: '81f26b58-159c-4879-80a0-bab30b5b4dd3',
      aud: 'api://d5850aa0-a667-41c3-8dd0-16f2dee4da25',
      sub: 'a23206e1-2dda-4854-aac7-0536d2da2c4c',
      appid: 'a23206e1-2dda-4854-aac7-0536d2da2c4c',
      roles: ['mcp:tool1']
    }, TEST_SECRET, { expiresInSeconds: 300 });

    const delegatedUserHeader = JSON.stringify({
      sub: 'alice@example.com',
      email: 'alice@example.com',
      roles: ['auditor', 'Storage Blob Data Reader']
    });

    const res = await rpcRequest(
      'tools/call',
      {
        name: 'tool1',
        arguments: { container: 'app1', action: 'read', filename: 'financial-report.json' }
      },
      entraToken,
      { 'x-delegated-identity': delegatedUserHeader }
    );

    assert.strictEqual(res.result.isError, false);
    assert.strictEqual(res.result.audit.principal, 'alice@example.com');
    assert.strictEqual(res.result.audit.actingAgent, 'entra://a23206e1-2dda-4854-aac7-0536d2da2c4c');
    assert.strictEqual(res.result.audit.decision, 'ALLOWED');
  });
});

