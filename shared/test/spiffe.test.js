const { test, describe, after } = require('node:test');
const assert = require('node:assert');
const spiffe = require('../spiffe');
const { createJwksClient } = require('../oidc');
const { createIdp, startFakeSpireAgent } = require('./helpers');

const ORCH = 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa';

describe('protobuf / gRPC framing', () => {
  test('request and response round trip', () => {
    const req = spiffe.encodeRequest(['gcp-mcp', 'azure-mcp'], ORCH);
    const fields = spiffe.decodeMessage(req);
    assert.deepStrictEqual(fields.filter(f => f.num === 1).map(f => f.bytes.toString()), ['gcp-mcp', 'azure-mcp']);
    assert.strictEqual(fields.find(f => f.num === 2).bytes.toString(), ORCH);
  });

  test('framing rejects truncated and compressed frames', () => {
    assert.throws(() => spiffe.grpcUnframe(Buffer.from([0, 0, 0])), /too short/);
    assert.throws(() => spiffe.grpcUnframe(Buffer.from([1, 0, 0, 0, 0])), /Compressed/);
    assert.throws(() => spiffe.grpcUnframe(Buffer.from([0, 0, 0, 0, 9, 1])), /Truncated/);
  });
});

describe('fetchJwtSvid (against a fake SPIRE agent)', () => {
  const agents = [];
  after(async () => { await Promise.all(agents.map(a => a.close())); });

  test('requests the right audience and returns the SVID', async () => {
    const agent = await startFakeSpireAgent((audience) => [{ spiffeId: ORCH, svid: `svid-for-${audience.join(',')}` }]);
    agents.push(agent);
    const svid = await spiffe.fetchJwtSvid({ socketPath: agent.socketPath, audience: ['gcp-mcp-server'] });
    assert.strictEqual(svid.spiffeId, ORCH);
    assert.strictEqual(svid.token, 'svid-for-gcp-mcp-server');
    assert.strictEqual(agent.calls[0].path, '/SpiffeWorkloadAPI/FetchJWTSVID');
    assert.strictEqual(agent.calls[0].workloadHeader, 'true');
  });

  test('surfaces gRPC errors from the agent', async () => {
    const agent = await startFakeSpireAgent(() => { throw new Error('no identity issued'); });
    agents.push(agent);
    await assert.rejects(spiffe.fetchJwtSvid({ socketPath: agent.socketPath, audience: ['x'] }), err => err.code === 'GRPC_ERROR' && /no identity issued/.test(err.message));
  });

  test('fails when the agent returns no SVID or the wrong SPIFFE ID', async () => {
    const empty = await startFakeSpireAgent(() => []);
    agents.push(empty);
    await assert.rejects(spiffe.fetchJwtSvid({ socketPath: empty.socketPath, audience: ['x'] }), err => err.code === 'NO_SVID');
    const other = await startFakeSpireAgent(() => [{ spiffeId: 'spiffe://example.org/other', svid: 't' }]);
    agents.push(other);
    await assert.rejects(spiffe.fetchJwtSvid({ socketPath: other.socketPath, audience: ['x'], spiffeId: ORCH }), err => err.code === 'NO_SVID');
  });

  test('fails fast when the socket does not exist or no audience is given', async () => {
    await assert.rejects(spiffe.fetchJwtSvid({ socketPath: '/nonexistent/agent.sock', audience: ['x'], timeoutMs: 2000 }), err => err.code === 'CONNECT');
    await assert.rejects(spiffe.fetchJwtSvid({ socketPath: '/x', audience: [] }), err => err.code === 'CONFIG');
    await assert.rejects(spiffe.fetchJwtSvid({ audience: ['x'] }), err => err.code === 'CONFIG');
  });
});

describe('verifySvid', () => {
  const issuer = 'https://spire.test';
  const setup = () => {
    const idp = createIdp({ issuer, kid: 'spire-key' });
    return { idp, jwks: createJwksClient({ issuer, fetchJson: idp.fetchJson }) };
  };
  const opts = jwks => ({ issuer, audience: 'gcp-mcp-server', jwks, allowedSpiffeIds: [ORCH] });

  test('accepts an SVID for an allowed SPIFFE ID and audience', async () => {
    const { idp, jwks } = setup();
    const result = await spiffe.verifySvid(idp.sign({ sub: ORCH, aud: ['gcp-mcp-server'] }), opts(jwks));
    assert.strictEqual(result.spiffeId, ORCH);
  });

  test('rejects exact-match violations: sibling workload, prefix tricks, wrong audience, non-SPIFFE subject', async () => {
    const { idp, jwks } = setup();
    for (const [claims, code] of [
      [{ sub: 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa-evil', aud: ['gcp-mcp-server'] }, 'SVID_NOT_ALLOWED'],
      [{ sub: 'spiffe://example.org/ns/agent-system/sa/other', aud: ['gcp-mcp-server'] }, 'SVID_NOT_ALLOWED'],
      [{ sub: ORCH, aud: ['azure-mcp-server'] }, 'SVID_INVALID'],
      [{ sub: 'alice@example.com', aud: ['gcp-mcp-server'] }, 'SVID_INVALID']
    ]) {
      await assert.rejects(spiffe.verifySvid(idp.sign(claims), opts(jwks)), err => err.code === code, JSON.stringify(claims));
    }
  });

  test('rejects an SVID signed by a different trust domain key', async () => {
    const { jwks } = setup();
    const attacker = createIdp({ issuer, kid: 'spire-key' });
    await assert.rejects(spiffe.verifySvid(attacker.sign({ sub: ORCH, aud: ['gcp-mcp-server'] }), opts(jwks)), err => err.code === 'SVID_INVALID');
  });
});
