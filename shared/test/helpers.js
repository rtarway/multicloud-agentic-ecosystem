// Test helpers: an in-memory identity provider (RSA keys + JWKS) and a fake SPIRE Workload API server.
const crypto = require('crypto');
const http2 = require('http2');
const fs = require('fs');
const os = require('os');
const path = require('path');
const spiffe = require('../spiffe');

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function createIdp({ issuer = 'https://idp.test/realms/poc', kid = 'key-1' } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const keys = new Map([[kid, publicKey]]);
  const idp = {
    issuer, kid, privateKey, fetchCount: 0,
    jwks() {
      return { keys: [...keys].map(([k, pub]) => ({ ...pub.export({ format: 'jwk' }), kid: k, use: 'sig', alg: 'RS256' })) };
    },
    addKey(newKid, pub) { keys.set(newKid, pub); },
    // fetchJson stand-in serving discovery + jwks
    fetchJson: async url => {
      idp.fetchCount++;
      if (url === `${issuer}/.well-known/openid-configuration`) return { issuer, jwks_uri: `${issuer}/protocol/openid-connect/certs` };
      if (url === `${issuer}/protocol/openid-connect/certs`) return idp.jwks();
      throw new Error(`unexpected URL ${url}`);
    },
    sign(claims, { header = {}, key = privateKey, alg = 'RS256' } = {}) {
      const now = Math.floor(Date.now() / 1000);
      const payload = { iss: issuer, iat: now, exp: now + 300, ...claims };
      const h = { alg, typ: 'JWT', kid, ...header };
      const input = `${b64url(JSON.stringify(h))}.${b64url(JSON.stringify(payload))}`;
      const sig = alg === 'none' ? '' : crypto.sign('RSA-SHA256', Buffer.from(input), key).toString('base64url');
      return `${input}.${sig}`;
    }
  };
  return idp;
}

/** Fake SPIRE agent: serves FetchJWTSVID on a unix socket. `handler(audience, spiffeId)` returns [{spiffeId, svid}] or throws. */
function startFakeSpireAgent(handler) {
  const socketPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'spire-')), 'agent.sock');
  const calls = [];
  const server = http2.createServer();
  server.on('stream', (stream, headers) => {
    const chunks = [];
    stream.on('data', c => chunks.push(c));
    stream.on('end', () => {
      calls.push({ path: headers[':path'], workloadHeader: headers['workload.spiffe.io'] });
      try {
        const fields = spiffe.decodeMessage(spiffe.grpcUnframe(Buffer.concat(chunks)));
        const audience = fields.filter(f => f.num === 1).map(f => f.bytes.toString('utf8'));
        const idField = fields.find(f => f.num === 2);
        const svids = handler(audience, idField ? idField.bytes.toString('utf8') : undefined);
        const body = Buffer.concat(svids.map(s => {
          const inner = Buffer.concat([spiffe.field(1, s.spiffeId), spiffe.field(2, s.svid)]);
          return Buffer.concat([Buffer.from([0x0a, inner.length]), inner]);
        }));
        stream.respond({ ':status': 200, 'content-type': 'application/grpc' }, { waitForTrailers: true });
        stream.on('wantTrailers', () => stream.sendTrailers({ 'grpc-status': '0' }));
        stream.end(spiffe.grpcFrame(body));
      } catch (err) {
        stream.respond({ ':status': 200, 'content-type': 'application/grpc' }, { waitForTrailers: true });
        stream.on('wantTrailers', () => stream.sendTrailers({ 'grpc-status': '7', 'grpc-message': encodeURIComponent(err.message) }));
        stream.end();
      }
    });
  });
  return new Promise(resolve => server.listen(socketPath, () => resolve({
    socketPath, calls,
    close: () => new Promise(r => server.close(() => { try { fs.rmSync(path.dirname(socketPath), { recursive: true, force: true }); } catch {} r(); }))
  })));
}

module.exports = { createIdp, startFakeSpireAgent, b64url };
