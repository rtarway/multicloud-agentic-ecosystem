// SPIFFE Workload API client (JWT-SVIDs) and JWT-SVID verification.
// Canonical copy: shared/spiffe.js; vendored into services by scripts/sync-shared.sh.
//
// The Workload API is gRPC over a unix socket. Only the single unary call needed here (FetchJWTSVID) is implemented,
// with a hand-rolled protobuf codec for its three small messages, so no gRPC dependency is required.
//   service SpiffeWorkloadAPI { rpc FetchJWTSVID(JWTSVIDRequest) returns (JWTSVIDResponse); }
//   message JWTSVIDRequest  { repeated string audience = 1; string spiffe_id = 2; }
//   message JWTSVIDResponse { repeated JWTSVID svids = 1; }
//   message JWTSVID         { string spiffe_id = 1; string svid = 2; string hint = 3; }

const http2 = require('http2');
const net = require('net');
const { verifyJwt, decodeJwt, OidcError } = require('./oidc');

class SpiffeError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SpiffeError';
    this.code = code;
  }
}

// ---- protobuf (length-delimited strings only) ----

function varint(n) {
  const out = [];
  while (n > 0x7f) { out.push((n & 0x7f) | 0x80); n >>>= 7; }
  out.push(n);
  return Buffer.from(out);
}

function field(num, value) {
  const bytes = Buffer.from(value, 'utf8');
  return Buffer.concat([varint((num << 3) | 2), varint(bytes.length), bytes]);
}

function encodeRequest(audience, spiffeId) {
  return Buffer.concat([...audience.map(a => field(1, a)), ...(spiffeId ? [field(2, spiffeId)] : [])]);
}

function readVarint(buf, pos) {
  let result = 0, shift = 0;
  for (;;) {
    if (pos >= buf.length) throw new SpiffeError('PROTOCOL', 'Truncated protobuf varint.');
    const b = buf[pos++];
    result |= (b & 0x7f) << shift;
    if (!(b & 0x80)) return [result >>> 0, pos];
    shift += 7;
  }
}

function decodeMessage(buf) {
  const fields = [];
  let pos = 0;
  while (pos < buf.length) {
    let tag;
    [tag, pos] = readVarint(buf, pos);
    if ((tag & 7) !== 2) throw new SpiffeError('PROTOCOL', 'Unexpected protobuf wire type.');
    let len;
    [len, pos] = readVarint(buf, pos);
    if (pos + len > buf.length) throw new SpiffeError('PROTOCOL', 'Truncated protobuf field.');
    fields.push({ num: tag >>> 3, bytes: buf.subarray(pos, pos + len) });
    pos += len;
  }
  return fields;
}

function decodeResponse(buf) {
  return decodeMessage(buf).filter(f => f.num === 1).map(f => {
    const svid = { spiffeId: '', svid: '', hint: '' };
    for (const inner of decodeMessage(f.bytes)) {
      if (inner.num === 1) svid.spiffeId = inner.bytes.toString('utf8');
      else if (inner.num === 2) svid.svid = inner.bytes.toString('utf8');
      else if (inner.num === 3) svid.hint = inner.bytes.toString('utf8');
    }
    return svid;
  });
}

// ---- gRPC framing ----

function grpcFrame(message) {
  const header = Buffer.alloc(5);
  header.writeUInt32BE(message.length, 1);
  return Buffer.concat([header, message]);
}

function grpcUnframe(buf) {
  if (buf.length < 5) throw new SpiffeError('PROTOCOL', 'gRPC response too short.');
  if (buf[0] !== 0) throw new SpiffeError('PROTOCOL', 'Compressed gRPC responses are not supported.');
  const len = buf.readUInt32BE(1);
  if (buf.length < 5 + len) throw new SpiffeError('PROTOCOL', 'Truncated gRPC response.');
  return buf.subarray(5, 5 + len);
}

/**
 * Fetches a JWT-SVID from the SPIRE agent's Workload API.
 * @param {{socketPath:string, audience:string[], spiffeId?:string, timeoutMs?:number}} opts
 * @returns {Promise<{spiffeId:string, token:string}>}
 */
function fetchJwtSvid({ socketPath, audience, spiffeId, timeoutMs = 5000 }) {
  if (!socketPath) return Promise.reject(new SpiffeError('CONFIG', 'No SPIRE agent socket path configured.'));
  if (!Array.isArray(audience) || audience.length === 0) return Promise.reject(new SpiffeError('CONFIG', 'At least one audience is required.'));

  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (fn, value) => { if (!settled) { settled = true; clearTimeout(timer); session.destroy(); fn(value); } };

    const session = http2.connect('http://localhost', { createConnection: () => net.connect(socketPath) });
    const timer = setTimeout(() => done(reject, new SpiffeError('TIMEOUT', 'SPIRE Workload API call timed out.')), timeoutMs);
    session.on('error', err => done(reject, new SpiffeError('CONNECT', `Cannot reach the SPIRE agent at ${socketPath}: ${err.message}`)));

    const req = session.request({
      ':method': 'POST',
      ':path': '/SpiffeWorkloadAPI/FetchJWTSVID',
      'content-type': 'application/grpc',
      te: 'trailers',
      'workload.spiffe.io': 'true'
    });
    const chunks = [];
    let grpcStatus = null, grpcMessage = '';
    req.on('data', c => chunks.push(c));
    req.on('trailers', t => { grpcStatus = t['grpc-status']; grpcMessage = t['grpc-message'] || ''; });
    req.on('response', h => { if (h['grpc-status'] !== undefined) { grpcStatus = h['grpc-status']; grpcMessage = h['grpc-message'] || ''; } });
    req.on('error', err => {
      const unreachable = err.cause && ['ENOENT', 'ECONNREFUSED', 'EACCES'].includes(err.cause.code);
      done(reject, unreachable
        ? new SpiffeError('CONNECT', `Cannot reach the SPIRE agent at ${socketPath}: ${err.cause.message}`)
        : new SpiffeError('CALL', err.message));
    });
    req.on('end', () => {
      try {
        if (grpcStatus !== null && String(grpcStatus) !== '0') {
          throw new SpiffeError('GRPC_ERROR', `SPIRE agent returned gRPC status ${grpcStatus}${grpcMessage ? `: ${decodeURIComponent(grpcMessage)}` : ''}.`);
        }
        const svids = decodeResponse(grpcUnframe(Buffer.concat(chunks)));
        if (svids.length === 0 || !svids[0].svid) throw new SpiffeError('NO_SVID', 'SPIRE agent returned no JWT-SVID.');
        const chosen = spiffeId ? svids.find(s => s.spiffeId === spiffeId) : svids[0];
        if (!chosen) throw new SpiffeError('NO_SVID', `SPIRE agent returned no JWT-SVID for ${spiffeId}.`);
        done(resolve, { spiffeId: chosen.spiffeId, token: chosen.svid });
      } catch (err) {
        done(reject, err);
      }
    });
    req.end(grpcFrame(encodeRequest(audience, spiffeId)));
  });
}

/**
 * Verifies a JWT-SVID presented by a peer: signature against the trust domain's published JWKS, issuer, audience
 * (this service's identifier), expiry, and that the SPIFFE ID (`sub`) is one of the allowed actors (exact match).
 * @returns {Promise<{spiffeId:string, payload:object}>}
 */
async function verifySvid(token, { issuer, audience, jwks, allowedSpiffeIds }) {
  let payload;
  try {
    payload = await verifyJwt(token, { issuer, audience, jwks });
  } catch (err) {
    if (err instanceof OidcError) throw new SpiffeError('SVID_INVALID', `JWT-SVID rejected: ${err.message}`);
    throw err;
  }
  if (typeof payload.sub !== 'string' || !payload.sub.startsWith('spiffe://')) {
    throw new SpiffeError('SVID_INVALID', 'JWT-SVID subject is not a SPIFFE ID.');
  }
  if (!allowedSpiffeIds.includes(payload.sub)) {
    throw new SpiffeError('SVID_NOT_ALLOWED', `SPIFFE ID '${payload.sub}' is not an allowed actor.`);
  }
  return { spiffeId: payload.sub, payload };
}

module.exports = {
  SpiffeError, fetchJwtSvid, verifySvid,
  // exported for tests
  encodeRequest, decodeMessage, decodeResponse, grpcFrame, grpcUnframe, field, decodeJwt
};
