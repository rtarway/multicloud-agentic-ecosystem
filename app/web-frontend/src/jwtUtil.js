// Zero-dependency RFC 7519 / RFC 7515 / RFC 8693 JWT Utility using Node.js built-in crypto
// Supports HS256 (HMAC symmetric) and RS256 (RSA asymmetric PKI)
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

function sign(payload, secret, options = {}) {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };

  const now = Math.floor(Date.now() / 1000);
  const fullPayload = {
    iat: now,
    exp: now + (options.expiresInSeconds || 3600),
    ...payload
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto
    .createHmac('sha256', secret)
    .update(dataToSign)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${dataToSign}.${signature}`;
}

function verify(token, secret) {
  if (!token || typeof token !== 'string') {
    throw new Error('Token must be a non-empty string.');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed JWT token: must have 3 parts.');
  }

  const [encodedHeader, encodedPayload, signature] = parts;
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(dataToSign)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  if (signature !== expectedSignature) {
    throw new Error('Invalid JWT signature.');
  }

  const payload = JSON.parse(base64UrlDecode(encodedPayload));
  const now = Math.floor(Date.now() / 1000);

  if (payload.exp && payload.exp < now) {
    throw new Error('JWT token has expired.');
  }

  return payload;
}

/**
 * Signs a JWT payload using RFC 7515 RS256 (Asymmetric RSA Private Key)
 */
function signRS256(payload, privateKeyPem, options = {}) {
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: options.kid || 'google-sts-key-1'
  };

  const now = Math.floor(Date.now() / 1000);
  const fullPayload = {
    iat: now,
    exp: now + (options.expiresInSeconds || 3600),
    ...payload
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(dataToSign);
  const signature = signer.sign(privateKeyPem, 'base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${dataToSign}.${signature}`;
}

/**
 * Verifies a JWT payload using RFC 7515 RS256 (Asymmetric RSA Public Key / Cert)
 */
function verifyRS256(token, publicKeyPem) {
  if (!token || typeof token !== 'string') {
    throw new Error('Token must be a non-empty string.');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed JWT token: must have 3 parts.');
  }

  const [encodedHeader, encodedPayload, signature] = parts;
  const header = JSON.parse(base64UrlDecode(encodedHeader));
  if (header.alg !== 'RS256') {
    throw new Error(`Invalid JWT algorithm: expected RS256, got '${header.alg}'. Asymmetric PKI is strictly required.`);
  }

  const dataToSign = `${encodedHeader}.${encodedPayload}`;
  let base64Sig = signature.replace(/-/g, '+').replace(/_/g, '/');
  while (base64Sig.length % 4) {
    base64Sig += '=';
  }

  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(dataToSign);
  const isValid = verifier.verify(publicKeyPem, base64Sig, 'base64');
  if (!isValid) {
    throw new Error('Invalid RS256 cryptographic signature.');
  }

  const payload = JSON.parse(base64UrlDecode(encodedPayload));
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    throw new Error('JWT token has expired.');
  }

  return payload;
}

// Cached Google STS keys
let _googlePublicKey = null;
let _googlePrivateKey = null;

function getGoogleStsPublicKey() {
  if (_googlePublicKey) return _googlePublicKey;
  if (process.env.GOOGLE_STS_PUBLIC_KEY) {
    _googlePublicKey = process.env.GOOGLE_STS_PUBLIC_KEY;
    return _googlePublicKey;
  }
  const possiblePaths = [
    path.resolve(__dirname, '../../../certs/google-sts-cert.pem'),
    path.resolve(__dirname, '../../certs/google-sts-cert.pem'),
    path.resolve(process.cwd(), 'certs/google-sts-cert.pem')
  ];
  for (const certPath of possiblePaths) {
    if (fs.existsSync(certPath)) {
      _googlePublicKey = fs.readFileSync(certPath, 'utf8');
      return _googlePublicKey;
    }
  }
  return null;
}

function getGoogleStsPrivateKey() {
  if (_googlePrivateKey) return _googlePrivateKey;
  if (process.env.GOOGLE_STS_PRIVATE_KEY) {
    _googlePrivateKey = process.env.GOOGLE_STS_PRIVATE_KEY;
    return _googlePrivateKey;
  }
  const possiblePaths = [
    path.resolve(__dirname, '../../../certs/google-sts-key.pem'),
    path.resolve(__dirname, '../../certs/google-sts-key.pem'),
    path.resolve(process.cwd(), 'certs/google-sts-key.pem')
  ];
  for (const keyPath of possiblePaths) {
    if (fs.existsSync(keyPath)) {
      _googlePrivateKey = fs.readFileSync(keyPath, 'utf8');
      return _googlePrivateKey;
    }
  }
  return null;
}

function decode(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    return JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    return null;
  }
}

module.exports = {
  sign,
  verify,
  signRS256,
  verifyRS256,
  getGoogleStsPublicKey,
  getGoogleStsPrivateKey,
  decode,
  base64UrlEncode,
  base64UrlDecode
};
