const { test, describe } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createJwksClient, verifyJwt, OidcError, tokenScopes } = require('../oidc');
const { createIdp } = require('./helpers');

const AUD = 'agent-orchestrator-client';

function setup(overrides = {}) {
  const idp = createIdp();
  const jwks = createJwksClient({ issuer: idp.issuer, fetchJson: idp.fetchJson, ...overrides });
  const verify = (token, opts = {}) => verifyJwt(token, { issuer: idp.issuer, audience: AUD, jwks, ...opts });
  return { idp, jwks, verify };
}

const rejectsWith = (promise, code) => assert.rejects(promise, err => err instanceof OidcError && err.code === code, code);

describe('verifyJwt', () => {
  test('accepts a valid token and returns its claims', async () => {
    const { idp, verify } = setup();
    const payload = await verify(idp.sign({ sub: 'u1', aud: AUD, scope: 'openid mcp:tool1' }));
    assert.strictEqual(payload.sub, 'u1');
    assert.deepStrictEqual(tokenScopes(payload), ['openid', 'mcp:tool1']);
  });

  test('accepts an audience array that contains the expected audience', async () => {
    const { idp, verify } = setup();
    await verify(idp.sign({ sub: 'u1', aud: ['account', AUD] }));
  });

  test('rejects a wrong issuer, wrong or missing audience, and a substring audience', async () => {
    const { idp, verify } = setup();
    await rejectsWith(verify(idp.sign({ aud: AUD, iss: 'https://evil.test/realms/poc' })), 'BAD_ISSUER');
    await rejectsWith(verify(idp.sign({ aud: 'someone-else' })), 'BAD_AUDIENCE');
    await rejectsWith(verify(idp.sign({ aud: `${AUD}-evil` })), 'BAD_AUDIENCE');
    await rejectsWith(verify(idp.sign({ sub: 'u1' })), 'NO_AUDIENCE');
  });

  test('rejects expired, not-yet-valid and future-issued tokens, and tokens without exp', async () => {
    const { idp, verify } = setup();
    const now = Math.floor(Date.now() / 1000);
    await rejectsWith(verify(idp.sign({ aud: AUD, exp: now - 3600 })), 'EXPIRED');
    await rejectsWith(verify(idp.sign({ aud: AUD, nbf: now + 3600 })), 'NOT_YET_VALID');
    await rejectsWith(verify(idp.sign({ aud: AUD, iat: now + 3600 })), 'IAT_IN_FUTURE');
    const noExp = idp.sign({ aud: AUD });
    const [h, p, s] = noExp.split('.');
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    delete payload.exp;
    // re-sign without exp
    const input = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
    const token = `${input}.${crypto.sign('RSA-SHA256', Buffer.from(input), idp.privateKey).toString('base64url')}`;
    await rejectsWith(verify(token), 'NO_EXPIRY');
  });

  test('tolerates small clock skew', async () => {
    const { idp, verify } = setup();
    await verify(idp.sign({ aud: AUD, exp: Math.floor(Date.now() / 1000) - 10 }));
  });

  test('rejects alg=none, HS256 and any algorithm outside the allow-list', async () => {
    const { idp, verify } = setup();
    await rejectsWith(verify(idp.sign({ aud: AUD }, { alg: 'none' })), 'ALG_NOT_ALLOWED');
    await rejectsWith(verify(idp.sign({ aud: AUD }, { header: { alg: 'HS256' } })), 'ALG_NOT_ALLOWED');
    // HMAC "confusion": HS256 signed with the public key bytes must not verify either
    const input = `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: idp.kid })).toString('base64url')}.${Buffer.from(JSON.stringify({ iss: idp.issuer, aud: AUD, exp: Math.floor(Date.now() / 1000) + 60 })).toString('base64url')}`;
    const mac = crypto.createHmac('sha256', JSON.stringify(idp.jwks())).update(input).digest('base64url');
    await rejectsWith(verify(`${input}.${mac}`), 'ALG_NOT_ALLOWED');
  });

  test('rejects a tampered payload and a token signed by another key', async () => {
    const { idp, verify } = setup();
    const good = idp.sign({ sub: 'alice', aud: AUD });
    const [h, p, s] = good.split('.');
    const forgedPayload = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url').toString()), sub: 'admin' })).toString('base64url');
    await rejectsWith(verify(`${h}.${forgedPayload}.${s}`), 'BAD_SIGNATURE');

    const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    await rejectsWith(verify(idp.sign({ aud: AUD }, { key: other.privateKey })), 'BAD_SIGNATURE');
  });

  test('rejects malformed tokens', async () => {
    const { verify } = setup();
    for (const t of ['', 'abc', 'a.b', 'a.b.c.d', '..', null, undefined, 42]) {
      await assert.rejects(verify(t), err => err instanceof OidcError && err.code === 'MALFORMED');
    }
  });

  test('enforces authorized parties and required scopes when configured', async () => {
    const { idp, verify } = setup();
    const token = idp.sign({ aud: AUD, azp: 'web-frontend', scope: 'openid mcp:tool1' });
    await verify(token, { authorizedParties: ['web-frontend'], requiredScopes: ['openid'] });
    await rejectsWith(verify(token, { authorizedParties: ['other-client'] }), 'BAD_AUTHORIZED_PARTY');
    await rejectsWith(verify(token, { requiredScopes: ['mcp:tool2'] }), 'MISSING_SCOPE');
  });
});

describe('JWKS client', () => {
  test('caches keys and does not refetch for a known kid', async () => {
    const { idp, verify } = setup();
    await verify(idp.sign({ aud: AUD }));
    await verify(idp.sign({ aud: AUD }));
    assert.strictEqual(idp.fetchCount, 2, 'one discovery + one jwks fetch only');
  });

  test('picks up a rotated key via one rate-limited refetch', async () => {
    let clock = Date.now();
    const { idp, verify } = setup({ now: () => clock, minRefetchMs: 30_000 });
    await verify(idp.sign({ aud: AUD }), { now: () => clock });
    const next = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    idp.addKey('key-2', next.publicKey);
    const rotated = idp.sign({ aud: AUD }, { key: next.privateKey, header: { kid: 'key-2' } });

    // within the rate-limit window: unknown kid is rejected without hammering the IdP
    const before = idp.fetchCount;
    await rejectsWith(verify(rotated, { now: () => clock }), 'UNKNOWN_KEY');
    assert.strictEqual(idp.fetchCount, before);

    clock += 31_000;
    await verify(rotated, { now: () => clock });
  });

  test('refuses a discovery document whose issuer does not match', async () => {
    const jwks = createJwksClient({
      issuer: 'https://idp.test/realms/poc',
      fetchJson: async () => ({ issuer: 'https://evil.test', jwks_uri: 'https://evil.test/jwks' })
    });
    await rejectsWith(jwks.getKey('x'), 'DISCOVERY');
  });

  test('can use an explicit jwksUri (in-cluster URL) without discovery', async () => {
    const idp = createIdp();
    const seen = [];
    const jwks = createJwksClient({ jwksUri: 'http://keycloak.internal/certs', fetchJson: async url => { seen.push(url); return idp.jwks(); } });
    await verifyJwt(idp.sign({ aud: AUD }), { issuer: idp.issuer, audience: AUD, jwks });
    assert.deepStrictEqual(seen, ['http://keycloak.internal/certs']);
  });
});
