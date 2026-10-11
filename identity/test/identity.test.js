// Tests for the POC identity seed: users.yaml validation, the generated map, the identity-mapping module,
// the consistency checker and the offboard plan. All offline (live checkers are replaced by fakes).

const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const { loadUsersYaml, validate, buildMap, MAP_JSON } = require('../lib/directory');
const { createResolver, IdentityMappingError } = require('../../shared/identityMapping');
const { offlineChecks, liveChecks, expectedGoogleGrants } = require('../../scripts/identity-check');
const { buildPlan, run } = require('../../scripts/identity-offboard');

const clone = o => JSON.parse(JSON.stringify(o));
const doc = loadUsersYaml();

describe('identity/users.yaml', () => {
  test('is valid and defines the three POC personas', () => {
    assert.deepStrictEqual(validate(doc), []);
    assert.deepStrictEqual(doc.users.map(u => u.id), ['alice', 'bob', 'charlie']);
  });

  test('contains no passwords or secrets', () => {
    const raw = fs.readFileSync(path.join(__dirname, '..', 'users.yaml'), 'utf8')
      .split('\n').filter(line => !line.trim().startsWith('#')).join('\n');
    assert.ok(!/password\s*:/i.test(raw));
    assert.ok(!/secret\s*:/i.test(raw));
  });

  test('rejects duplicate emails, unknown groups and missing Google accounts for BigQuery users', () => {
    const bad = clone(doc);
    bad.users[1].emails.keycloak = bad.users[0].emails.keycloak;
    bad.users[1].groups.push('no-such-group');
    delete bad.users[0].emails.google;
    const errors = validate(bad).join('\n');
    assert.match(errors, /used by another user/);
    assert.match(errors, /unknown group 'no-such-group'/);
    assert.match(errors, /Google account .* is required/);
  });

  test('rejects an Entra UPN outside the configured tenant domain', () => {
    const bad = clone(doc);
    bad.users[0].emails.entra_upn = 'alice@other-tenant.example';
    assert.match(validate(bad).join('\n'), /must be in/);
  });

  test('the committed identity-map.json is in sync with users.yaml', () => {
    assert.strictEqual(fs.readFileSync(MAP_JSON, 'utf8'), JSON.stringify(buildMap(doc), null, 2) + '\n');
  });

  test('the generated map carries no secrets', () => {
    const rendered = JSON.stringify(buildMap(doc));
    assert.ok(!/password|secret|token/i.test(rendered));
  });
});

describe('identity mapping (fails closed)', () => {
  const resolver = createResolver(buildMap(doc));
  const claimsFor = (u, extra = {}) => ({ email: u.emails.keycloak, email_verified: true, ...extra });

  test('resolves a verified Keycloak identity to the Entra and Google identities', () => {
    const alice = doc.users.find(u => u.id === 'alice');
    const identity = resolver.resolveFromClaims(claimsFor(alice));
    assert.strictEqual(identity.id, 'alice');
    assert.strictEqual(identity.entraUpn, alice.emails.entra_upn);
    assert.strictEqual(identity.googleEmail, alice.emails.google);
    assert.ok(identity.groups.includes('agent-bigquery-audit'));
    assert.strictEqual(resolver.requireGoogleEmail(identity), alice.emails.google);
    assert.strictEqual(resolver.requireEntraUpn(identity), alice.emails.entra_upn);
  });

  test('email matching is case- and whitespace-insensitive', () => {
    const bob = doc.users.find(u => u.id === 'bob');
    const identity = resolver.resolveFromClaims({ email: `  ${bob.emails.keycloak.toUpperCase()} `, email_verified: true });
    assert.strictEqual(identity.id, 'bob');
  });

  test('rejects unverified, missing and unknown emails', () => {
    const bob = doc.users.find(u => u.id === 'bob');
    for (const [claims, code] of [
      [{ email: bob.emails.keycloak, email_verified: false }, 'IDENTITY_EMAIL_UNVERIFIED'],
      [{ email: bob.emails.keycloak }, 'IDENTITY_EMAIL_UNVERIFIED'],
      [{ email_verified: true }, 'IDENTITY_EMAIL_MISSING'],
      [{ email: 'mallory@evil.example', email_verified: true }, 'IDENTITY_NOT_MAPPED'],
      [null, 'IDENTITY_CLAIMS_MISSING']
    ]) {
      assert.throws(() => resolver.resolveFromClaims(claims), err => err instanceof IdentityMappingError && err.code === code, code);
    }
  });

  test('does not fall back to sub or preferred_username when email is absent', () => {
    assert.throws(() => resolver.resolveFromClaims({ sub: 'alice', preferred_username: 'alice', email_verified: true }), /IDENTITY_EMAIL_MISSING|no email claim/);
  });

  test('a user without a Google account never resolves a Google identity', () => {
    const charlie = doc.users.find(u => u.id === 'charlie');
    const identity = resolver.resolveFromClaims(claimsFor(charlie));
    assert.strictEqual(identity.googleEmail, null);
    assert.throws(() => resolver.requireGoogleEmail(identity), err => err.code === 'IDENTITY_NO_GOOGLE_MAPPING');
  });

  test('a disabled (deprovisioned) user does not resolve', () => {
    const disabled = clone(buildMap(doc));
    disabled.users.find(u => u.id === 'bob').enabled = false;
    const bob = doc.users.find(u => u.id === 'bob');
    assert.throws(() => createResolver(disabled).resolveFromClaims(claimsFor(bob)), err => err.code === 'IDENTITY_DISABLED');
  });

  test('ambiguous directories are rejected at load time', () => {
    const dup = clone(buildMap(doc));
    dup.users[1].emails.google = dup.users[0].emails.google;
    assert.throws(() => createResolver(dup), err => err.code === 'DIRECTORY_AMBIGUOUS');
    const dupKc = clone(buildMap(doc));
    dupKc.users[1].emails.keycloak = dupKc.users[0].emails.keycloak;
    assert.throws(() => createResolver(dupKc), err => err.code === 'DIRECTORY_AMBIGUOUS');
  });

  test('a Google account only matches the mapped user (prevents linking someone else\'s account)', () => {
    const alice = resolver.resolveFromClaims(claimsFor(doc.users.find(u => u.id === 'alice')));
    const bobGoogle = doc.users.find(u => u.id === 'bob').emails.google;
    assert.strictEqual(resolver.googleAccountMatches(alice, { email: alice.googleEmail, email_verified: true }), true);
    assert.strictEqual(resolver.googleAccountMatches(alice, { email: bobGoogle, email_verified: true }), false);
    assert.strictEqual(resolver.googleAccountMatches(alice, { email: alice.googleEmail, email_verified: false }), false);
    assert.strictEqual(resolver.googleAccountMatches(alice, null), false);
  });

  test('loads the committed identity-map.json from disk', () => {
    const fromDisk = createResolver(MAP_JSON);
    const bob = doc.users.find(u => u.id === 'bob');
    assert.strictEqual(fromDisk.resolveFromClaims(claimsFor(bob)).id, 'bob');
  });

  test('vendored copies in the services are identical to shared/identityMapping.js', () => {
    const canonical = fs.readFileSync(path.join(__dirname, '../../shared/identityMapping.js'), 'utf8');
    for (const svc of ['agent-orchestrator', 'gcp-mcp-server', 'mcp-server']) {
      assert.strictEqual(fs.readFileSync(path.join(__dirname, `../../app/${svc}/src/identityMapping.js`), 'utf8'), canonical, svc);
    }
  });
});

describe('consistency checker', () => {
  const mapContents = JSON.stringify(buildMap(doc), null, 2) + '\n';

  test('passes offline for the committed seed', () => {
    assert.deepStrictEqual(offlineChecks(doc, mapContents), []);
  });

  test('flags a stale generated map', () => {
    const problems = offlineChecks(doc, '{}');
    assert.ok(problems.some(p => p.system === 'identity-map.json'));
  });

  test('derives expected Google grants from groups and drops them for disabled users', () => {
    const bob = doc.users.find(u => u.id === 'bob');
    assert.deepStrictEqual(expectedGoogleGrants(doc, bob), [{ dataset: 'analytics_data', role: 'roles/bigquery.dataViewer' }]);
    assert.deepStrictEqual(expectedGoogleGrants(doc, { ...bob, enabled: false }), []);
    assert.deepStrictEqual(expectedGoogleGrants(doc, doc.users.find(u => u.id === 'charlie')), []);
  });

  function checkersFor(overrides = {}) {
    return {
      keycloak: async u => ({ found: true, enabled: u.enabled !== false, email: u.emails.keycloak }),
      entra: async u => ({ found: true, enabled: u.enabled !== false }),
      google: async (u, expected) => ({ grants: expected }),
      ...overrides
    };
  }

  test('live mode passes when all three systems match', async () => {
    assert.deepStrictEqual(await liveChecks(doc, checkersFor()), []);
  });

  test('live mode reports a missing Keycloak user, a disabled Entra user and a missing/extra Google grant', async () => {
    const problems = await liveChecks(doc, checkersFor({
      keycloak: async u => (u.id === 'bob' ? { found: false } : { found: true, enabled: true, email: u.emails.keycloak }),
      entra: async u => ({ found: true, enabled: u.id !== 'alice' }),
      google: async (u, expected) => (u.id === 'alice'
        ? { grants: expected.slice(1) }
        : { grants: [...expected, ...(u.id === 'bob' ? [{ dataset: 'audit_logs', role: 'roles/bigquery.dataViewer' }] : [])] })
    }));
    const text = problems.map(p => `${p.system}:${p.user}:${p.problem}`).join('\n');
    assert.match(text, /keycloak:bob:user not found/);
    assert.match(text, /entra:alice:accountEnabled=false, expected true/);
    assert.match(text, /google:alice:missing/);
    assert.match(text, /google:bob:unexpected roles\/bigquery.dataViewer on dataset audit_logs/);
  });

  test('live mode expects disabled users to be disabled and to hold no grants', async () => {
    const offboarded = clone(doc);
    offboarded.users.find(u => u.id === 'bob').enabled = false;
    const problems = await liveChecks(offboarded, checkersFor({
      keycloak: async u => ({ found: true, enabled: true, email: u.emails.keycloak }),
      google: async (u, expected) => ({ grants: u.id === 'bob' ? [{ dataset: 'analytics_data', role: 'roles/bigquery.dataViewer' }] : expected })
    }));
    const text = problems.map(p => `${p.system}:${p.user}:${p.problem}`).join('\n');
    assert.match(text, /keycloak:bob:enabled=true, expected false/);
    assert.match(text, /google:bob:unexpected/);
  });
});

describe('offboarding', () => {
  test('plans terraform applies in all three roots, a Keycloak logout and a purge notice', () => {
    const plan = buildPlan('bob', doc, {});
    assert.deepStrictEqual(plan.steps.map(s => s.kind), ['terraform', 'terraform', 'terraform', 'keycloak-logout', 'notice']);
    assert.ok(plan.steps[0].args.includes('-var=offboard_users=["bob"]'));
  });

  test('plans the purge call when GRANT_PURGE_URL is configured', () => {
    const plan = buildPlan('bob', doc, { GRANT_PURGE_URL: 'https://gcp-mcp.example/admin/purge' });
    assert.strictEqual(plan.steps.at(-1).kind, 'purge');
  });

  test('rejects unknown users', () => {
    assert.throws(() => buildPlan('mallory', doc, {}), /Unknown user/);
  });

  test('executes terraform, ends sessions and purges grants through injected dependencies', async () => {
    const calls = [];
    const env = { KEYCLOAK_URL: 'http://kc', KEYCLOAK_ADMIN_USER: 'a', KEYCLOAK_ADMIN_PASSWORD: 'p', GRANT_PURGE_URL: 'http://purge/x', GRANT_PURGE_TOKEN: 't' };
    const fakeFetch = async (url, opts = {}) => {
      calls.push(`${opts.method || 'GET'} ${url}`);
      const json = url.includes('/protocol/openid-connect/token') ? { access_token: 'admin-token' } : [{ id: 'kc-uuid' }];
      return { ok: true, status: 200, json: async () => json };
    };
    const execCalls = [];
    await run(buildPlan('bob', doc, env), { exec: (cmd, args) => execCalls.push([cmd, ...args]), fetch: fakeFetch, log: () => {} }, env);
    assert.strictEqual(execCalls.length, 3);
    assert.ok(execCalls.every(c => c[0] === 'terraform'));
    assert.ok(calls.some(c => c.startsWith('POST') && c.endsWith('/users/kc-uuid/logout')));
    assert.ok(calls.includes('POST http://purge/x'));
  });

  test('refuses to end sessions without Keycloak admin credentials in the environment', async () => {
    await assert.rejects(
      () => run(buildPlan('bob', doc, {}), { exec: () => {}, fetch: async () => ({ ok: true, json: async () => ({}) }), log: () => {} }, {}),
      /KEYCLOAK_URL/
    );
  });
});
