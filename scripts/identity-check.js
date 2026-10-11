#!/usr/bin/env node
// Consistency check for the POC identity seed.
//
//   node scripts/identity-check.js            offline: validate identity/users.yaml, the generated map and the
//                                             identity-mapping round trip (no network, no credentials)
//   node scripts/identity-check.js --live     also verify every user exists, with the right enabled state, in
//                                             Keycloak, Microsoft Entra ID and (BigQuery grants) Google Cloud
//
// Live mode reads credentials from the environment only:
//   Keycloak : KEYCLOAK_URL, KEYCLOAK_ADMIN_USER, KEYCLOAK_ADMIN_PASSWORD
//   Entra    : an authenticated `az` CLI (az login)
//   Google   : an authenticated `bq` CLI (gcloud auth login) and GCP_PROJECT_ID
// Exit code is non-zero if anything is missing, disabled/enabled incorrectly, or unmapped.

const fs = require('fs');
const { execFileSync } = require('child_process');
const { loadUsersYaml, validate, buildMap, MAP_JSON } = require('../identity/lib/directory');
const { createResolver } = require('../shared/identityMapping');

const LEGACY_ROLE = { 'roles/bigquery.dataViewer': 'READER', 'roles/bigquery.dataEditor': 'WRITER', 'roles/bigquery.dataOwner': 'OWNER' };

/** Datasets/roles a user should hold in Google, derived from their groups. */
function expectedGoogleGrants(doc, user) {
  if (user.enabled === false) return [];
  const grants = [];
  for (const gid of user.groups || []) {
    const g = (doc.groups || []).find(x => x.id === gid);
    for (const b of (g && g.bigquery) || []) grants.push({ dataset: b.dataset, role: b.role });
  }
  return grants;
}

/** Offline checks: structure, generated-map freshness, and identity-mapping round trip. */
function offlineChecks(doc, mapFileContents) {
  const problems = validate(doc).map(message => ({ system: 'users.yaml', user: '-', problem: message }));
  if (problems.length > 0) return problems;

  const expectedMap = JSON.stringify(buildMap(doc), null, 2) + '\n';
  if (mapFileContents !== expectedMap) {
    problems.push({ system: 'identity-map.json', user: '-', problem: 'generated map is missing or stale (run scripts/identity-build-map.js)' });
  }

  const resolver = createResolver(buildMap(doc));
  for (const u of doc.users) {
    const claims = { email: u.emails.keycloak, email_verified: true };
    try {
      const identity = resolver.resolveFromClaims(claims);
      if (identity.id !== u.id || identity.entraUpn !== u.emails.entra_upn.toLowerCase()) {
        problems.push({ system: 'mapping', user: u.id, problem: 'resolved to a different identity than users.yaml declares' });
      }
      if (u.emails.google && identity.googleEmail !== u.emails.google.toLowerCase()) {
        problems.push({ system: 'mapping', user: u.id, problem: 'google email did not round-trip' });
      }
    } catch (err) {
      if (!(u.enabled === false && err.code === 'IDENTITY_DISABLED')) {
        problems.push({ system: 'mapping', user: u.id, problem: `${err.code || 'error'}: ${err.message}` });
      }
    }
    try {
      resolver.resolveFromClaims({ email: u.emails.keycloak, email_verified: false });
      problems.push({ system: 'mapping', user: u.id, problem: 'an unverified email resolved (must fail closed)' });
    } catch { /* expected */ }
  }
  return problems;
}

/** Live checks, parameterised by lookup functions so they can be unit-tested. */
async function liveChecks(doc, checkers) {
  const problems = [];
  for (const u of doc.users) {
    const enabled = u.enabled !== false;

    const kc = await checkers.keycloak(u);
    if (!kc.found) problems.push({ system: 'keycloak', user: u.id, problem: 'user not found' });
    else {
      if (kc.enabled !== enabled) problems.push({ system: 'keycloak', user: u.id, problem: `enabled=${kc.enabled}, expected ${enabled}` });
      if ((kc.email || '').toLowerCase() !== u.emails.keycloak.toLowerCase()) problems.push({ system: 'keycloak', user: u.id, problem: `email '${kc.email}' != '${u.emails.keycloak}'` });
    }

    const en = await checkers.entra(u);
    if (!en.found) problems.push({ system: 'entra', user: u.id, problem: `user '${u.emails.entra_upn}' not found` });
    else if (en.enabled !== enabled) problems.push({ system: 'entra', user: u.id, problem: `accountEnabled=${en.enabled}, expected ${enabled}` });

    const expected = expectedGoogleGrants(doc, u);
    if (u.emails.google || expected.length > 0) {
      const gc = await checkers.google(u, expected);
      for (const want of expected) {
        if (!gc.grants.some(g => g.dataset === want.dataset && g.role === want.role)) {
          problems.push({ system: 'google', user: u.id, problem: `missing ${want.role} on dataset ${want.dataset}` });
        }
      }
      for (const have of gc.grants) {
        if (!expected.some(g => g.dataset === have.dataset && g.role === have.role)) {
          problems.push({ system: 'google', user: u.id, problem: `unexpected ${have.role} on dataset ${have.dataset}` });
        }
      }
    }
  }
  return problems;
}

// ---- live checkers (network / CLI) ----

function liveCheckers(doc, env = process.env) {
  const realm = doc.settings.keycloak_realm;
  let adminToken;

  async function keycloak(u) {
    const base = env.KEYCLOAK_URL;
    if (!base || !env.KEYCLOAK_ADMIN_USER || !env.KEYCLOAK_ADMIN_PASSWORD) {
      throw new Error('KEYCLOAK_URL, KEYCLOAK_ADMIN_USER and KEYCLOAK_ADMIN_PASSWORD must be set for --live');
    }
    if (!adminToken) {
      const res = await fetch(`${base}/realms/master/protocol/openid-connect/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: env.KEYCLOAK_ADMIN_USER, password: env.KEYCLOAK_ADMIN_PASSWORD })
      });
      if (!res.ok) throw new Error(`Keycloak admin login failed (HTTP ${res.status})`);
      adminToken = (await res.json()).access_token;
    }
    const res = await fetch(`${base}/admin/realms/${encodeURIComponent(realm)}/users?username=${encodeURIComponent(u.id)}&exact=true`, {
      headers: { authorization: `Bearer ${adminToken}` }
    });
    if (!res.ok) throw new Error(`Keycloak user lookup failed (HTTP ${res.status})`);
    const [found] = await res.json();
    return found ? { found: true, enabled: found.enabled === true, email: found.email } : { found: false };
  }

  async function entra(u) {
    try {
      const out = execFileSync('az', ['ad', 'user', 'show', '--id', u.emails.entra_upn, '--query', '{enabled:accountEnabled}', '-o', 'json'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      return { found: true, enabled: JSON.parse(out).enabled === true };
    } catch (err) {
      if (/Request_ResourceNotFound|does not exist|not found/i.test(String(err.stderr || err.message))) return { found: false };
      throw err;
    }
  }

  async function google(u, expected) {
    const email = (u.emails.google || '').toLowerCase();
    const grants = [];
    const datasets = [...new Set(expected.map(g => g.dataset))];
    for (const dataset of datasets) {
      const project = env.GCP_PROJECT_ID;
      if (!project) throw new Error('GCP_PROJECT_ID must be set for --live');
      const out = execFileSync('bq', ['show', '--format=prettyjson', `${project}:${dataset}`], { encoding: 'utf8' });
      for (const entry of JSON.parse(out).access || []) {
        if ((entry.userByEmail || '').toLowerCase() === email) {
          const role = Object.keys(LEGACY_ROLE).find(r => LEGACY_ROLE[r] === entry.role);
          if (role) grants.push({ dataset, role });
        }
      }
    }
    return { grants };
  }

  return { keycloak, entra, google };
}

async function main() {
  const doc = loadUsersYaml();
  const mapContents = fs.existsSync(MAP_JSON) ? fs.readFileSync(MAP_JSON, 'utf8') : null;
  let problems = offlineChecks(doc, mapContents);
  if (process.argv.includes('--live') && problems.length === 0) {
    problems = await liveChecks(doc, liveCheckers(doc));
  }
  if (problems.length === 0) {
    console.log(`Identity seed is consistent (${doc.users.length} users${process.argv.includes('--live') ? ', live systems verified' : ', offline checks only'}).`);
    return;
  }
  console.error('Identity seed problems:');
  problems.forEach(p => console.error(`  [${p.system}] ${p.user}: ${p.problem}`));
  process.exit(1);
}

if (require.main === module) {
  main().catch(err => { console.error(err.message); process.exit(1); });
}

module.exports = { offlineChecks, liveChecks, expectedGoogleGrants, liveCheckers };
