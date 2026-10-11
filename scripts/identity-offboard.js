#!/usr/bin/env node
// Offboards a POC user everywhere (simulates the enterprise deprovisioning event).
//
//   node scripts/identity-offboard.js <user-id>            print the plan (dry run)
//   node scripts/identity-offboard.js <user-id> --apply    execute it
//
// Steps: (1) `terraform apply -var offboard_users=[<id>]` in the Keycloak, Entra and Google roots, which disables the
// accounts and removes the cloud grants; (2) end the user's live Keycloak sessions; (3) call the grant-purge hook so
// stored per-user credentials (the Google grant vault, Phase 4) are deleted. The hook is skipped, with a notice, until
// GRANT_PURGE_URL is configured.
// Credentials come from the environment only: KEYCLOAK_URL, KEYCLOAK_ADMIN_USER, KEYCLOAK_ADMIN_PASSWORD,
// optional GRANT_PURGE_URL and GRANT_PURGE_TOKEN.

const path = require('path');
const { execFileSync } = require('child_process');
const { loadUsersYaml } = require('../identity/lib/directory');

const ROOT = path.resolve(__dirname, '..');
const TERRAFORM_ROOTS = ['keycloak', 'entra', 'google'].map(n => path.join(ROOT, 'terraform', 'identity', n));

function buildPlan(userId, doc, env = process.env) {
  const user = (doc.users || []).find(u => u.id === userId);
  if (!user) throw new Error(`Unknown user '${userId}'. Known users: ${(doc.users || []).map(u => u.id).join(', ')}`);

  const steps = TERRAFORM_ROOTS.map(dir => ({
    kind: 'terraform',
    description: `terraform apply (offboard ${userId}) in ${path.relative(ROOT, dir)}`,
    dir,
    args: ['apply', '-auto-approve', '-input=false', `-var=offboard_users=["${userId}"]`]
  }));
  steps.push({ kind: 'keycloak-logout', description: `end all Keycloak sessions for ${userId}`, userId, realm: doc.settings.keycloak_realm });
  steps.push(env.GRANT_PURGE_URL
    ? { kind: 'purge', description: `POST ${env.GRANT_PURGE_URL} to delete stored grants for ${user.emails.keycloak}`, email: user.emails.keycloak }
    : { kind: 'notice', description: 'GRANT_PURGE_URL not set: no stored grants to purge yet (grant vault arrives in Phase 4)' });
  return { user, steps };
}

async function run(plan, deps = {}, env = process.env) {
  const exec = deps.exec || ((cmd, args, opts) => execFileSync(cmd, args, { stdio: 'inherit', ...opts }));
  const doFetch = deps.fetch || fetch;
  const log = deps.log || console.log;

  for (const step of plan.steps) {
    log(`-> ${step.description}`);
    if (step.kind === 'terraform') {
      exec('terraform', ['-chdir=' + step.dir, ...step.args], {});
    } else if (step.kind === 'keycloak-logout') {
      const base = env.KEYCLOAK_URL;
      if (!base || !env.KEYCLOAK_ADMIN_USER || !env.KEYCLOAK_ADMIN_PASSWORD) {
        throw new Error('KEYCLOAK_URL, KEYCLOAK_ADMIN_USER and KEYCLOAK_ADMIN_PASSWORD are required to end sessions');
      }
      const tokenRes = await doFetch(`${base}/realms/master/protocol/openid-connect/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: env.KEYCLOAK_ADMIN_USER, password: env.KEYCLOAK_ADMIN_PASSWORD })
      });
      if (!tokenRes.ok) throw new Error(`Keycloak admin login failed (HTTP ${tokenRes.status})`);
      const token = (await tokenRes.json()).access_token;
      const headers = { authorization: `Bearer ${token}` };
      const found = await (await doFetch(`${base}/admin/realms/${encodeURIComponent(step.realm)}/users?username=${encodeURIComponent(step.userId)}&exact=true`, { headers })).json();
      if (!found[0]) throw new Error(`User '${step.userId}' not found in Keycloak`);
      const res = await doFetch(`${base}/admin/realms/${encodeURIComponent(step.realm)}/users/${found[0].id}/logout`, { method: 'POST', headers });
      if (!res.ok) throw new Error(`Keycloak session logout failed (HTTP ${res.status})`);
    } else if (step.kind === 'purge') {
      const headers = { 'content-type': 'application/json' };
      if (env.GRANT_PURGE_TOKEN) headers.authorization = `Bearer ${env.GRANT_PURGE_TOKEN}`;
      const res = await doFetch(env.GRANT_PURGE_URL, { method: 'POST', headers, body: JSON.stringify({ email: step.email }) });
      if (!res.ok) throw new Error(`Grant purge failed (HTTP ${res.status})`);
    }
  }
}

async function main() {
  const [userId, ...flags] = process.argv.slice(2);
  if (!userId || userId.startsWith('-')) {
    console.error('usage: identity-offboard.js <user-id> [--apply]');
    process.exit(2);
  }
  const plan = buildPlan(userId, loadUsersYaml());
  if (!flags.includes('--apply')) {
    console.log(`Dry run: offboarding '${userId}' would:`);
    plan.steps.forEach(s => console.log(`  - ${s.description}`));
    console.log('Re-run with --apply to execute. To make it permanent, also set enabled: false in identity/users.yaml.');
    return;
  }
  await run(plan);
  console.log(`Offboarded '${userId}'. Set enabled: false in identity/users.yaml so later applies keep it disabled.`);
}

if (require.main === module) {
  main().catch(err => { console.error(err.message); process.exit(1); });
}

module.exports = { buildPlan, run };
