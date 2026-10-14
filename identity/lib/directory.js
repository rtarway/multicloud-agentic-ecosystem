// Loads, validates and converts identity/users.yaml (the POC identity seed).
// js-yaml is resolved from app/mcp-server (which already depends on it) so the repo needs no extra install.

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const USERS_YAML = path.join(ROOT, 'identity', 'users.yaml');
const MAP_JSON = path.join(ROOT, 'identity', 'identity-map.json');

function loadYamlLib() {
  const paths = [path.join(ROOT, 'app', 'mcp-server'), path.join(ROOT, 'app', 'gcp-mcp-server'), ROOT];
  return require(require.resolve('js-yaml', { paths }));
}

function loadUsersYaml(file = USERS_YAML) {
  return loadYamlLib().load(fs.readFileSync(file, 'utf8'));
}

const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const ID = /^[a-z][a-z0-9-]{0,62}$/;

/** Returns a list of human-readable problems (empty when the document is valid). */
function validate(doc) {
  const errors = [];
  if (!doc || typeof doc !== 'object') return ['users.yaml is empty or not a mapping'];
  if (doc.version !== 1) errors.push(`unsupported version '${doc.version}' (expected 1)`);

  const settings = doc.settings || {};
  if (!settings.keycloak_realm) errors.push('settings.keycloak_realm is required');
  if (!settings.entra_default_domain) errors.push('settings.entra_default_domain is required');

  const groupIds = new Set();
  const groups = Array.isArray(doc.groups) ? doc.groups : [];
  for (const g of groups) {
    if (!g.id || !ID.test(g.id)) errors.push(`group id '${g.id}' is invalid (lowercase letters, digits, hyphens)`);
    else if (groupIds.has(g.id)) errors.push(`duplicate group id '${g.id}'`);
    groupIds.add(g.id);
    for (const r of g.azure_roles || []) {
      if (!r.container || !r.role) errors.push(`group '${g.id}': azure_roles entries need container and role`);
    }
    for (const b of g.bigquery || []) {
      if (!b.dataset || !b.role || !/^roles\//.test(b.role)) errors.push(`group '${g.id}': bigquery entries need dataset and a roles/... role`);
    }
  }

  const ids = new Set();
  const emails = { keycloak: new Set(), entra_upn: new Set(), google: new Set() };
  const users = Array.isArray(doc.users) ? doc.users : [];
  if (users.length === 0) errors.push('at least one user is required');

  for (const u of users) {
    if (!u.id || !ID.test(u.id)) { errors.push(`user id '${u.id}' is invalid`); continue; }
    if (ids.has(u.id)) errors.push(`duplicate user id '${u.id}'`);
    ids.add(u.id);

    const e = u.emails || {};
    for (const field of ['keycloak', 'entra_upn', 'google']) {
      const value = (e[field] || '').trim().toLowerCase();
      if (!value) continue;
      if (!EMAIL.test(value)) errors.push(`user '${u.id}': emails.${field} '${e[field]}' is not an email address`);
      if (emails[field].has(value)) errors.push(`user '${u.id}': emails.${field} '${value}' is used by another user`);
      emails[field].add(value);
    }
    if (!e.keycloak) errors.push(`user '${u.id}': emails.keycloak is required`);
    if (!e.entra_upn) errors.push(`user '${u.id}': emails.entra_upn is required`);
    if (e.entra_upn && settings.entra_default_domain && !e.entra_upn.toLowerCase().endsWith(`@${settings.entra_default_domain.toLowerCase()}`)) {
      errors.push(`user '${u.id}': emails.entra_upn must be in '${settings.entra_default_domain}'`);
    }

    let needsGoogle = false;
    for (const gid of u.groups || []) {
      const g = groups.find(x => x.id === gid);
      if (!g) { errors.push(`user '${u.id}' references unknown group '${gid}'`); continue; }
      if ((g.bigquery || []).length > 0) needsGoogle = true;
    }
    if (u.enabled !== false && needsGoogle && !e.google) {
      errors.push(`user '${u.id}': a Google account (emails.google) is required because a group grants BigQuery access`);
    }
  }
  return errors;
}

/** Deterministic, secret-free directory consumed by services (see shared/identityMapping.js). */
function buildMap(doc) {
  return {
    version: doc.version,
    realm: doc.settings.keycloak_realm,
    users: doc.users.map(u => ({
      id: u.id,
      display_name: u.display_name || u.id,
      enabled: u.enabled !== false,
      emails: {
        keycloak: (u.emails.keycloak || '').toLowerCase(),
        entra_upn: (u.emails.entra_upn || '').toLowerCase(),
        ...(u.emails.google ? { google: u.emails.google.toLowerCase() } : {})
      },
      groups: [...(u.groups || [])].sort()
    })).sort((a, b) => a.id.localeCompare(b.id)),
    groups: doc.groups.map(g => ({
      id: g.id,
      agent_scopes: [...(g.agent_scopes || [])].sort(),
      // Azure RBAC the group holds; used only to EMULATE Azure Storage RBAC in the demo profile (Azure itself decides in real mode)
      azure_roles: (g.azure_roles || []).map(r => ({ container: r.container, role: r.role }))
    })).sort((a, b) => a.id.localeCompare(b.id))
  };
}

module.exports = { ROOT, USERS_YAML, MAP_JSON, loadUsersYaml, validate, buildMap };
