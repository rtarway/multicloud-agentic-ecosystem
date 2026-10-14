// Emulation of Azure Storage RBAC for the DEMO PROFILE ONLY.
//
// With real Azure Storage the user's own OBO token is presented and Azure RBAC decides. When storage is simulated there
// is no Azure to ask, so this module answers the same question from the same source of truth the seed provisions Azure
// from: the groups and `azure_roles` in the identity directory. It never looks at names or emails for decisions.

const fs = require('fs');
const path = require('path');

const PERMISSIONS = {
  'Storage Blob Data Reader': ['read'],
  'Storage Blob Data Contributor': ['read', 'write'],
  'Storage Blob Data Owner': ['read', 'write']
};

function defaultMapPath(env = process.env) {
  if (env.IDENTITY_MAP_PATH) return env.IDENTITY_MAP_PATH;
  const repoMap = path.resolve(__dirname, '../../../identity/identity-map.json');
  return fs.existsSync(repoMap) ? repoMap : '';
}

function createRbacEmulator(source = defaultMapPath()) {
  let directory = { users: [], groups: [] };
  if (typeof source === 'string' && source) {
    try { directory = JSON.parse(fs.readFileSync(source, 'utf8')); } catch { /* empty directory: everything is denied */ }
  } else if (source && typeof source === 'object') {
    directory = source;
  }
  const groups = new Map((directory.groups || []).map(g => [g.id, g]));

  /** Does the user (by Entra UPN) hold a role that allows `action` on `container`? */
  function can(upn, container, action) {
    const wanted = String(upn || '').trim().toLowerCase();
    const user = (directory.users || []).find(u => u.enabled !== false && (u.emails || {}).entra_upn === wanted);
    if (!user) return { allowed: false, role: null };
    for (const gid of user.groups || []) {
      for (const assignment of (groups.get(gid) || {}).azure_roles || []) {
        if (assignment.container === container && (PERMISSIONS[assignment.role] || []).includes(action)) {
          return { allowed: true, role: assignment.role };
        }
      }
    }
    return { allowed: false, role: null };
  }

  return { can };
}

module.exports = { createRbacEmulator, PERMISSIONS };
