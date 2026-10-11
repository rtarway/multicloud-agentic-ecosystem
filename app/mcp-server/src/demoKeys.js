// Demo signing keys (canonical copy: shared/demoKeys.js; synced into each app by scripts/sync-shared.sh).
//
// No key material is committed to the repository. Demo keys are only available when
// ALLOW_SIMULATION=true, and are resolved in this order:
//   1. environment variables (DEMO_<NAME>_PRIVATE_KEY / DEMO_<NAME>_PUBLIC_KEY, PEM)
//   2. files in DEMO_KEYS_DIR (default: <repo>/.demo-keys, created by scripts/gen-demo-keys.sh)
//   3. a keypair generated in memory and cached in process.env for the lifetime of the process
// Outside simulation mode every lookup returns null.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { isSimulation } = require('./simulation');

const FILE_NAMES = {
  azure: { private: 'azure-test-key.pem', public: 'azure-test-pub.pem' },
  google: { private: 'google-sts-key.pem', public: 'google-sts-pub.pem' }
};

function envName(name, kind) {
  return `DEMO_${name.toUpperCase()}_${kind.toUpperCase()}_KEY`;
}

function candidateDirs() {
  const dirs = [];
  if (process.env.DEMO_KEYS_DIR) dirs.push(path.resolve(process.env.DEMO_KEYS_DIR));
  dirs.push(
    path.resolve(__dirname, '../../../.demo-keys'),
    path.resolve(__dirname, '../../.demo-keys'),
    path.resolve(process.cwd(), '.demo-keys'),
    path.resolve(process.cwd(), '../../.demo-keys')
  );
  return dirs;
}

function readFromFiles(name, kind) {
  const file = FILE_NAMES[name] && FILE_NAMES[name][kind];
  if (!file) return null;
  for (const dir of candidateDirs()) {
    const p = path.join(dir, file);
    if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8');
  }
  return null;
}

function generateAndCache(name) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  process.env[envName(name, 'private')] = privateKey.export({ type: 'pkcs8', format: 'pem' });
  process.env[envName(name, 'public')] = publicKey.export({ type: 'spki', format: 'pem' });
}

/**
 * @param {'azure'|'google'} name
 * @param {'private'|'public'} kind
 * @returns {string|null} PEM, or null when simulation is disabled / the key is unavailable
 */
function getDemoKey(name, kind) {
  if (!isSimulation()) return null;
  const fromEnv = process.env[envName(name, kind)];
  if (fromEnv) return fromEnv;
  const fromFile = readFromFiles(name, kind);
  if (fromFile) return fromFile;
  generateAndCache(name);
  return process.env[envName(name, kind)] || null;
}

module.exports = { getDemoKey };
