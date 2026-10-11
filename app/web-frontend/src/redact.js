// Credential redaction (canonical copy: shared/redact.js; synced into each app by scripts/sync-shared.sh).
//
// Responses sent to a browser must never contain bearer credentials. redactDeep() replaces the
// value of well-known credential fields and scrubs any JWT-shaped string it finds elsewhere.
// Decoded token claims (header/payload) are kept so the UI can still show lineage.

const REDACTED = '[REDACTED]';
const REDACTED_JWT = '[REDACTED_JWT]';

const CREDENTIAL_KEYS = new Set([
  'rawtoken', 'token', 'exchangedtoken', 'accesstoken', 'access_token', 'refresh_token', 'refreshtoken',
  'id_token', 'idtoken', 'keycloaktoken', 'entratoken', 'googleiamtoken', 'usertoken', 'userentratoken',
  'assertion', 'client_secret', 'clientsecret', 'password', 'authorization', 'svidtoken'
]);

const JWT_PATTERN = /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;

function redactString(value) {
  return value.replace(JWT_PATTERN, REDACTED_JWT);
}

function redactDeep(value, ancestors = new Set()) {
  if (typeof value === 'string') return redactString(value);
  if (value === null || typeof value !== 'object') return value;
  // Only true cycles are cut; the same object may legitimately appear in several places of a response.
  if (ancestors.has(value)) return '[CIRCULAR]';
  ancestors.add(value);
  let out;
  if (Array.isArray(value)) {
    out = value.map(v => redactDeep(v, ancestors));
  } else {
    out = {};
    for (const [k, v] of Object.entries(value)) {
      if (CREDENTIAL_KEYS.has(k.toLowerCase()) && v !== null && v !== undefined && v !== '') {
        out[k] = REDACTED;
      } else {
        out[k] = redactDeep(v, ancestors);
      }
    }
  }
  ancestors.delete(value);
  return out;
}

/** Express middleware: redacts every res.json() body. */
function redactResponses(req, res, next) {
  const original = res.json.bind(res);
  res.json = body => original(redactDeep(body));
  next();
}

module.exports = { redactDeep, redactString, redactResponses, REDACTED, REDACTED_JWT };
