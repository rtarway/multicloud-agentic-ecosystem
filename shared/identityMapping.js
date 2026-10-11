// Identity mapping (canonical copy: shared/identityMapping.js; synced into services by scripts/sync-shared.sh).
//
// Maps a verified IdP identity (Keycloak token claims) to the same person's identity in Microsoft Entra ID and
// Google Cloud. In the enterprise the directory comes from the identity sync; in the POC it is generated from
// identity/users.yaml (scripts/identity-build-map.js). The mapping FAILS CLOSED: an unknown, disabled,
// unverified or ambiguous identity never resolves to something else.

const fs = require('fs');

class IdentityMappingError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'IdentityMappingError';
    this.code = code;
  }
}

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

/**
 * @param {object|string} source parsed directory object, or a path to identity-map.json
 */
function loadDirectory(source) {
  const directory = typeof source === 'string' ? JSON.parse(fs.readFileSync(source, 'utf8')) : source;
  if (!directory || !Array.isArray(directory.users)) {
    throw new IdentityMappingError('DIRECTORY_INVALID', 'Identity directory must contain a users array.');
  }

  const byKeycloakEmail = new Map();
  const seen = { entra: new Map(), google: new Map() };
  for (const user of directory.users) {
    const kcEmail = normalizeEmail(user.emails && user.emails.keycloak);
    if (!user.id || !kcEmail) {
      throw new IdentityMappingError('DIRECTORY_INVALID', `User '${user.id || '?'}' must have an id and a keycloak email.`);
    }
    if (byKeycloakEmail.has(kcEmail)) {
      throw new IdentityMappingError('DIRECTORY_AMBIGUOUS', `Email '${kcEmail}' is assigned to more than one user.`);
    }
    byKeycloakEmail.set(kcEmail, user);

    for (const [system, field] of [['entra', 'entra_upn'], ['google', 'google']]) {
      const value = normalizeEmail(user.emails && user.emails[field]);
      if (!value) continue;
      if (seen[system].has(value)) {
        throw new IdentityMappingError('DIRECTORY_AMBIGUOUS', `${system} identity '${value}' is assigned to more than one user.`);
      }
      seen[system].set(value, user.id);
    }
  }
  return { directory, byKeycloakEmail };
}

function createResolver(source) {
  const { directory, byKeycloakEmail } = loadDirectory(source);

  /**
   * Resolves verified token claims to the user's identities.
   * @param {object} claims decoded, signature-verified IdP token claims
   */
  function resolveFromClaims(claims, { requireVerifiedEmail = true } = {}) {
    if (!claims || typeof claims !== 'object') {
      throw new IdentityMappingError('IDENTITY_CLAIMS_MISSING', 'No verified claims were provided.');
    }
    const email = normalizeEmail(claims.email);
    if (!email) {
      throw new IdentityMappingError('IDENTITY_EMAIL_MISSING', 'The token has no email claim to map.');
    }
    if (requireVerifiedEmail && claims.email_verified !== true) {
      throw new IdentityMappingError('IDENTITY_EMAIL_UNVERIFIED', `The email claim for '${email}' is not verified.`);
    }
    const user = byKeycloakEmail.get(email);
    if (!user) {
      throw new IdentityMappingError('IDENTITY_NOT_MAPPED', `No directory entry maps to '${email}'.`);
    }
    if (user.enabled === false) {
      throw new IdentityMappingError('IDENTITY_DISABLED', `User '${user.id}' is disabled (deprovisioned).`);
    }
    const emails = user.emails || {};
    return Object.freeze({
      id: user.id,
      displayName: user.display_name || user.id,
      keycloakEmail: normalizeEmail(emails.keycloak),
      entraUpn: normalizeEmail(emails.entra_upn) || null,
      googleEmail: normalizeEmail(emails.google) || null,
      groups: Object.freeze([...(user.groups || [])])
    });
  }

  /** Returns the Google account for the user, or throws if none is mapped. */
  function requireGoogleEmail(identity) {
    if (!identity || !identity.googleEmail) {
      throw new IdentityMappingError('IDENTITY_NO_GOOGLE_MAPPING', `User '${identity && identity.id}' has no Google account mapped.`);
    }
    return identity.googleEmail;
  }

  /** Returns the Entra UPN for the user, or throws if none is mapped. */
  function requireEntraUpn(identity) {
    if (!identity || !identity.entraUpn) {
      throw new IdentityMappingError('IDENTITY_NO_ENTRA_MAPPING', `User '${identity && identity.id}' has no Entra identity mapped.`);
    }
    return identity.entraUpn;
  }

  /**
   * True only if the Google account that completed an OAuth consent is the one mapped to this identity.
   * Prevents a user from linking someone else's Google account.
   */
  function googleAccountMatches(identity, googleIdTokenClaims) {
    if (!identity || !identity.googleEmail || !googleIdTokenClaims) return false;
    return googleIdTokenClaims.email_verified === true &&
      normalizeEmail(googleIdTokenClaims.email) === identity.googleEmail;
  }

  return { resolveFromClaims, requireGoogleEmail, requireEntraUpn, googleAccountMatches, directory };
}

module.exports = { createResolver, loadDirectory, IdentityMappingError, normalizeEmail };
