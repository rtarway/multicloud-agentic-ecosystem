// Azure Blob Storage backend for the MCP server.
//
// Real mode: the user's own identity reaches storage. The MCP server exchanges the incoming user token for a Storage
// token on behalf of that user (OBO, see storageTokens.js) and calls the Blob data plane with it, so Azure RBAC on the
// container decides. No account key, SAS or shared credential is involved, and nothing the caller sent is forwarded.
//
// Demo profile only: when storage is simulated (no live account), the in-memory buckets and an RBAC emulation derived
// from the identity directory stand in; they are refused outside ALLOW_SIMULATION=true.

const crypto = require('crypto');
const { isSimulation, requireSimulation } = require('./simulation');
const { createStorageTokenProvider } = require('./storageTokens');
const { createRbacEmulator } = require('./rbacEmulation');

// Blob names are single path segments made of safe characters: no separators, no traversal, no control characters.
const SAFE_BLOB_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function forbidden(message) {
  const err = new Error(message);
  err.statusCode = 403;
  err.code = 'AuthorizationPermissionMismatch';
  return err;
}

class AzureStorageService {
  constructor({ tokens, rbac, baseUrl, fetchImpl } = {}) {
    this.storageAccount = process.env.AZURE_STORAGE_ACCOUNT || 'azwifstoragepocrt';
    this.tokens = tokens || createStorageTokenProvider();
    this.rbac = rbac || null; // created lazily so tests can set IDENTITY_MAP_PATH first
    this.baseUrl = baseUrl || null;
    this.fetchImpl = fetchImpl || null;
    this.inMemoryBuckets = {
      app1: {
        'financial-report.json': JSON.stringify({ quarter: 'Q2-2026', revenue: '$14.2M', status: 'Audited' }, null, 2),
        'compliance.txt': 'App1 Compliance check verified: ISO27001 active.',
        'config.yaml': 'environment: production\nversion: 2.1.0'
      },
      app2: {
        'customer-metrics.json': JSON.stringify({ activeUsers: 48500, retentionRate: '94.2%' }, null, 2),
        'audit-log.txt': 'App2 Audit Log initialized at 2026-07-01T00:00:00Z.'
      }
    };
  }

  /** Test seam: replace collaborators (token provider, RBAC emulator, endpoint, fetch). */
  configure({ tokens, rbac, baseUrl, fetchImpl } = {}) {
    if (tokens) this.tokens = tokens;
    if (rbac) this.rbac = rbac;
    if (baseUrl !== undefined) this.baseUrl = baseUrl;
    if (fetchImpl) this.fetchImpl = fetchImpl;
  }

  _rbac() {
    if (!this.rbac) this.rbac = createRbacEmulator();
    return this.rbac;
  }

  _endpoint() {
    return this.baseUrl || process.env.AZURE_STORAGE_BASE_URL || `https://${this.storageAccount}.blob.core.windows.net`;
  }

  /** The demo profile may run storage fully in memory (no network). */
  _offline() {
    return isSimulation() && (process.env.NODE_ENV === 'test' || process.env.STORAGE_OFFLINE === 'true');
  }

  _meta(container, filename, permission, authContext, extra = {}) {
    const rawToken = authContext?.rawToken || '';
    return {
      credentialType: 'ENTRA_OBO_USER_TOKEN',
      authorizedBy: 'Azure RBAC on the container, evaluated for the signed-in user',
      resource: `/${container}/${filename}`,
      permissions: permission,
      correlationId: authContext?.correlationId || `chain-sig-${crypto.createHash('sha256').update(rawToken || 'anonymous').digest('hex').substring(0, 16)}`,
      userUpn: authContext?.email || authContext?.sub || 'anonymous',
      actorChain: authContext?.actorChain || [],
      ...extra
    };
  }

  _validate(container, filename) {
    if (!this.inMemoryBuckets[container]) throw new Error(`Azure Storage container '${container}' does not exist.`);
    if (typeof filename !== 'string' || !SAFE_BLOB_NAME.test(filename)) {
      const err = new Error(`Invalid blob name '${filename}': a blob name is one path segment of letters, digits, '.', '_' and '-'.`);
      err.statusCode = 400;
      throw err;
    }
  }

  // ---- emulated storage (demo profile) ----

  _emulate(op, container, filename, authContext, content) {
    requireSimulation('in-memory Azure Storage emulation');
    const upn = authContext?.email || authContext?.sub;
    const action = op === 'read' ? 'read' : 'write';
    const meta = this._meta(container, filename, action === 'read' ? 'r' : 'w', authContext, {
      credentialType: 'EMULATED_RBAC (demo profile)',
      authorizedBy: 'RBAC emulation from the identity directory (demo profile; real mode asks Azure)'
    });
    const decision = this._rbac().can(upn, container, action);
    if (!decision.allowed) {
      const err = forbidden(`Azure Storage HTTP 403 Forbidden: AuthorizationPermissionMismatch (Principal '${upn}' has no role that allows '${action}' on container '${container}')`);
      this._logAuditEvent('DENIED_BY_AZURE_STORAGE_IAM', container, filename, action, meta, err.message);
      throw err;
    }
    this._logAuditEvent('ALLOWED (SIMULATED)', container, filename, action, meta);

    if (action === 'read') {
      const bucket = this.inMemoryBuckets[container];
      if (!(filename in bucket)) throw new Error(`Blob '${filename}' not found in container '${container}'.`);
      return { container, filename, content: bucket[filename], storageAccount: this.storageAccount, lastModified: new Date().toISOString(), accessMeta: meta };
    }
    this.inMemoryBuckets[container][filename] = content || '';
    return { container, filename, bytesWritten: Buffer.byteLength(content || '', 'utf8'), storageAccount: this.storageAccount, timestamp: new Date().toISOString(), accessMeta: meta };
  }

  // ---- live storage ----

  async _live(op, container, filename, authContext, content) {
    const action = op === 'read' ? 'read' : 'write';
    const token = await this.tokens.acquire(authContext.rawToken);
    const meta = this._meta(container, filename, action === 'read' ? 'r' : 'w', authContext, { tokenExpiresAt: new Date(token.expiresAt).toISOString() });

    const doFetch = this.fetchImpl || fetch;
    const url = `${this._endpoint()}/${container}/${filename}`;
    const headers = {
      authorization: `Bearer ${token.token}`,
      'x-ms-version': '2020-10-02',
      'x-ms-client-request-id': meta.correlationId
    };
    const init = { method: op === 'read' ? 'GET' : 'PUT', headers, signal: AbortSignal.timeout(8000) };
    if (op === 'write') {
      headers['x-ms-blob-type'] = 'BlockBlob';
      headers['content-type'] = 'text/plain; charset=utf-8';
      init.body = Buffer.from(content || '', 'utf8');
    }
    const res = await doFetch(url, init);
    const requestId = res.headers && res.headers.get ? (res.headers.get('x-ms-request-id') || res.headers.get('x-ms-client-request-id')) : undefined;

    if (res.status === 403 || res.status === 401) {
      const err = forbidden(`Azure Storage HTTP ${res.status} ${res.status === 403 ? 'Forbidden: AuthorizationPermissionMismatch' : 'Unauthorized'} (Principal '${meta.userUpn}' lacks the required role on container '${container}')`);
      this._logAuditEvent('DENIED_BY_AZURE_STORAGE_IAM', container, filename, action, meta, err.message);
      throw err;
    }
    if (res.status === 404) throw Object.assign(new Error(`Blob '${filename}' not found in container '${container}'.`), { statusCode: 404 });
    if (!res.ok) throw Object.assign(new Error(`Azure Storage HTTP ${res.status}`), { statusCode: res.status });

    this._logAuditEvent('ALLOWED', container, filename, action, meta);
    if (op === 'read') {
      return { container, filename, content: await res.text(), storageAccount: this.storageAccount, lastModified: new Date().toISOString(), requestId, accessMeta: meta };
    }
    return { container, filename, bytesWritten: Buffer.byteLength(content || '', 'utf8'), storageAccount: this.storageAccount, timestamp: new Date().toISOString(), requestId, accessMeta: meta };
  }

  async _run(op, container, filename, authContext, content) {
    this._validate(container, filename);
    if (this._offline()) return this._emulate(op, container, filename, authContext, content);

    try {
      return await this._live(op, container, filename, authContext, content);
    } catch (err) {
      // A real denial or a real error is final. Only "could not reach or authenticate to live Azure" may fall back, and
      // only in the demo profile, to the emulation. Outside it, the error stands.
      const unavailable = !err.statusCode && (
        ['ENTRA_UNREACHABLE', 'CLIENT_ASSERTION_UNAVAILABLE', 'NOT_CONFIGURED'].includes(err.code) ||
        (!err.code && /fetch failed|ECONN|ENOTFOUND|timed out|aborted/i.test(err.message))
      );
      if (!unavailable || !isSimulation()) throw err;
      console.warn(`[AZURE-STORAGE] ⚠️ Live Azure unavailable (${err.message}); using the RBAC emulation (demo profile).`);
      return this._emulate(op, container, filename, authContext, content);
    }
  }

  async readBlob(container, filename, authContext = {}) {
    return this._run('read', container, filename, authContext);
  }

  async writeBlob(container, filename, content, authContext = {}) {
    return this._run('write', container, filename, authContext, content);
  }

  async listBlobs(container) {
    requireSimulation('in-memory blob listing (no live listing implemented)');
    const bucket = this.inMemoryBuckets[container];
    if (!bucket) throw new Error(`Azure Storage container '${container}' does not exist.`);
    return Object.keys(bucket).map(name => ({ name, container, size: Buffer.byteLength(bucket[name], 'utf8') }));
  }

  _logAuditEvent(decision, container, filename, action, meta, errorDetail = null) {
    const auditRecord = {
      event: 'DELEGATED_STORAGE_ACCESS',
      timestamp: new Date().toISOString(),
      correlationId: meta.correlationId,
      executionChain: {
        endUser: { upn: meta.userUpn },
        actors: meta.actorChain || []
      },
      targetResource: { storageAccount: this.storageAccount, container, blob: filename },
      credentialType: meta.credentialType,
      action,
      decision,
      errorDetail
    };
    console.log(`\n[DELEGATED_STORAGE_ACCESS] ${JSON.stringify(auditRecord)}\n`);
  }
}

module.exports = new AzureStorageService();
module.exports.AzureStorageService = AzureStorageService;
module.exports.SAFE_BLOB_NAME = SAFE_BLOB_NAME;
