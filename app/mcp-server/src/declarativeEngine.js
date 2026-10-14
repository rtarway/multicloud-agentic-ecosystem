const fs = require('fs');
const path = require('path');
const yamlUtil = require('./yamlUtil');
const azureStorage = require('./azureStorage');
const { SAFE_BLOB_NAME } = azureStorage;
const { storageScope } = require('./azureScopes');

class DeclarativeEngine {
  constructor(toolsYamlPath) {
    this.toolsYamlPath = toolsYamlPath || path.join(__dirname, '..', 'tools.yaml');
    this.loadDefinitions();
  }

  loadDefinitions() {
    try {
      const parsed = yamlUtil.parseYamlOrJson(this.toolsYamlPath);
      this.protocolVersion = parsed.version || '2026-07-15';
      this.tools = parsed.tools || [];
      this.toolMap = new Map();
      for (const t of this.tools) {
        this.toolMap.set(t.name, t);
      }
      console.log(`[Low-Code MCP] Loaded ${this.tools.length} declarative tools from tools.yaml (Spec ${this.protocolVersion}).`);
    } catch (err) {
      console.error('[Low-Code MCP] Failed to load tools.yaml:', err.message);
      this.tools = [];
      this.toolMap = new Map();
    }
  }

  getProtocolVersion() {
    return this.protocolVersion;
  }

  listTools() {
    return this.tools.map(t => ({
      name: t.name,
      title: t.title,
      description: t.description,
      inputSchema: t.inputSchema
    }));
  }

  async executeTool(toolName, args, authContext) {
    const toolDef = this.toolMap.get(toolName);

    if (!toolDef) {
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: `MCP Tool Error: Unknown tool '${toolName}'. Available tools: ${Array.from(this.toolMap.keys()).join(', ')}`
          }
        ]
      };
    }

    const sub = authContext?.sub || 'anonymous';
    const actSub = authContext?.act?.sub || 'direct-client';
    const scopes = authContext?.scopes || [];
    const { container, action, filename, content } = args || {};

    console.log(`\n[MCP-EVAL] >>> Executing Tool '${toolName}' for principal '${sub}' (agent '${actSub}')...`);

    // Input validation against declarative constraints (the delegated scope depends on the container and action)
    console.log(`[MCP-EVAL] Step 1 (Validation - Storage): container='${container}', action='${action}', filename='${filename}'`);

    if (!container || !toolDef.allowed_containers?.includes(container)) {
      console.warn(`[MCP-EVAL] ❌ Invalid container '${container}'. Allowed: [${(toolDef.allowed_containers || []).join(', ')}]`);
      return {
        isError: true,
        content: [{ type: 'text', text: `Invalid parameter 'container': '${container}' is not allowed for '${toolName}'. Permitted: [${(toolDef.allowed_containers || []).join(', ')}].` }]
      };
    }

    if (!action || !toolDef.allowed_actions?.includes(action)) {
      console.warn(`[MCP-EVAL] ❌ Invalid action '${action}'. Allowed: [${(toolDef.allowed_actions || []).join(', ')}]`);
      return {
        isError: true,
        content: [{ type: 'text', text: `Invalid parameter 'action': '${action}' is not allowed for '${toolName}'. Permitted: [${(toolDef.allowed_actions || []).join(', ')}].` }]
      };
    }

    if (!filename || !SAFE_BLOB_NAME.test(filename)) {
      console.warn(`[MCP-EVAL] ❌ Missing or invalid parameter 'filename'.`);
      return {
        isError: true,
        content: [{ type: 'text', text: filename ? `Invalid parameter 'filename': a blob name is one path segment of letters, digits, '.', '_' and '-'.` : `Missing required parameter 'filename'.` }]
      };
    }

    // Delegated-scope authorization: the token must carry the scope for exactly this operation
    const requiredScope = storageScope(action, container);
    const hasRequiredScope = scopes.includes(requiredScope);
    console.log(`[MCP-EVAL] Step 2 (Scope): Required='${requiredScope}', Token scopes=[${scopes.join(', ')}] -> ${hasRequiredScope ? 'PASSED ✅' : 'DENIED ❌'}`);
    if (!hasRequiredScope) {
      const auditLog = {
        timestamp: new Date().toISOString(),
        principal: sub,
        actingAgent: actSub,
        requestedTool: toolName,
        requiredScope,
        grantedScopes: scopes,
        decision: 'DENIED_BY_POLICY'
      };

      console.warn(`[MCP Security] ACCESS DENIED: ${JSON.stringify(auditLog)}`);

      // Native MCP Protocol Error handling (July 2026 specification)
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: `MCP Authorization Denied: Principal '${sub}' (acting agent '${actSub}') lacks required scope '${requiredScope}' for tool '${toolName}'. Current granted scopes: [${scopes.join(', ')}].`
          }
        ],
        audit: auditLog
      };
    }

    // In-Process Fine-Grained Policy (FGP) evaluation defined in tools.yaml
    if (Array.isArray(toolDef.fine_grained_policies) && toolDef.fine_grained_policies.length > 0) {
      console.log(`[MCP-EVAL] Step 3 (FGP): Evaluating ${toolDef.fine_grained_policies.length} in-process policies from tools.yaml...`);
      for (const policy of toolDef.fine_grained_policies) {
        const isTriggered = this._evaluateFgp(policy.condition, { args, auth: authContext });
        if (isTriggered) {
          if (policy.effect === 'DENY') {
            const auditLog = {
              timestamp: new Date().toISOString(),
              principal: sub,
              actingAgent: actSub,
              requestedTool: toolName,
              policyId: policy.id,
              decision: 'DENIED_BY_FGP'
            };
            console.warn(`[MCP FGP] ❌ Policy '${policy.id}' TRIGGERED -> ACCESS DENIED: ${JSON.stringify(auditLog)}`);
            return {
              isError: true,
              content: [
                {
                  type: 'text',
                  text: policy.message || `Fine-Grained Policy Denial (${policy.id})`
                }
              ],
              audit: auditLog
            };
          }
        } else {
          console.log(`[MCP-EVAL]   Policy '${policy.id}': PASSED ✅`);
        }
      }
    }

    try {
      let operationResult;

      console.log(`[MCP-STORAGE] Step 4 (Storage): Accessing container='${container}', file='${filename}' as the signed-in user (Azure RBAC decides)...`);
      if (action === 'read') {
        operationResult = await azureStorage.readBlob(container, filename, authContext);
      } else if (action === 'write') {
        operationResult = await azureStorage.writeBlob(container, filename, content || '', authContext);
      }

      const auditLog = {
        timestamp: new Date().toISOString(),
        principal: sub,
        actingAgent: actSub,
        requestedTool: toolName,
        action,
        container,
        filename,
        requiredScope,
        decision: 'ALLOWED'
      };

      console.log(`[MCP Storage] ACCESS GRANTED: ${JSON.stringify(auditLog)}`);

      return {
        isError: false,
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'SUCCESS',
              tool: toolName,
              container,
              filename,
              action,
              data: operationResult,
              audit: {
                userPrincipal: sub,
                actingAgent: actSub,
                authorizedScope: requiredScope
              }
            }, null, 2)
          }
        ],
        audit: auditLog
      };
    } catch (storageErr) {
      if (storageErr.code === 'INTERACTION_REQUIRED') {
        const auditLog = { timestamp: new Date().toISOString(), principal: sub, actingAgent: actSub, requestedTool: toolName, decision: 'STEP_UP_REQUIRED' };
        return {
          isError: true,
          stepUp: { required: true, claims: storageErr.claims },
          content: [{ type: 'text', text: `Step-up required: ${storageErr.message}` }],
          audit: auditLog
        };
      }
      const isCloudIamDenied = storageErr.statusCode === 403 || storageErr.message?.includes('403') || storageErr.message?.includes('AuthorizationPermissionMismatch');
      const auditLog = {
        timestamp: new Date().toISOString(),
        principal: sub,
        actingAgent: actSub,
        requestedTool: toolName,
        action,
        container,
        filename,
        decision: isCloudIamDenied ? 'DENIED_BY_AZURE_STORAGE_IAM' : 'STORAGE_EXECUTION_ERROR',
        error: storageErr.message
      };

      console.warn(`[MCP Storage] ❌ ${isCloudIamDenied ? 'CLOUD IAM REJECTION (403)' : 'ERROR'}: ${storageErr.message}`);

      return {
        isError: true,
        cloudIAMDecision: isCloudIamDenied ? 'DENIED_BY_AZURE_STORAGE_IAM' : undefined,
        content: [
          {
            type: 'text',
            text: isCloudIamDenied
              ? `Azure Storage Cloud IAM Access Denied (HTTP 403): Principal '${sub}' lacks required Azure Storage RBAC role ('Storage Blob Data Reader') on container '${container}'. Operation was rejected natively by Azure Storage kernel.`
              : `Azure Storage Execution Error: ${storageErr.message}`
          }
        ],
        audit: auditLog
      };
    }
  }

  _evaluateFgp(condition, context) {
    try {
      const fn = new Function('args', 'auth', `return Boolean(${condition});`);
      return fn(context.args, context.auth);
    } catch (err) {
      console.warn(`[MCP FGP] Error evaluating condition '${condition}':`, err.message);
      return false;
    }
  }
}

module.exports = DeclarativeEngine;
