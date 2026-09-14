const fs = require('fs');
const path = require('path');
const yamlUtil = require('./yamlUtil');
const azureStorage = require('./azureStorage');

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

    // Check OBO Downscoped Scope Authorization
    const hasRequiredScope = scopes.includes(toolDef.required_scope);
    console.log(`[MCP-EVAL] Step 1 (CGP): Required scope='${toolDef.required_scope}', Token scopes=[${scopes.join(', ')}] -> ${hasRequiredScope ? 'PASSED ✅' : 'DENIED ❌'}`);
    if (!hasRequiredScope) {
      const auditLog = {
        timestamp: new Date().toISOString(),
        principal: sub,
        actingAgent: actSub,
        requestedTool: toolName,
        requiredScope: toolDef.required_scope,
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
            text: `MCP Authorization Denied: Principal '${sub}' (acting agent '${actSub}') lacks required scope '${toolDef.required_scope}' for tool '${toolName}'. Current granted scopes: [${scopes.join(', ')}].`
          }
        ],
        audit: auditLog
      };
    }

    // Input validation against declarative constraints
    console.log(`[MCP-EVAL] Step 2 (Validation - Storage): container='${container}', action='${action}', filename='${filename}'`);

      if (!container || !toolDef.allowed_containers?.includes(container)) {
        console.warn(`[MCP-EVAL] ❌ Invalid container '${container}'. Allowed: [${(toolDef.allowed_containers || []).join(', ')}]`);
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Invalid parameter 'container': '${container}' is not allowed for '${toolName}'. Permitted: [${(toolDef.allowed_containers || []).join(', ')}].`
            }
          ]
        };
      }

      if (!action || !toolDef.allowed_actions?.includes(action)) {
        console.warn(`[MCP-EVAL] ❌ Invalid action '${action}'. Allowed: [${(toolDef.allowed_actions || []).join(', ')}]`);
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Invalid parameter 'action': '${action}' is not allowed for '${toolName}'. Permitted: [${(toolDef.allowed_actions || []).join(', ')}].`
            }
          ]
        };
      }

      if (!filename) {
        console.warn(`[MCP-EVAL] ❌ Missing required parameter 'filename'.`);
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Missing required parameter 'filename'.`
            }
          ]
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

      console.log(`[MCP-STORAGE] Step 4 (Storage): Executing JIT User-Delegation access for container='${container}', file='${filename}'...`);
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
                authorizedScope: toolDef.required_scope
              }
            }, null, 2)
          }
        ],
        audit: auditLog
      };
    } catch (storageErr) {
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
