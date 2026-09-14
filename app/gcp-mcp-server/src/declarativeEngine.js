// Declarative Low-Code Policy & Execution Engine for GCP BigQuery MCP Server
// Spec Version: 2026-07-15

const path = require('path');
const yamlUtil = require('./yamlUtil');
const bigqueryClient = require('./bigqueryClient');

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
      console.log(`[GCP Low-Code MCP] Loaded ${this.tools.length} declarative tools from tools.yaml (Spec ${this.protocolVersion}).`);
    } catch (err) {
      console.error('[GCP Low-Code MCP] Failed to load tools.yaml:', err.message);
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
            text: `MCP Tool Error: Unknown GCP tool '${toolName}'. Available tools: ${Array.from(this.toolMap.keys()).join(', ')}`
          }
        ]
      };
    }

    const sub = authContext?.sub || 'anonymous';
    const actSub = authContext?.act?.sub || 'direct-client';
    const scopes = authContext?.scopes || [];
    const actorChain = authContext?.actorChain || [actSub];

    console.log(`\n[GCP-MCP-EVAL] >>> Executing GCP Tool '${toolName}' for principal '${sub}'...`);
    console.log(`[GCP-MCP-EVAL] Full Multi-Hop Lineage: [${actorChain.join(' -> ')}]`);

    // 1. Check RFC 8693 Downscoped Scope Authorization
    const hasRequiredScope = scopes.includes(toolDef.required_scope);
    console.log(`[GCP-MCP-EVAL] Step 1 (Scope): Required='${toolDef.required_scope}', Token scopes=[${scopes.join(', ')}] -> ${hasRequiredScope ? 'PASSED ✅' : 'DENIED ❌'}`);

    if (!hasRequiredScope) {
      const auditLog = {
        timestamp: new Date().toISOString(),
        principal: sub,
        actingAgent: actSub,
        actorChain,
        requestedTool: toolName,
        requiredScope: toolDef.required_scope,
        grantedScopes: scopes,
        decision: 'DENIED_BY_POLICY'
      };

      console.warn(`[GCP-MCP Security] ACCESS DENIED: ${JSON.stringify(auditLog)}`);

      // Native MCP Protocol Error handling (July 2026 specification)
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: `MCP Authorization Denied: Principal '${sub}' (acting lineage: ${actorChain.join(' -> ')}) lacks required scope '${toolDef.required_scope}' for GCP tool '${toolName}'. Current granted scopes: [${scopes.join(', ')}].`
          }
        ],
        audit: auditLog
      };
    }

    // 2. Input Validation
    if (toolName === 'bigquery_query_sales') {
      const { quarter, region, metric } = args || {};
      if (!quarter || !region || !metric) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Missing required parameter for 'bigquery_query_sales'. Required: ['quarter', 'region', 'metric'].` }]
        };
      }
    } else if (toolName === 'bigquery_audit_compliance') {
      const { dataset, timeRange } = args || {};
      if (!dataset || !timeRange) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Missing required parameter for 'bigquery_audit_compliance'. Required: ['dataset', 'timeRange'].` }]
        };
      }
    }

    // 3. Fine-Grained Policy (FGP) Evaluation
    if (Array.isArray(toolDef.fine_grained_policies) && toolDef.fine_grained_policies.length > 0) {
      console.log(`[GCP-MCP-EVAL] Step 2 (FGP): Evaluating ${toolDef.fine_grained_policies.length} declarative policies from tools.yaml...`);
      for (const policy of toolDef.fine_grained_policies) {
        const isTriggered = this._evaluateFgp(policy.condition, { args, auth: authContext });
        if (isTriggered) {
          if (policy.effect === 'DENY') {
            const auditLog = {
              timestamp: new Date().toISOString(),
              principal: sub,
              actingAgent: actSub,
              actorChain,
              requestedTool: toolName,
              policyId: policy.id,
              decision: 'DENIED_BY_FGP'
            };
            console.warn(`[GCP-MCP FGP] ❌ Policy '${policy.id}' TRIGGERED -> ACCESS DENIED: ${JSON.stringify(auditLog)}`);
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
          console.log(`[GCP-MCP-EVAL]   Policy '${policy.id}': PASSED ✅`);
        }
      }
    }

    // 4. BigQuery Execution
    try {
      console.log(`[GCP-MCP-EXEC] Step 3: Dispatching to Google Cloud BigQuery client...`);
      let operationResult;

      if (toolName === 'bigquery_query_sales') {
        operationResult = await bigqueryClient.querySales(args, authContext);
      } else if (toolName === 'bigquery_audit_compliance') {
        operationResult = await bigqueryClient.queryAuditLogs(args, authContext);
      }

      const auditLog = {
        timestamp: new Date().toISOString(),
        principal: sub,
        actingAgent: actSub,
        actorChain,
        requestedTool: toolName,
        targetBackend: 'gcp_bigquery',
        queryJobId: operationResult?.queryJobId,
        decision: 'ALLOWED'
      };

      console.log(`[GCP-MCP BigQuery] ACCESS GRANTED: ${JSON.stringify(auditLog)}`);

      return {
        isError: false,
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'SUCCESS',
              tool: toolName,
              backend: 'gcp_bigquery',
              data: operationResult,
              audit: {
                userPrincipal: sub,
                actingAgent: actSub,
                actorChain,
                authorizedScope: toolDef.required_scope
              }
            }, null, 2)
          }
        ],
        audit: auditLog
      };
    } catch (bqErr) {
      const isCloudIamDenied = bqErr.statusCode === 403 || bqErr.message?.includes('403') || bqErr.message?.includes('Access Denied');
      const auditLog = {
        timestamp: new Date().toISOString(),
        principal: sub,
        actingAgent: actSub,
        actorChain,
        requestedTool: toolName,
        decision: isCloudIamDenied ? 'DENIED_BY_GCP_IAM' : 'BIGQUERY_EXECUTION_ERROR',
        error: bqErr.message
      };

      console.warn(`[GCP-MCP BigQuery] ❌ ${isCloudIamDenied ? 'GCP CLOUD IAM REJECTION (403)' : 'ERROR'}: ${bqErr.message}`);

      return {
        isError: true,
        cloudIAMDecision: isCloudIamDenied ? 'DENIED_BY_GCP_IAM' : undefined,
        content: [
          {
            type: 'text',
            text: isCloudIamDenied
              ? `Google Cloud BigQuery IAM Access Denied (HTTP 403): Principal '${sub}' lacks required GCP IAM role on dataset. Rejected by GCP Cloud IAM kernel.`
              : `BigQuery Execution Error: ${bqErr.message}`
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
      console.warn(`[GCP-MCP FGP] Error evaluating condition '${condition}':`, err.message);
      return false;
    }
  }
}

module.exports = DeclarativeEngine;
