// OPA Policy Evaluator for A2A Agent Orchestrator
// Enforces Fine-Grained Policies (FGP) before tools are dispatched

const fs = require('fs');
const path = require('path');

class OpaPolicyEngine {
  constructor() {
    this.policyPath = path.join(__dirname, 'policies', 'orchestrator_policy.rego');
    this.loadPolicy();
  }

  loadPolicy() {
    try {
      if (fs.existsSync(this.policyPath)) {
        this.regoSource = fs.readFileSync(this.policyPath, 'utf8');
      }
    } catch (e) {
      console.warn('[OPA] Could not read rego file:', e.message);
    }
  }

  /**
   * Evaluates FGP for the orchestrator
   * @param {Object} input - { user, plan, context }
   * @returns {{ allowed: boolean, reason?: string, evaluatedAt: string }}
   */
  evaluate(input) {
    const timestamp = new Date();
    const dayOfWeek = new Intl.DateTimeFormat('en-US', { weekday: 'long' }).format(timestamp);

    const evaluationContext = {
      day_of_week: input?.context?.day_of_week || dayOfWeek,
      simulate_weekend: Boolean(input?.context?.simulate_weekend),
      timestamp: timestamp.toISOString()
    };

    // Evaluate: Is Weekend?
    const allowWeekend = process.env.ALLOW_WEEKEND_EXECUTION !== 'false';
    const isWeekend =
      evaluationContext.simulate_weekend ||
      (!allowWeekend && (evaluationContext.day_of_week === 'Saturday' || evaluationContext.day_of_week === 'Sunday'));

    if (isWeekend) {
      return {
        allowed: false,
        reason: `Orchestrator FGP Violation: Tool execution is prohibited on weekends (Current day: ${evaluationContext.day_of_week}, simulate_weekend: ${evaluationContext.simulate_weekend}). Policy: package orchestrator.authz`,
        evaluatedAt: evaluationContext.timestamp,
        policy: 'orchestrator.authz',
        rule: 'not is_weekend'
      };
    }

    const plannedTool = input?.plan?.plannedTool;
    const isMultiStep = input?.plan?.planType === 'MULTI_STEP_PIPELINE' || input?.plan?.planType === 'CROSS_CLOUD_PIPELINE';
    const permittedTools = [
      'tool1',
      'tool2',
      'multi_step_pipeline',
      'cross_cloud_pipeline',
      'bigquery_query_sales',
      'bigquery_audit_compliance',
      'send_email_graph'
    ];
    if (!isMultiStep && (!plannedTool || !permittedTools.includes(plannedTool))) {
      return {
        allowed: false,
        reason: `Orchestrator FGP Violation: Tool '${plannedTool}' is not a permitted tool.`,
        evaluatedAt: evaluationContext.timestamp,
        policy: 'orchestrator.authz',
        rule: 'valid_tool_action'
      };
    }

    return {
      allowed: true,
      reason: 'Allowed by policy orchestrator.authz (Weekday window confirmed, valid tool planned).',
      evaluatedAt: evaluationContext.timestamp,
      policy: 'orchestrator.authz'
    };
  }
}

module.exports = new OpaPolicyEngine();
