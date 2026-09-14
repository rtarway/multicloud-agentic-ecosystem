package orchestrator.authz

# Default deny
default allow = false
default reason = "Default deny"

# Allow rule: Must not be a weekend, and must be an authorized tool
allow {
    not is_weekend
    valid_tool_action
}

# Rule: Weekend check
is_weekend {
    input.context.simulate_weekend == true
}

is_weekend {
    input.context.day_of_week == "Saturday"
}

is_weekend {
    input.context.day_of_week == "Sunday"
}

# Rule: Valid tool
valid_tool_action {
    input.plan.plannedTool == "tool1"
}

valid_tool_action {
    input.plan.plannedTool == "tool2"
}

valid_tool_action {
    input.plan.plannedTool == "multi_step_pipeline"
}

valid_tool_action {
    input.plan.plannedTool == "send_email_graph"
}

