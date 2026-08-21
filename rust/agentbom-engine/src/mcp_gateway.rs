use crate::gateway::{EnforcementDecision, ToolRequest};
use crate::{Decision, Engine, PolicyRule};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpToolCall {
    pub request_id: String,
    pub agent_id: String,
    pub tool: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpToolDefinition {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub annotations: serde_json::Value,
    #[serde(default)]
    pub input_schema: serde_json::Value,
    #[serde(default)]
    pub default_action: Option<String>,
    #[serde(default)]
    pub default_resource: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpGatewayResult {
    pub request: McpToolCall,
    pub enforcement: EnforcementDecision,
    pub forward: bool,
    pub response_status: String,
    pub resolved_action: String,
    pub resolved_resource: String,
    pub resolution_source: String,
}

#[derive(Debug, Clone, Default)]
pub struct McpGateway;

impl McpGateway {
    pub fn inspect(&self, engine: &Engine, call: &McpToolCall, action: &str, resource: &str, rules: &[PolicyRule]) -> McpGatewayResult {
        self.inspect_resolved(engine, call, action.to_string(), resource.to_string(), "explicit", rules)
    }

    pub fn inspect_with_definitions(
        &self,
        engine: &Engine,
        call: &McpToolCall,
        definitions: &[McpToolDefinition],
        action_override: Option<&str>,
        resource_override: Option<&str>,
        rules: &[PolicyRule],
    ) -> McpGatewayResult {
        let definition = definitions.iter().find(|item| item.name == call.tool);
        let (action, action_source) = action_override
            .filter(|value| !value.is_empty())
            .map(|value| (value.to_string(), "explicit"))
            .or_else(|| definition.and_then(|item| item.default_action.clone()).map(|value| (value, "tool-definition")))
            .unwrap_or_else(|| (infer_action(call, definition), "inferred"));

        let (resource, resource_source) = resource_override
            .filter(|value| !value.is_empty())
            .map(|value| (value.to_string(), "explicit"))
            .or_else(|| definition.and_then(|item| item.default_resource.clone()).map(|value| (value, "tool-definition")))
            .unwrap_or_else(|| (infer_resource(call, definition), "inferred"));

        self.inspect_resolved(engine, call, action, resource, if action_source == resource_source { action_source } else { "mixed" }, rules)
    }

    fn inspect_resolved(
        &self,
        engine: &Engine,
        call: &McpToolCall,
        action: String,
        resource: String,
        resolution_source: &str,
        rules: &[PolicyRule],
    ) -> McpGatewayResult {
        let request = ToolRequest {
            request_id: call.request_id.clone(),
            agent_id: call.agent_id.clone(),
            tool: call.tool.clone(),
            action: action.clone(),
            resource: resource.clone(),
            arguments: call.arguments.clone(),
            approval_token: None,
        };
        let enforcement = engine.enforce_request(&request, rules);
        let forward = matches!(enforcement.decision, Decision::Allow);
        let response_status = match enforcement.decision {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::RequireApproval => "require_approval",
        }
        .to_string();
        McpGatewayResult {
            request: call.clone(),
            enforcement,
            forward,
            response_status,
            resolved_action: action,
            resolved_resource: resource,
            resolution_source: resolution_source.to_string(),
        }
    }
}

fn infer_action(call: &McpToolCall, definition: Option<&McpToolDefinition>) -> String {
    let haystack = format!("{} {}", call.tool, definition.and_then(|d| d.description.clone()).unwrap_or_default()).to_ascii_lowercase();
    if haystack.contains("delete") || haystack.contains("remove") { return "delete".into(); }
    if haystack.contains("write") || haystack.contains("update") || haystack.contains("create") || haystack.contains("send") || haystack.contains("execute") { return "write".into(); }
    "read".into()
}

fn infer_resource(call: &McpToolCall, definition: Option<&McpToolDefinition>) -> String {
    for key in ["resource", "target", "path", "url", "uri", "file", "destination"] {
        if let Some(value) = call.arguments.get(key).and_then(|value| value.as_str()) {
            if !value.is_empty() { return value.to_string(); }
        }
    }
    if let Some(resource) = definition.and_then(|item| item.annotations.get("resource")).and_then(|value| value.as_str()) {
        if !resource.is_empty() { return resource.to_string(); }
    }
    "unknown".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deny_prevents_forwarding() {
        let engine = Engine::new();
        let rules = vec![PolicyRule { id: "deny-shell".into(), action: "execute".into(), resource: "shell".into(), decision: Decision::Deny }];
        let call = McpToolCall { request_id: "1".into(), agent_id: "agent".into(), tool: "shell".into(), arguments: json!({"cmd":"id"}) };
        let result = McpGateway::default().inspect(&engine, &call, "execute", "shell", &rules);
        assert!(!result.forward);
        assert_eq!(result.response_status, "deny");
    }

    #[test]
    fn definition_and_arguments_resolve_context() {
        let engine = Engine::new();
        let definitions = vec![McpToolDefinition {
            name: "read_file".into(),
            description: Some("Read a local file".into()),
            annotations: json!({}),
            input_schema: json!({}),
            default_action: Some("read".into()),
            default_resource: None,
        }];
        let call = McpToolCall { request_id: "2".into(), agent_id: "agent".into(), tool: "read_file".into(), arguments: json!({"path":"/workspace/README.md"}) };
        let result = McpGateway::default().inspect_with_definitions(&engine, &call, &definitions, None, None, &[]);
        assert_eq!(result.resolved_action, "read");
        assert_eq!(result.resolved_resource, "/workspace/README.md");
        assert_eq!(result.resolution_source, "mixed");
    }
}
