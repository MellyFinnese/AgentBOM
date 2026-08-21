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
pub struct McpGatewayResult {
    pub request: McpToolCall,
    pub enforcement: EnforcementDecision,
    pub forward: bool,
    pub response_status: String,
}

#[derive(Debug, Clone, Default)]
pub struct McpGateway;

impl McpGateway {
    pub fn inspect(&self, engine: &Engine, call: &McpToolCall, action: &str, resource: &str, rules: &[PolicyRule]) -> McpGatewayResult {
        let request = ToolRequest {
            request_id: call.request_id.clone(),
            agent_id: call.agent_id.clone(),
            tool: call.tool.clone(),
            action: action.to_string(),
            resource: resource.to_string(),
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
        McpGatewayResult { request: call.clone(), enforcement, forward, response_status }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deny_prevents_forwarding() {
        let engine = Engine::new();
        let rules = vec![PolicyRule {
            id: "deny-shell".into(),
            action: "execute".into(),
            resource: "shell".into(),
            decision: Decision::Deny,
        }];
        let call = McpToolCall {
            request_id: "1".into(),
            agent_id: "agent".into(),
            tool: "shell".into(),
            arguments: json!({"cmd":"id"}),
        };
        let result = McpGateway::default().inspect(&engine, &call, "execute", "shell", &rules);
        assert!(!result.forward);
        assert_eq!(result.response_status, "deny");
    }

    #[test]
    fn allow_can_forward() {
        let engine = Engine::new();
        let call = McpToolCall {
            request_id: "2".into(),
            agent_id: "agent".into(),
            tool: "read_file".into(),
            arguments: json!({"path":"README.md"}),
        };
        let result = McpGateway::default().inspect(&engine, &call, "read", "workspace", &[]);
        assert!(result.forward);
        assert_eq!(result.response_status, "allow");
    }
}
