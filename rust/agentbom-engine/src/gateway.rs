use crate::enforcement::{Decision, PolicyRule};
use crate::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolRequest {
    pub request_id: String,
    pub agent_id: String,
    pub tool: String,
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnforcementDecision {
    pub request_id: String,
    pub decision: Decision,
    pub reason: String,
    pub matched_rule: Option<String>,
    pub approval_required: bool,
    pub audit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub audit_id: String,
    pub request_id: String,
    pub agent_id: String,
    pub tool: String,
    pub action: String,
    pub resource: String,
    pub decision: Decision,
    pub matched_rule: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct EnforcementGateway;

impl EnforcementGateway {
    pub fn evaluate(&self, engine: &Engine, request: &ToolRequest, rules: &[PolicyRule]) -> EnforcementDecision {
        let mut result = engine.evaluate_policy(&request.action, &request.resource, rules);
        if matches!(result.decision, Decision::RequireApproval) && request.approval_token.as_deref().is_some_and(|v| !v.is_empty()) {
            result.decision = Decision::Allow;
            result.reason = format!("approval token supplied for {}", result.matched_rule.as_deref().unwrap_or("policy"));
        }
        let audit_id = audit_id(request, &result.decision, result.matched_rule.as_deref());
        EnforcementDecision {
            request_id: request.request_id.clone(),
            approval_required: matches!(result.decision, Decision::RequireApproval),
            decision: result.decision,
            reason: result.reason,
            matched_rule: result.matched_rule,
            audit_id,
        }
    }

    pub fn audit(&self, request: &ToolRequest, decision: &EnforcementDecision) -> AuditEvent {
        AuditEvent {
            audit_id: decision.audit_id.clone(),
            request_id: request.request_id.clone(),
            agent_id: request.agent_id.clone(),
            tool: request.tool.clone(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            decision: decision.decision.clone(),
            matched_rule: decision.matched_rule.clone(),
            reason: decision.reason.clone(),
        }
    }
}

fn audit_id(request: &ToolRequest, decision: &Decision, rule: Option<&str>) -> String {
    let canonical = format!("{}|{}|{}|{}|{}|{}", request.request_id, request.agent_id, request.tool, request.action, request.resource, serde_json::to_string(&decision).unwrap_or_default());
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    if let Some(rule) = rule { hasher.update(rule.as_bytes()); }
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use serde_json::json;

    #[test]
    fn deny_is_enforced() {
        let engine = Engine::new();
        let rules = vec![PolicyRule { id: "block-prod-delete".into(), action: "delete".into(), resource: "production/*".into(), decision: Decision::Deny }];
        let request = ToolRequest { request_id: "r1".into(), agent_id: "agent".into(), tool: "db".into(), action: "delete".into(), resource: "production/db".into(), arguments: json!({}), approval_token: None };
        let result = EnforcementGateway.evaluate(&EnforcementGateway, &engine, &request, &rules);
        assert_eq!(result.decision, Decision::Deny);
        assert!(!result.audit_id.is_empty());
    }

    #[test]
    fn approval_token_converts_require_approval_to_allow() {
        let engine = Engine::new();
        let rules = vec![PolicyRule { id: "approve-prod-write".into(), action: "write".into(), resource: "production/*".into(), decision: Decision::RequireApproval }];
        let request = ToolRequest { request_id: "r2".into(), agent_id: "agent".into(), tool: "db".into(), action: "write".into(), resource: "production/db".into(), arguments: json!({}), approval_token: Some("approved".into()) };
        let result = EnforcementGateway.evaluate(&EnforcementGateway, &engine, &request, &rules);
        assert_eq!(result.decision, Decision::Allow);
    }
}
