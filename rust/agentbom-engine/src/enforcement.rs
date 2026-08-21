use crate::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: String,
    pub action: String,
    pub resource: String,
    pub decision: Decision,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub matched_rule: Option<String>,
    pub reason: String,
}

impl Engine {
    pub fn evaluate_policy(&self, action: &str, resource: &str, rules: &[PolicyRule]) -> PolicyDecision {
        for rule in rules {
            if matches_pattern(&rule.action, action) && matches_pattern(&rule.resource, resource) {
                return PolicyDecision {
                    decision: rule.decision.clone(),
                    matched_rule: Some(rule.id.clone()),
                    reason: format!("matched policy {}", rule.id),
                };
            }
        }
        PolicyDecision { decision: Decision::Allow, matched_rule: None, reason: "no policy rule matched".into() }
    }
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    pattern == "*" || pattern.eq_ignore_ascii_case(value)
}
