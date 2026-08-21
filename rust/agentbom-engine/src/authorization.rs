use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Effect { Allow, Deny }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Permission {
    pub id: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub effect: Effect,
    #[serde(default)]
    pub conditions: serde_json::Value,
    /// Provider which produced the normalized permission (aws, gcp, azure, k8s, oauth, mcp).
    #[serde(default)]
    pub provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow,
    Deny,
    Indeterminate,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthorizationModel {
    pub permissions: Vec<Permission>,
}

impl AuthorizationModel {
    pub fn add(&mut self, permission: Permission) { self.permissions.push(permission); }

    pub fn effective(&self, principal: &str, action: &str, resource: &str) -> Vec<&Permission> {
        self.permissions.iter().filter(|p| {
            principal_matches(&p.principal, principal)
                && matches_pattern(&p.action, action, true)
                && matches_pattern(&p.resource, resource, false)
        }).collect()
    }

    /// Evaluate without a condition context. Condition-bearing allows never grant authority
    /// unless their conditions are empty. This prevents a normalized conditional allow from
    /// becoming an unconditional allow.
    pub fn is_allowed(&self, principal: &str, action: &str, resource: &str) -> bool {
        matches!(self.evaluate(principal, action, resource, &HashMap::new()), AuthorizationDecision::Allow)
    }

    pub fn evaluate(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context: &HashMap<String, String>,
    ) -> AuthorizationDecision {
        let mut saw_indeterminate = false;
        let mut allowed = false;

        for permission in self.effective(principal, action, resource) {
            match condition_state(&permission.conditions, context) {
                ConditionState::False => continue,
                ConditionState::Indeterminate => {
                    saw_indeterminate = true;
                    continue;
                }
                ConditionState::True => {}
            }

            match permission.effect {
                Effect::Deny => return AuthorizationDecision::Deny,
                Effect::Allow => allowed = true,
            }
        }

        if allowed { AuthorizationDecision::Allow }
        else if saw_indeterminate { AuthorizationDecision::Indeterminate }
        else { AuthorizationDecision::Deny }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionState { True, False, Indeterminate }

fn condition_state(conditions: &serde_json::Value, context: &HashMap<String, String>) -> ConditionState {
    if conditions.is_null() || conditions.as_object().is_none() || conditions.as_object().is_some_and(|o| o.is_empty()) {
        return ConditionState::True;
    }
    let Some(object) = conditions.as_object() else { return ConditionState::Indeterminate; };
    let mut saw_unknown = false;

    for (operator, operands) in object {
        let Some(operand_object) = operands.as_object() else { return ConditionState::Indeterminate; };
        for (key, expected) in operand_object {
            let Some(actual) = context.get(key) else {
                saw_unknown = true;
                continue;
            };
            let Some(expected_text) = expected.as_str() else { return ConditionState::Indeterminate; };
            let matches = match operator.as_str() {
                "StringEquals" | "ArnEquals" | "StringLike" | "ArnLike" => {
                    if operator.ends_with("Like") { glob_match(expected_text, actual, false) }
                    else { expected_text.eq_ignore_ascii_case(actual) }
                }
                "StringNotEquals" | "ArnNotEquals" | "StringNotLike" | "ArnNotLike" => {
                    if operator.ends_with("NotLike") { !glob_match(expected_text, actual, false) }
                    else { !expected_text.eq_ignore_ascii_case(actual) }
                }
                "Bool" => expected_text.eq_ignore_ascii_case(actual),
                "NumericEquals" => expected_text.parse::<f64>().ok().zip(actual.parse::<f64>().ok()).is_some_and(|(e, a)| (e - a).abs() < f64::EPSILON),
                _ => return ConditionState::Indeterminate,
            };
            if !matches { return ConditionState::False; }
        }
    }
    if saw_unknown { ConditionState::Indeterminate } else { ConditionState::True }
}

fn principal_matches(pattern: &str, value: &str) -> bool { matches_pattern(pattern, value, true) }

/// Supports `*` and `?` globs for action/principal/resource patterns. This deliberately
/// avoids provider-specific regex semantics while supporting hierarchical ARN/path-style
/// resource scopes such as `arn:aws:s3:::bucket/*` and `/prod/*`.
fn matches_pattern(pattern: &str, value: &str, case_insensitive: bool) -> bool {
    if pattern == "*" { return true; }
    glob_match(pattern, value, case_insensitive)
}

fn glob_match(pattern: &str, value: &str, case_insensitive: bool) -> bool {
    let p = if case_insensitive { pattern.to_ascii_lowercase() } else { pattern.to_string() };
    let v = if case_insensitive { value.to_ascii_lowercase() } else { value.to_string() };
    let p = p.as_bytes();
    let v = v.as_bytes();
    let mut pi = 0usize;
    let mut vi = 0usize;
    let mut star = None;
    let mut star_vi = 0usize;

    while vi < v.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            star_vi = vi;
            pi += 1;
        } else if let Some(star_pi) = star {
            star_vi += 1;
            vi = star_vi;
            pi = star_pi + 1;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' { pi += 1; }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permission(effect: Effect, action: &str, resource: &str, conditions: serde_json::Value) -> Permission {
        Permission { id: "p".into(), principal: "agent".into(), action: action.into(), resource: resource.into(), effect, conditions, provider: None }
    }

    #[test]
    fn supports_hierarchical_resource_patterns() {
        let model = AuthorizationModel { permissions: vec![permission(Effect::Allow, "read", "arn:aws:s3:::bucket/*", serde_json::json!({}))] };
        assert!(model.is_allowed("agent", "read", "arn:aws:s3:::bucket/prod/file"));
        assert!(!model.is_allowed("agent", "read", "arn:aws:s3:::other/file"));
    }

    #[test]
    fn conditional_allow_fails_closed_without_context() {
        let model = AuthorizationModel { permissions: vec![permission(Effect::Allow, "read", "prod/*", serde_json::json!({"StringEquals":{"env":"prod"}}))] };
        assert!(!model.is_allowed("agent", "read", "prod/db"));
    }

    #[test]
    fn conditional_allow_can_be_resolved_with_context() {
        let model = AuthorizationModel { permissions: vec![permission(Effect::Allow, "read", "prod/*", serde_json::json!({"StringEquals":{"env":"prod"}}))] };
        let context = HashMap::from([(String::from("env"), String::from("prod"))]);
        assert_eq!(model.evaluate("agent", "read", "prod/db", &context), AuthorizationDecision::Allow);
    }

    #[test]
    fn explicit_deny_wins_over_matching_allow() {
        let model = AuthorizationModel { permissions: vec![
            permission(Effect::Allow, "write", "prod/*", serde_json::json!({})),
            permission(Effect::Deny, "write", "prod/secrets/*", serde_json::json!({})),
        ]};
        assert!(!model.is_allowed("agent", "write", "prod/secrets/db"));
    }

    #[test]
    fn unsupported_condition_operator_is_indeterminate_and_denies() {
        let model = AuthorizationModel { permissions: vec![permission(Effect::Allow, "read", "*", serde_json::json!({"IpAddress":{"sourceIp":"10.0.0.1"}}))] };
        assert!(!model.is_allowed("agent", "read", "anything"));
    }
}
