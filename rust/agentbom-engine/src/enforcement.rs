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

pub fn evaluate(_engine: &Engine, action: &str, resource: &str, rules: &[PolicyRule]) -> PolicyDecision {
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

fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern.eq_ignore_ascii_case(value) {
        return true;
    }
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return false;
    }
    let mut remainder = value;
    if !parts[0].is_empty() {
        if !remainder.to_ascii_lowercase().starts_with(&parts[0].to_ascii_lowercase()) {
            return false;
        }
        remainder = &remainder[parts[0].len()..];
    }
    for (index, part) in parts.iter().enumerate().skip(1) {
        if part.is_empty() {
            continue;
        }
        let is_last = index == parts.len() - 1;
        let lower = remainder.to_ascii_lowercase();
        let needle = part.to_ascii_lowercase();
        if is_last {
            return lower.ends_with(&needle);
        }
        let Some(position) = lower.find(&needle) else { return false; };
        remainder = &remainder[position + part.len()..];
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_patterns_match_subresources() {
        assert!(matches_pattern("production/*", "production/db"));
        assert!(matches_pattern("prod-*", "prod-db"));
        assert!(matches_pattern("*/write", "database/write"));
        assert!(!matches_pattern("production/*", "staging/db"));
    }
}
