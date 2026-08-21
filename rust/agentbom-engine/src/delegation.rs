use crate::authorization::{AuthorizationDecision, AuthorizationModel, Effect, Permission};
use agentbom_core::SecurityGraph;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityPath {
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub path: Vec<String>,
    pub hops: usize,
    #[serde(default)]
    pub decision: String,
    #[serde(default)]
    pub provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityFinding {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub path: Vec<String>,
}

pub fn effective_authority(graph: &SecurityGraph, principal: &str, max_hops: usize) -> Vec<AuthorityPath> {
    let mut principals = HashSet::from([principal.to_string()]);
    let mut queue = VecDeque::from([(principal.to_string(), vec![principal.to_string()], 0usize)]);
    let mut authority = Vec::new();

    while let Some((current, path, hops)) = queue.pop_front() {
        if hops >= max_hops { continue; }
        for edge in graph.edges.iter().filter(|e| e.source == current && matches!(e.kind.as_str(), "delegates" | "assumes" | "impersonates")) {
            if !principals.insert(edge.target.clone()) { continue; }
            let mut next_path = path.clone();
            next_path.push(edge.target.clone());
            queue.push_back((edge.target.clone(), next_path, hops + 1));
        }
    }

    let mut permissions = Vec::new();
    for node in graph.nodes.values().filter(|n| n.kind == "permission") {
        let effect = match node.properties.get("effect").and_then(|v| v.as_str()).unwrap_or("allow").to_ascii_lowercase().as_str() {
            "deny" => Effect::Deny,
            _ => Effect::Allow,
        };
        permissions.push(Permission {
            id: node.id.clone(),
            principal: node.properties.get("principal").and_then(|v| v.as_str()).unwrap_or(&node.name).to_string(),
            action: node.properties.get("action").and_then(|v| v.as_str()).unwrap_or("*").to_string(),
            resource: node.properties.get("resource").and_then(|v| v.as_str()).unwrap_or("*").to_string(),
            effect,
            conditions: node.properties.get("conditions").cloned().unwrap_or_else(|| serde_json::json!({})),
            provider: node.properties.get("provider").and_then(|v| v.as_str()).map(ToOwned::to_owned),
        });
    }
    let model = AuthorizationModel { permissions };

    for p in principals {
        for permission in model.permissions.iter().filter(|permission| permission.principal == p || permission.principal == "*") {
            if permission.effect == Effect::Deny { continue; }
            if shadowed_by_overlapping_deny(&model, permission) { continue; }
            let decision = model.evaluate(&p, &permission.action, &permission.resource, &HashMap::new());
            if !matches!(decision, AuthorizationDecision::Allow) { continue; }
            let path = graph_path_for_principal(graph, principal, &p, max_hops);
            authority.push(AuthorityPath {
                principal: p.clone(),
                action: permission.action.clone(),
                resource: permission.resource.clone(),
                hops: path.len().saturating_sub(1),
                path,
                decision: "allow".into(),
                provider: permission.provider.clone(),
            });
        }
    }
    authority
}

fn shadowed_by_overlapping_deny(model: &AuthorizationModel, allow: &Permission) -> bool {
    model.permissions.iter().any(|deny| {
        deny.effect == Effect::Deny
            && (deny.principal == allow.principal || deny.principal == "*")
            && patterns_overlap(&deny.action, &allow.action)
            && patterns_overlap(&deny.resource, &allow.resource)
            && (deny.conditions.is_null() || deny.conditions.as_object().is_some_and(|o| o.is_empty()))
    })
}

fn patterns_overlap(a: &str, b: &str) -> bool {
    if a == "*" || b == "*" || a.eq_ignore_ascii_case(b) { return true; }
    let a_prefix = a.split(['*', '?']).next().unwrap_or(a);
    let b_prefix = b.split(['*', '?']).next().unwrap_or(b);
    a_prefix.starts_with(b_prefix) || b_prefix.starts_with(a_prefix)
}

pub fn delegation_findings(graph: &SecurityGraph, principal: &str, max_hops: usize) -> Vec<AuthorityFinding> {
    effective_authority(graph, principal, max_hops).into_iter().filter(|a| a.hops > 0).map(|a| AuthorityFinding {
        rule_id: "AUTH-TRANSITIVE-DELEGATION".into(),
        severity: if a.action == "*" || a.resource == "*" { "high".into() } else { "medium".into() },
        title: "Authority is inherited through delegation".into(),
        description: format!("{principal} reaches {} on {} through {} delegation hop(s); decision={}.", a.action, a.resource, a.hops, a.decision),
        principal: a.principal,
        action: a.action,
        resource: a.resource,
        path: a.path,
    }).collect()
}

fn graph_path_for_principal(graph: &SecurityGraph, start: &str, target: &str, max_hops: usize) -> Vec<String> {
    if start == target { return vec![start.to_string()]; }
    let mut queue = VecDeque::from([(start.to_string(), vec![start.to_string()])]);
    let mut seen = HashSet::from([start.to_string()]);
    while let Some((current, path)) = queue.pop_front() {
        if path.len() > max_hops + 1 { continue; }
        for edge in graph.edges.iter().filter(|e| e.source == current && matches!(e.kind.as_str(), "delegates" | "assumes" | "impersonates")) {
            if edge.target == target { let mut found = path.clone(); found.push(target.to_string()); return found; }
            if seen.insert(edge.target.clone()) { let mut next = path.clone(); next.push(edge.target.clone()); queue.push_back((edge.target.clone(), next)); }
        }
    }
    vec![start.to_string(), target.to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentbom_core::{Edge, Node};

    fn node(id: &str, kind: &str, name: &str, properties: serde_json::Value) -> Node {
        Node { id: id.into(), kind: kind.into(), name: name.into(), properties }
    }

    #[test]
    fn resolves_transitive_authority() {
        let mut graph = SecurityGraph::default();
        graph.add_node(node("a", "agent", "agent", serde_json::json!({}))).unwrap();
        graph.add_node(node("b", "identity", "delegated", serde_json::json!({}))).unwrap();
        graph.add_node(node("p", "permission", "write-prod", serde_json::json!({"principal":"b","action":"write","resource":"prod","effect":"allow"}))).unwrap();
        graph.add_edge(Edge { source: "a".into(), kind: "delegates".into(), target: "b".into(), properties: serde_json::json!({}) }).unwrap();
        let paths = effective_authority(&graph, "a", 4);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].action, "write");
        assert_eq!(paths[0].decision, "allow");
    }

    #[test]
    fn denied_and_conditioned_permissions_do_not_become_effective_authority() {
        let mut graph = SecurityGraph::default();
        graph.add_node(node("a", "agent", "agent", serde_json::json!({}))).unwrap();
        graph.add_node(node("b", "identity", "delegated", serde_json::json!({}))).unwrap();
        graph.add_node(node("allow", "permission", "allow", serde_json::json!({"principal":"b","action":"write","resource":"prod/*","effect":"allow"}))).unwrap();
        graph.add_node(node("deny", "permission", "deny", serde_json::json!({"principal":"b","action":"write","resource":"prod/secrets/*","effect":"deny"}))).unwrap();
        graph.add_node(node("conditional", "permission", "conditional", serde_json::json!({"principal":"b","action":"read","resource":"prod/*","effect":"allow","conditions":{"StringEquals":{"env":"prod"}}}))).unwrap();
        graph.add_edge(Edge { source: "a".into(), kind: "delegates".into(), target: "b".into(), properties: serde_json::json!({}) }).unwrap();
        let paths = effective_authority(&graph, "a", 4);
        assert!(!paths.iter().any(|p| p.action == "read"));
        assert!(!paths.iter().any(|p| p.action == "write" && p.resource == "prod/*"));
    }
}
