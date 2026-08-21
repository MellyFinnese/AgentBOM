use agentbom_core::SecurityGraph;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityPath {
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub path: Vec<String>,
    pub hops: usize,
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

    for p in principals {
        for node in graph.nodes.values().filter(|n| n.kind == "permission") {
            let principal_match = node.properties.get("principal").and_then(|v| v.as_str()).unwrap_or(&node.name) == p;
            if !principal_match { continue; }
            let action = node.properties.get("action").and_then(|v| v.as_str()).unwrap_or("*").to_string();
            let resource = node.properties.get("resource").and_then(|v| v.as_str()).unwrap_or("*").to_string();
            let path = graph_path_for_principal(graph, principal, &p, max_hops);
            authority.push(AuthorityPath { principal: p.clone(), action, resource, hops: path.len().saturating_sub(1), path });
        }
    }
    authority
}

pub fn delegation_findings(graph: &SecurityGraph, principal: &str, max_hops: usize) -> Vec<AuthorityFinding> {
    effective_authority(graph, principal, max_hops).into_iter().filter(|a| a.hops > 0).map(|a| AuthorityFinding {
        rule_id: "AUTH-TRANSITIVE-DELEGATION".into(),
        severity: if a.action == "*" || a.resource == "*" { "high".into() } else { "medium".into() },
        title: "Authority is inherited through delegation".into(),
        description: format!("{principal} reaches {} on {} through {} delegation hop(s).", a.action, a.resource, a.hops),
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

    #[test]
    fn resolves_transitive_authority() {
        let mut graph = SecurityGraph::default();
        graph.add_node(Node { id: "a".into(), kind: "agent".into(), name: "agent".into(), properties: serde_json::json!({}) });
        graph.add_node(Node { id: "b".into(), kind: "identity".into(), name: "delegated".into(), properties: serde_json::json!({}) });
        graph.add_node(Node { id: "p".into(), kind: "permission".into(), name: "write-prod".into(), properties: serde_json::json!({"principal":"b","action":"write","resource":"prod"}) });
        graph.add_edge(Edge { source: "a".into(), kind: "delegates".into(), target: "b".into(), properties: serde_json::json!({}) }).unwrap();
        graph.add_edge(Edge { source: "b".into(), kind: "grants".into(), target: "p".into(), properties: serde_json::json!({}) }).unwrap();
        let paths = effective_authority(&graph, "a", 4);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].action, "write");
    }
}
