use crate::delegation::effective_authority;
use agentbom_core::SecurityGraph;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityPath {
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub path: Vec<String>,
    pub delegated: bool,
    pub hops: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelatedFinding {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub path: Vec<String>,
    pub evidence: Vec<String>,
}

pub fn correlated_security_paths(graph: &SecurityGraph, principal: &str, max_hops: usize, max_depth: usize) -> Vec<SecurityPath> {
    let mut output = Vec::new();
    let authorities = effective_authority(graph, principal, max_hops);
    for authority in authorities {
        for (path, terminal) in reachable_terminals(graph, &authority.principal, max_depth) {
            let kind = graph.nodes.get(&terminal).map(|n| n.kind.as_str()).unwrap_or("");
            if matches!(kind, "data_source" | "api" | "deployment" | "runtime") {
                let mut combined = authority.path.clone();
                for id in path.iter().skip(1) {
                    if combined.last() != Some(id) { combined.push(id.clone()); }
                }
                output.push(SecurityPath {
                    principal: authority.principal.clone(),
                    action: authority.action.clone(),
                    resource: authority.resource.clone(),
                    delegated: authority.hops > 0,
                    hops: combined.len().saturating_sub(1),
                    path: combined,
                });
            }
        }
    }
    output.sort_by(|a, b| a.path.cmp(&b.path));
    output.dedup_by(|a, b| a.path == b.path && a.action == b.action && a.resource == b.resource);
    output
}

pub fn correlate_findings(graph: &SecurityGraph, principal: &str, max_hops: usize, max_depth: usize) -> Vec<CorrelatedFinding> {
    correlated_security_paths(graph, principal, max_hops, max_depth)
        .into_iter()
        .map(|path| {
            let wildcard = path.action == "*" || path.resource == "*";
            let severity = if path.delegated && wildcard { "critical" } else if path.delegated { "high" } else if wildcard { "high" } else { "medium" };
            CorrelatedFinding {
                rule_id: if path.delegated { "PATH-DELEGATED-AUTHORITY" } else { "PATH-EFFECTIVE-AUTHORITY" }.into(),
                severity: severity.into(),
                title: if path.delegated { "Delegated authority creates a reachable security path" } else { "Effective authority creates a reachable security path" }.into(),
                description: format!("{} can reach {} with action {} through a {} hop path.", path.principal, path.resource, path.action, path.hops),
                principal: path.principal.clone(),
                action: path.action.clone(),
                resource: path.resource.clone(),
                evidence: path.path.clone(),
                path: path.path,
            }
        })
        .collect()
}

fn reachable_terminals(graph: &SecurityGraph, start: &str, max_depth: usize) -> Vec<(Vec<String>, String)> {
    let mut queue = VecDeque::from([(start.to_string(), vec![start.to_string()], 0usize)]);
    let mut seen = HashSet::from([start.to_string()]);
    let mut out = Vec::new();
    while let Some((current, path, depth)) = queue.pop_front() {
        if depth >= max_depth { continue; }
        for edge in graph.edges.iter().filter(|e| e.source == current) {
            if !seen.insert(edge.target.clone()) { continue; }
            let mut next = path.clone();
            next.push(edge.target.clone());
            out.push((next.clone(), edge.target.clone()));
            queue.push_back((edge.target.clone(), next, depth + 1));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentbom_core::{Edge, Node, SecurityGraph};

    #[test]
    fn correlates_delegated_permission_to_resource() {
        let mut graph = SecurityGraph::default();
        graph.add_node(Node { id: "agent".into(), kind: "agent".into(), name: "agent".into(), properties: serde_json::json!({}) });
        graph.add_node(Node { id: "role".into(), kind: "identity".into(), name: "role".into(), properties: serde_json::json!({}) });
        graph.add_node(Node { id: "perm".into(), kind: "permission".into(), name: "write-prod".into(), properties: serde_json::json!({"principal":"role","action":"write","resource":"prod"}) });
        graph.add_node(Node { id: "db".into(), kind: "data_source".into(), name: "prod".into(), properties: serde_json::json!({}) });
        graph.add_edge(Edge { source: "agent".into(), kind: "delegates".into(), target: "role".into(), properties: serde_json::json!({}) }).unwrap();
        graph.add_edge(Edge { source: "role".into(), kind: "grants".into(), target: "perm".into(), properties: serde_json::json!({}) }).unwrap();
        graph.add_edge(Edge { source: "perm".into(), kind: "accesses".into(), target: "db".into(), properties: serde_json::json!({}) }).unwrap();
        let findings = correlate_findings(&graph, "agent", 4, 6);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, "high");
    }
}
