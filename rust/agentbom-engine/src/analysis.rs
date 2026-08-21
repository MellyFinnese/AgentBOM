use agentbom_core::{Node, SecurityGraph};
use serde::{Deserialize, Serialize};

const HIGH_IMPACT_KINDS: &[&str] = &["credential", "data_source", "database", "deployment"];
const SENSITIVE_WORDS: &[&str] = &["prod", "production", "secret", "credential", "database", "admin"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyFinding {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub node_ids: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathResult {
    pub start: String,
    pub target: String,
    pub node_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactedResource {
    pub name: String,
    pub kind: String,
    pub distance: usize,
    pub path_count: usize,
    pub tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlastRadius {
    pub agent: String,
    pub score: u32,
    pub tier: String,
    pub resources: Vec<ImpactedResource>,
}

pub fn analyze_policy(graph: &SecurityGraph, max_depth: usize) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();
    for node in graph.nodes.values() {
        match node.kind.as_str() {
            "permission" => {
                let action = prop(node, "action");
                let resource = prop(node, "resource");
                if is_wildcard(&action) || is_wildcard(&resource) {
                    findings.push(PolicyFinding {
                        rule_id: "AUTH-WILDCARD".into(), severity: "high".into(),
                        title: "Wildcard authorization grant".into(),
                        description: format!("Permission grants broad scope: {action} on {resource}."),
                        node_ids: vec![node.id.clone()],
                        evidence: vec![format!("action={action}"), format!("resource={resource}")],
                    });
                }
                let lr = resource.to_lowercase();
                let la = action.to_lowercase();
                if ["write", "delete", "admin", "execute", "assume_role"].contains(&la.as_str())
                    && (lr.contains("prod") || lr.contains("production"))
                {
                    findings.push(PolicyFinding {
                        rule_id: "AUTH-PROD-WRITE".into(), severity: "critical".into(),
                        title: "Production modification authority".into(),
                        description: format!("A principal has {action} authority over {resource}."),
                        node_ids: vec![node.id.clone()],
                        evidence: vec![format!("action={action}"), format!("resource={resource}")],
                    });
                }
            }
            "credential" => {
                if prop(node, "secret").eq_ignore_ascii_case("true") && node.properties.get("source").is_some() {
                    findings.push(PolicyFinding {
                        rule_id: "CRED-CONFIG-EXPOSED".into(), severity: "high".into(),
                        title: "Credential material referenced by configuration".into(),
                        description: "A credential is represented as a configuration-backed secret.".into(),
                        node_ids: vec![node.id.clone()],
                        evidence: vec![format!("source={}", prop(node, "source"))],
                    });
                }
            }
            "tool" => {
                let operation = prop(node, "operation").to_lowercase();
                let description = prop(node, "description").to_lowercase();
                if ["execute", "delete", "assume_role", "admin", "write"].iter().any(|x| operation.contains(x))
                    || ["shell", "execute", "arbitrary command"].iter().any(|x| description.contains(x))
                {
                    findings.push(PolicyFinding {
                        rule_id: "TOOL-DANGEROUS-CAP".into(), severity: "high".into(),
                        title: "Dangerous tool capability".into(),
                        description: "A tool exposes a high-impact execution or mutation capability.".into(),
                        node_ids: vec![node.id.clone()],
                        evidence: vec![format!("operation={operation}")],
                    });
                }
            }
            _ => {}
        }
    }
    for agent in graph.nodes.values().filter(|n| n.kind == "agent") {
        for path in graph.reachable(&agent.id, max_depth) {
            let Some(target_id) = path.last() else { continue };
            let Some(target) = graph.nodes.get(target_id) else { continue };
            if !HIGH_IMPACT_KINDS.contains(&target.kind.as_str()) { continue; }
            let joined = path.iter().filter_map(|id| graph.nodes.get(id)).map(|n| n.name.clone()).collect::<Vec<_>>().join(" -> ");
            let lower = joined.to_lowercase();
            let severity = if SENSITIVE_WORDS.iter().any(|word| lower.contains(word)) { "critical" } else { "high" };
            findings.push(PolicyFinding {
                rule_id: "PATH-HIGH-IMPACT".into(), severity: severity.into(),
                title: "Agent has a reachable high-impact resource".into(),
                description: format!("The agent can traverse a graph path to {}: {}.", target.kind, target.name),
                node_ids: path, evidence: vec![joined],
            });
        }
    }
    findings.sort_by(|a, b| (&a.rule_id, &a.node_ids).cmp(&(&b.rule_id, &b.node_ids)));
    findings.dedup_by(|a, b| a.rule_id == b.rule_id && a.node_ids == b.node_ids);
    findings
}

pub fn attack_paths(graph: &SecurityGraph, max_depth: usize) -> Vec<PathResult> {
    let mut result = Vec::new();
    for agent in graph.nodes.values().filter(|n| n.kind == "agent") {
        for path in graph.reachable(&agent.id, max_depth) {
            let Some(target_id) = path.last() else { continue };
            let Some(target) = graph.nodes.get(target_id) else { continue };
            if HIGH_IMPACT_KINDS.contains(&target.kind.as_str()) {
                result.push(PathResult { start: agent.name.clone(), target: target.name.clone(), node_ids: path });
            }
        }
    }
    result
}

pub fn blast_radius(graph: &SecurityGraph, max_depth: usize) -> Vec<BlastRadius> {
    let mut results = Vec::new();
    for agent in graph.nodes.values().filter(|n| n.kind == "agent") {
        let mut resources: std::collections::HashMap<String, ImpactedResource> = std::collections::HashMap::new();
        for path in graph.reachable(&agent.id, max_depth) {
            let Some(target_id) = path.last() else { continue };
            let Some(target) = graph.nodes.get(target_id) else { continue };
            if !HIGH_IMPACT_KINDS.contains(&target.kind.as_str()) { continue; }
            let entry = resources.entry(target.id.clone()).or_insert_with(|| ImpactedResource {
                name: target.name.clone(), kind: target.kind.clone(), distance: usize::MAX, path_count: 0, tier: resource_tier(target),
            });
            entry.distance = entry.distance.min(path.len().saturating_sub(1));
            entry.path_count += 1;
        }
        let mut resources: Vec<_> = resources.into_values().collect();
        resources.sort_by(|a, b| (a.distance, &a.name).cmp(&(b.distance, &b.name)));
        let score = resources.iter().map(|r| match r.tier.as_str() { "critical" => 35, "high" => 20, "medium" => 10, _ => 5 }).sum::<u32>().min(100);
        let tier = if score >= 75 { "critical" } else if score >= 50 { "high" } else if score >= 25 { "medium" } else { "low" };
        results.push(BlastRadius { agent: agent.name.clone(), score, tier: tier.into(), resources });
    }
    results
}

fn prop(node: &Node, key: &str) -> String {
    node.properties.get(key).and_then(|v| v.as_str()).unwrap_or_default().to_string()
}

fn is_wildcard(value: &str) -> bool {
    matches!(value.to_lowercase().as_str(), "*" | "all" | "any" | "admin:*" | "*:*")
}

fn resource_tier(node: &Node) -> String {
    let value = format!("{} {}", node.kind, node.name).to_lowercase();
    if value.contains("prod") || value.contains("production") || value.contains("secret") || value.contains("credential") { "critical".into() }
    else if node.kind == "database" || node.kind == "deployment" || node.kind == "credential" { "high".into() }
    else { "medium".into() }
}
