use agentbom_core::{Node, SecurityGraph};
use serde::{Deserialize, Serialize};

const HIGH_IMPACT_KINDS: &[&str] = &["credential", "data_source", "database", "deployment"];
const ANALYSIS_PATH_CAP: usize = 10_000;
const SENSITIVE_WORDS: &[&str] = &["prod", "production", "secret", "credential", "payment"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyFinding {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub node_ids: Vec<String>,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub likelihood: String,
    #[serde(default)]
    pub confidence: String,
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
    #[serde(default)]
    pub sensitivity_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlastRadius {
    pub agent: String,
    pub score: u32,
    pub tier: String,
    pub resources: Vec<ImpactedResource>,
    #[serde(default)]
    pub score_model: String,
}

fn finding(
    rule_id: &str,
    severity: &str,
    title: &str,
    description: String,
    node_ids: Vec<String>,
    evidence: Vec<String>,
) -> PolicyFinding {
    let confidence = if evidence.is_empty() { "low" } else { "high" };
    let likelihood = match severity {
        "critical" => "high",
        "high" => "medium-high",
        "medium" => "medium",
        _ => "low",
    };
    PolicyFinding {
        rule_id: rule_id.into(),
        severity: severity.into(),
        title: title.into(),
        description,
        node_ids,
        evidence,
        likelihood: likelihood.into(),
        confidence: confidence.into(),
    }
}

pub fn analyze_policy(graph: &SecurityGraph, max_depth: usize) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();
    for node in graph.nodes.values() {
        match node.kind.as_str() {
            "permission" => {
                let action = prop(node, "action");
                let resource = prop(node, "resource");
                if is_wildcard(&action) || is_wildcard(&resource) {
                    findings.push(finding(
                        "AUTH-WILDCARD", "high", "Wildcard authorization grant",
                        format!("Permission grants broad scope: {action} on {resource}."),
                        vec![node.id.clone()], vec![format!("action={action}"), format!("resource={resource}")],
                    ));
                }
                let lr = resource.to_lowercase();
                let la = action.to_lowercase();
                if ["write", "delete", "admin", "execute", "assume_role"].contains(&la.as_str())
                    && (lr.contains("prod") || lr.contains("production"))
                {
                    findings.push(finding(
                        "AUTH-PROD-WRITE", "critical", "Production modification authority",
                        format!("A principal has {action} authority over {resource}."),
                        vec![node.id.clone()], vec![format!("action={action}"), format!("resource={resource}")],
                    ));
                }
            }
            "credential" => {
                if prop(node, "secret").eq_ignore_ascii_case("true") && node.properties.get("source").is_some() {
                    findings.push(finding(
                        "CRED-CONFIG-EXPOSED", "high", "Credential material referenced by configuration",
                        "A credential is represented as a configuration-backed secret.".into(),
                        vec![node.id.clone()], vec![format!("source={}", prop(node, "source"))],
                    ));
                }
            }
            "tool" => {
                let operation = prop(node, "operation").to_lowercase();
                let description = prop(node, "description").to_lowercase();
                if ["execute", "delete", "assume_role", "admin", "write"].iter().any(|x| operation.contains(x))
                    || ["shell", "execute", "arbitrary command"].iter().any(|x| description.contains(x))
                {
                    findings.push(finding(
                        "TOOL-DANGEROUS-CAP", "high", "Dangerous tool capability",
                        "A tool exposes a high-impact execution or mutation capability.".into(),
                        vec![node.id.clone()], vec![format!("operation={operation}")],
                    ));
                }
            }
            _ => {}
        }
    }

    for agent in graph.nodes.values().filter(|n| n.kind == "agent") {
        for path in graph.reachable_limited_mode(&agent.id, max_depth, ANALYSIS_PATH_CAP, "can") {
            let Some(target_id) = path.last() else { continue };
            let Some(target) = graph.nodes.get(target_id) else { continue; };
            if !HIGH_IMPACT_KINDS.contains(&target.kind.as_str()) { continue; }
            let joined = path.iter().filter_map(|id| graph.nodes.get(id)).map(|n| n.name.clone()).collect::<Vec<_>>().join(" -> ");
            let (tier, reason) = resource_tier(target);
            let severity = match tier.as_str() {
                "critical" => "critical",
                "high" => "high",
                _ => "medium",
            };
            let mut evidence = vec![joined.clone(), format!("sensitivity={tier}")];
            if !reason.is_empty() { evidence.push(format!("sensitivity_reason={reason}")); }
            findings.push(finding(
                "PATH-HIGH-IMPACT", severity,
                "Agent has a reachable high-impact resource",
                format!("The agent has a CAN-qualified graph path to {}: {}.", target.kind, target.name),
                path,
                evidence,
            ));
        }
    }
    findings.sort_by(|a, b| (&a.rule_id, &a.node_ids).cmp(&(&b.rule_id, &b.node_ids)));
    findings.dedup_by(|a, b| a.rule_id == b.rule_id && a.node_ids == b.node_ids);
    findings
}

pub fn attack_paths(graph: &SecurityGraph, max_depth: usize) -> Vec<PathResult> {
    let mut result = Vec::new();
    for agent in graph.nodes.values().filter(|n| n.kind == "agent") {
        for path in graph.reachable_limited_mode(&agent.id, max_depth, ANALYSIS_PATH_CAP, "can") {
            let Some(target_id) = path.last() else { continue; };
            let Some(target) = graph.nodes.get(target_id) else { continue; };
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
        for path in graph.reachable_limited_mode(&agent.id, max_depth, ANALYSIS_PATH_CAP, "can") {
            let Some(target_id) = path.last() else { continue; };
            let Some(target) = graph.nodes.get(target_id) else { continue; };
            if !HIGH_IMPACT_KINDS.contains(&target.kind.as_str()) { continue; }
            let (tier, reason) = resource_tier(target);
            let entry = resources.entry(target.id.clone()).or_insert_with(|| ImpactedResource {
                name: target.name.clone(), kind: target.kind.clone(), distance: usize::MAX, path_count: 0, tier: tier.clone(), sensitivity_reason: reason.clone(),
            });
            entry.distance = entry.distance.min(path.len().saturating_sub(1));
            entry.path_count = entry.path_count.saturating_add(1);
        }
        let mut resources: Vec<_> = resources.into_values().collect();
        resources.sort_by(|a, b| (a.distance, &a.name).cmp(&(b.distance, &b.name)));

        // This is deliberately an impact score, not a probabilistic risk score. Sensitive
        // resources establish severity floors so a single production/secret target cannot be
        // diluted by graph distance or by a larger number of medium targets.
        let additive = resources.iter().map(|r| match r.tier.as_str() { "critical" => 40, "high" => 20, "medium" => 10, _ => 5 }).sum::<u32>().min(100);
        let floor = resources.iter().map(|r| match r.tier.as_str() { "critical" => 80, "high" => 50, "medium" => 25, _ => 0 }).max().unwrap_or(0);
        let score = additive.max(floor).min(100);
        let tier = if score >= 80 { "critical" } else if score >= 50 { "high" } else if score >= 25 { "medium" } else { "low" };
        results.push(BlastRadius { agent: agent.name.clone(), score, tier: tier.into(), resources, score_model: "graph-impact-v2".into() });
    }
    results
}

fn prop(node: &Node, key: &str) -> String {
    node.properties.get(key).and_then(|v| v.as_str()).unwrap_or_default().to_string()
}

fn is_wildcard(value: &str) -> bool {
    matches!(value.to_lowercase().as_str(), "*" | "all" | "any" | "admin:*" | "*:*")
}

fn resource_tier(node: &Node) -> (String, String) {
    if let Some(explicit) = node.properties.get("sensitivity").and_then(|v| v.as_str()) {
        let tier = explicit.to_ascii_lowercase();
        if matches!(tier.as_str(), "critical" | "high" | "medium" | "low") {
            return (tier, "explicit sensitivity metadata".into());
        }
    }
    match node.kind.as_str() {
        "credential" => return ("critical".into(), "credential resource kind".into()),
        "database" | "deployment" => {
            let name = node.name.to_ascii_lowercase();
            if SENSITIVE_WORDS.iter().any(|token| name.contains(token)) {
                return ("critical".into(), format!("name heuristic matched one of: {}", SENSITIVE_WORDS.join(", ")));
            }
            return ("high".into(), "high-impact resource kind".into());
        }
        "data_source" => return ("high".into(), "data source resource kind".into()),
        _ => {}
    }
    ("medium".into(), "default resource classification".into())
}
