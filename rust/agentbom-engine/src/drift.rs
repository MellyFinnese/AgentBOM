use agentbom_core::SecurityGraph;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftFinding {
    pub drift_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub key: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

pub fn analyze_drift(current: &SecurityGraph, baseline: &SecurityGraph) -> Vec<DriftFinding> {
    let diff = baseline.diff(current);
    let mut findings = Vec::new();

    for node in diff.added_nodes {
        let (severity, reason) = entity_severity(&node.kind, &node.name, &node.properties);
        findings.push(DriftFinding {
            drift_type: "added_entity".into(), severity: severity.into(),
            title: format!("New {} introduced", node.kind),
            description: format!("New entity '{}' was added to the security graph.", node.name),
            key: node.id,
            evidence: vec![format!("sensitivity_reason={reason}")],
        });
    }

    for edge in diff.added_edges {
        let target = current.nodes.get(&edge.target);
        let (severity, reason) = relationship_severity(&edge.kind, target);
        findings.push(DriftFinding {
            drift_type: "added_relationship".into(),
            severity: severity.into(),
            title: format!("New {} relationship", edge.kind),
            description: format!("{} -> {} now exists.", edge.source, edge.target),
            key: format!("{}:{}:{}", edge.source, edge.kind, edge.target),
            evidence: vec![format!("target_kind={}", target.map(|n| n.kind.as_str()).unwrap_or("unknown")), format!("sensitivity_reason={reason}")],
        });
    }

    for node in diff.removed_nodes {
        findings.push(DriftFinding {
            drift_type: "removed_entity".into(), severity: "low".into(),
            title: format!("{} removed", node.kind),
            description: format!("Entity '{}' is no longer present.", node.name),
            key: node.id,
            evidence: Vec::new(),
        });
    }

    for edge in diff.removed_edges {
        findings.push(DriftFinding {
            drift_type: "removed_relationship".into(), severity: "low".into(),
            title: format!("{} relationship removed", edge.kind),
            description: format!("{} -> {} is no longer present.", edge.source, edge.target),
            key: format!("{}:{}:{}", edge.source, edge.kind, edge.target),
            evidence: Vec::new(),
        });
    }

    findings.sort_by(|a, b| (&a.severity, &a.key).cmp(&(&b.severity, &b.key)));
    findings
}

fn entity_severity(kind: &str, name: &str, properties: &serde_json::Value) -> (&'static str, String) {
    if let Some(sensitivity) = properties.get("sensitivity").and_then(|v| v.as_str()) {
        let normalized = sensitivity.to_ascii_lowercase();
        if normalized == "critical" { return ("critical", "explicit sensitivity metadata".into()); }
        if normalized == "high" { return ("high", "explicit sensitivity metadata".into()); }
    }
    match kind {
        "credential" | "permission" | "identity" => return ("high", format!("sensitive entity kind: {kind}")),
        "database" | "deployment" | "data_source" => {
            if ["prod", "production", "secret", "credential", "payment"].iter().any(|token| name.to_ascii_lowercase().contains(token)) {
                return ("critical", "name heuristic matched sensitive token".into());
            }
            return ("high", format!("high-impact entity kind: {kind}"));
        }
        "tool" => return ("high", "tool capability can change authority".into()),
        _ => {}
    }
    ("medium", "default entity classification".into())
}

fn relationship_severity(kind: &str, target: Option<&agentbom_core::Node>) -> (&'static str, String) {
    let (target_severity, target_reason) = target.map(|n| entity_severity(&n.kind, &n.name, &n.properties)).unwrap_or(("medium", "unknown target".into()));
    if matches!(kind, "grants" | "accesses" | "assumes" | "delegates" | "writes" | "reads" | "calls") {
        match target_severity {
            "critical" => return ("critical", format!("high-impact relationship to critical target; {target_reason}")),
            "high" => return ("high", format!("high-impact relationship to sensitive target; {target_reason}")),
            _ => return ("high", "high-impact relationship".into()),
        }
    }
    ("medium", format!("relationship kind {kind}"))
}
