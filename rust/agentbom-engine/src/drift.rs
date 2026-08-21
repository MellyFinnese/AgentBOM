use agentbom_core::SecurityGraph;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftFinding {
    pub drift_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub key: String,
}

pub fn analyze_drift(current: &SecurityGraph, baseline: &SecurityGraph) -> Vec<DriftFinding> {
    let diff = baseline.diff(current);
    let mut findings = Vec::new();

    for node in diff.added_nodes {
        let sensitive = matches!(node.kind.as_str(), "credential" | "permission" | "identity" | "tool")
            || node.name.to_lowercase().contains("prod");
        let severity = if sensitive { "high" } else { "medium" };
        findings.push(DriftFinding {
            drift_type: "added_entity".into(), severity: severity.into(),
            title: format!("New {} introduced", node.kind),
            description: format!("New entity '{}' was added to the security graph.", node.name),
            key: node.id,
        });
    }

    for edge in diff.added_edges {
        let high_impact = matches!(edge.kind.as_str(), "grants" | "accesses" | "assumes" | "delegates" | "writes");
        findings.push(DriftFinding {
            drift_type: "added_relationship".into(),
            severity: if high_impact { "high" } else { "medium" }.into(),
            title: format!("New {} relationship", edge.kind),
            description: format!("{} -> {} now exists.", edge.source, edge.target),
            key: format!("{}:{}:{}", edge.source, edge.kind, edge.target),
        });
    }

    for node in diff.removed_nodes {
        findings.push(DriftFinding {
            drift_type: "removed_entity".into(), severity: "low".into(),
            title: format!("{} removed", node.kind),
            description: format!("Entity '{}' is no longer present.", node.name),
            key: node.id,
        });
    }

    for edge in diff.removed_edges {
        findings.push(DriftFinding {
            drift_type: "removed_relationship".into(), severity: "low".into(),
            title: format!("{} relationship removed", edge.kind),
            description: format!("{} -> {} is no longer present.", edge.source, edge.target),
            key: format!("{}:{}:{}", edge.source, edge.kind, edge.target),
        });
    }

    findings.sort_by(|a, b| (&a.severity, &a.key).cmp(&(&b.severity, &b.key)));
    findings
}
