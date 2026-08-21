use agentbom_core::{Edge, GraphDiff, Node, SecurityGraph};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod analysis;
pub mod drift;
use analysis::{analyze_policy, attack_paths, blast_radius, BlastRadius, PathResult, PolicyFinding};
use drift::{analyze_drift, DriftFinding};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Engine { graph: SecurityGraph }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineSummary { pub node_count: usize, pub edge_count: usize, pub snapshot_hash: String }

impl Engine {
    pub fn new() -> Self { Self::default() }
    pub fn add_node(&mut self, node: Node) { self.graph.add_node(node); }
    pub fn add_edge(&mut self, edge: Edge) -> Result<(), String> { self.graph.add_edge(edge) }
    pub fn reachable(&self, start: &str, max_depth: usize) -> Vec<Vec<String>> { self.graph.reachable(start, max_depth) }
    pub fn snapshot_hash(&self) -> String { self.graph.snapshot_hash() }
    pub fn diff(&self, baseline: &Engine) -> GraphDiff { baseline.graph.diff(&self.graph) }
    pub fn summary(&self) -> EngineSummary { EngineSummary { node_count: self.graph.nodes.len(), edge_count: self.graph.edges.len(), snapshot_hash: self.snapshot_hash() } }
    pub fn export_json(&self) -> Result<String, String> { serde_json::to_string(&self.graph).map_err(|err| err.to_string()) }
    pub fn import_json(payload: &str) -> Result<Self, String> { serde_json::from_str(payload).map(|graph| Self { graph }).map_err(|err| err.to_string()) }
    pub fn stable_digest(&self) -> String { let payload = self.export_json().expect("engine graph is serializable"); format!("{:x}", Sha256::digest(payload.as_bytes())) }
    pub fn policy_findings(&self, max_depth: usize) -> Vec<PolicyFinding> { analyze_policy(&self.graph, max_depth) }
    pub fn attack_paths(&self, max_depth: usize) -> Vec<PathResult> { attack_paths(&self.graph, max_depth) }
    pub fn blast_radius(&self, max_depth: usize) -> Vec<BlastRadius> { blast_radius(&self.graph, max_depth) }
    pub fn drift_findings(&self, baseline: &Engine) -> Vec<DriftFinding> { analyze_drift(&self.graph, &baseline.graph) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Engine {
        let mut engine = Engine::new();
        engine.add_node(Node { id: "agent".into(), kind: "agent".into(), name: "agent".into(), properties: json!({}) });
        engine.add_node(Node { id: "permission".into(), kind: "permission".into(), name: "write production-db".into(), properties: json!({"action":"write","resource":"production-db"}) });
        engine.add_node(Node { id: "data".into(), kind: "data_source".into(), name: "production-db".into(), properties: json!({}) });
        engine.add_edge(Edge { source: "agent".into(), kind: "uses".into(), target: "permission".into(), properties: json!({}) }).unwrap();
        engine.add_edge(Edge { source: "permission".into(), kind: "accesses".into(), target: "data".into(), properties: json!({}) }).unwrap();
        engine
    }

    #[test]
    fn engine_is_stable() {
        let engine = sample();
        assert_eq!(engine.snapshot_hash(), engine.snapshot_hash());
        assert!(!engine.attack_paths(4).is_empty());
        assert!(engine.policy_findings(4).iter().any(|f| f.rule_id == "PATH-HIGH-IMPACT"));
        assert_eq!(engine.summary().node_count, 3);
    }

    #[test]
    fn engine_round_trips_json() {
        let engine = sample();
        let restored = Engine::import_json(&engine.export_json().unwrap()).unwrap();
        assert_eq!(engine.snapshot_hash(), restored.snapshot_hash());
    }

    #[test]
    fn drift_detects_new_permission() {
        let baseline = sample();
        let mut current = baseline.clone();
        current.add_node(Node { id: "new-permission".into(), kind: "permission".into(), name: "admin production".into(), properties: json!({"action":"admin","resource":"production"}) });
        let findings = current.drift_findings(&baseline);
        assert!(findings.iter().any(|f| f.severity == "high" && f.key == "new-permission"));
    }
}
