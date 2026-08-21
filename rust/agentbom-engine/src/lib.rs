use agentbom_core::{Edge, GraphDiff, Node, SecurityGraph};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod adapters;
pub mod analysis;
pub mod attestation;
pub mod authorization;
pub mod backend;
pub mod correlation;
pub mod delegation;
pub mod drift;
pub mod enforcement;
pub mod graph_backend;
pub mod monitoring;
pub mod provider_adapters;
pub mod query;
pub mod runtime;
pub mod signing;

use analysis::{analyze_policy, attack_paths, blast_radius, BlastRadius, PathResult, PolicyFinding};
use drift::{analyze_drift, DriftFinding};
pub use adapters::{AuthorizationAdapter, AZURE_RBAC, AWS_IAM, GCP_IAM, KUBERNETES_RBAC, MCP_AUTH, OAUTH_SCOPES};
pub use attestation::Attestation;
pub use authorization::{AuthorizationModel, Effect, Permission};
pub use backend::{GraphBackend, JsonBackend};
pub use correlation::{correlate_findings, correlated_security_paths, CorrelatedFinding, SecurityPath};
pub use delegation::{delegation_findings, effective_authority, AuthorityFinding, AuthorityPath};
pub use enforcement::{Decision, PolicyDecision, PolicyRule};
pub use graph_backend::{CypherExporter, CypherStatement, GraphTransport, MemgraphTransport, Neo4jTransport};
pub use monitoring::{MonitoringReport, RuntimeSession};
pub use provider_adapters::{parse_aws_iam, parse_azure_rbac, parse_gcp_iam, parse_kubernetes_rbac, parse_mcp_auth, parse_oauth_scopes};
pub use query::GraphQueryResult;
pub use runtime::{RuntimeEvent, RuntimeFinding, RuntimeMonitor};
pub use signing::{canonical_attestation_bytes, AttestationSigner, DigestSigner};

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
    pub fn paths_to_kind(&self, start: &str, target_kind: &str, max_depth: usize) -> GraphQueryResult { self.query_paths_to_kind(start, target_kind, max_depth) }
    pub fn agents_reaching_kind(&self, target_kind: &str, max_depth: usize) -> Vec<GraphQueryResult> { self.graph.nodes.values().filter(|n| n.kind == "agent").map(|n| self.query_paths_to_kind(&n.id, target_kind, max_depth)).filter(|r| !r.paths.is_empty()).collect() }
    pub fn evaluate_policy(&self, action: &str, resource: &str, rules: &[PolicyRule]) -> PolicyDecision { enforcement::evaluate(self, action, resource, rules) }
    pub fn parse_authorization<A: AuthorizationAdapter>(&self, adapter: A, payload: &str) -> Result<AuthorizationModel, String> { adapter.parse_json(payload) }
    pub fn effective_authority(&self, principal: &str, max_hops: usize) -> Vec<AuthorityPath> { effective_authority(&self.graph, principal, max_hops) }
    pub fn delegation_findings(&self, principal: &str, max_hops: usize) -> Vec<AuthorityFinding> { delegation_findings(&self.graph, principal, max_hops) }
    pub fn correlated_security_paths(&self, principal: &str, max_hops: usize, max_depth: usize) -> Vec<SecurityPath> { correlated_security_paths(&self.graph, principal, max_hops, max_depth) }
    pub fn correlated_findings(&self, principal: &str, max_hops: usize, max_depth: usize) -> Vec<CorrelatedFinding> { correlate_findings(&self.graph, principal, max_hops, max_depth) }
}

impl Engine {
    fn query_paths_to_kind(&self, start: &str, target_kind: &str, max_depth: usize) -> GraphQueryResult {
        let paths = self.graph.reachable(start, max_depth).into_iter().filter(|path| path.last().and_then(|id| self.graph.nodes.get(id)).map(|node| node.kind.as_str() == target_kind).unwrap_or(false)).collect();
        GraphQueryResult { start: start.into(), target_kind: Some(target_kind.into()), paths }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Engine {
        let mut engine = Engine::new();
        engine.add_node(Node { id: "agent".into(), kind: "agent".into(), name: "agent".into(), properties: json!({}) });
        engine.add_node(Node { id: "permission".into(), kind: "permission".into(), name: "write production-db".into(), properties: json!({"principal":"agent","action":"write","resource":"production-db"}) });
        engine.add_node(Node { id: "data".into(), kind: "data_source".into(), name: "production-db".into(), properties: json!({}) });
        engine.add_edge(Edge { source: "agent".into(), kind: "grants".into(), target: "permission".into(), properties: json!({}) }).unwrap();
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
        assert_eq!(engine.paths_to_kind("agent", "data_source", 4).paths.len(), 1);
    }

    #[test]
    fn engine_round_trips_json() {
        let engine = sample();
        let restored = Engine::import_json(&engine.export_json().unwrap()).unwrap();
        assert_eq!(engine.snapshot_hash(), restored.snapshot_hash());
    }

    #[test]
    fn authority_analysis_exposes_direct_permission() {
        let engine = sample();
        let paths = engine.effective_authority("agent", 4);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].action, "write");
    }

    #[test]
    fn correlation_exposes_effective_security_path() {
        let engine = sample();
        let findings = engine.correlated_findings("agent", 4, 4);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "PATH-EFFECTIVE-AUTHORITY");
    }
}
