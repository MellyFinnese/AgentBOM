use agentbom_core::{Edge, GraphDiff, Node, SecurityGraph};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Engine {
    graph: SecurityGraph,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineSummary {
    pub node_count: usize,
    pub edge_count: usize,
    pub snapshot_hash: String,
}

impl Engine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: Node) {
        self.graph.add_node(node);
    }

    pub fn add_edge(&mut self, edge: Edge) -> Result<(), String> {
        self.graph.add_edge(edge)
    }

    pub fn reachable(&self, start: &str, max_depth: usize) -> Vec<Vec<String>> {
        self.graph.reachable(start, max_depth)
    }

    pub fn snapshot_hash(&self) -> String {
        self.graph.snapshot_hash()
    }

    pub fn diff(&self, baseline: &Engine) -> GraphDiff {
        baseline.graph.diff(&self.graph)
    }

    pub fn summary(&self) -> EngineSummary {
        EngineSummary {
            node_count: self.graph.nodes.len(),
            edge_count: self.graph.edges.len(),
            snapshot_hash: self.snapshot_hash(),
        }
    }

    pub fn export_json(&self) -> Result<String, String> {
        serde_json::to_string(&self.graph).map_err(|err| err.to_string())
    }

    pub fn import_json(payload: &str) -> Result<Self, String> {
        let graph: SecurityGraph = serde_json::from_str(payload).map_err(|err| err.to_string())?;
        Ok(Self { graph })
    }

    pub fn stable_digest(&self) -> String {
        let payload = self.export_json().expect("engine graph is serializable");
        format!("{:x}", Sha256::digest(payload.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Engine {
        let mut engine = Engine::new();
        engine.add_node(Node { id: "agent".into(), kind: "agent".into(), name: "agent".into() });
        engine.add_node(Node { id: "data".into(), kind: "data_source".into(), name: "production-db".into() });
        engine.add_edge(Edge { source: "agent".into(), kind: "accesses".into(), target: "data".into() }).unwrap();
        engine
    }

    #[test]
    fn engine_is_stable() {
        let engine = sample();
        assert_eq!(engine.snapshot_hash(), engine.snapshot_hash());
        assert_eq!(engine.reachable("agent", 2).len(), 1);
        assert_eq!(engine.summary().node_count, 2);
    }

    #[test]
    fn engine_round_trips_json() {
        let engine = sample();
        let restored = Engine::import_json(&engine.export_json().unwrap()).unwrap();
        assert_eq!(engine.snapshot_hash(), restored.snapshot_hash());
    }
}
