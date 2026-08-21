use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    pub id: String,
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub properties: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Edge {
    pub source: String,
    pub kind: String,
    pub target: String,
    #[serde(default)]
    pub properties: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityGraph {
    pub nodes: HashMap<String, Node>,
    pub edges: Vec<Edge>,
}

impl SecurityGraph {
    pub fn add_node(&mut self, node: Node) -> Result<(), String> {
        if node.id.trim().is_empty() || node.kind.trim().is_empty() {
            return Err("node id and kind must be non-empty".into());
        }
        if self.nodes.contains_key(&node.id) {
            return Err(format!("duplicate node id: {}", node.id));
        }
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    pub fn upsert_node(&mut self, node: Node) -> Result<(), String> {
        if node.id.trim().is_empty() || node.kind.trim().is_empty() {
            return Err("node id and kind must be non-empty".into());
        }
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    pub fn add_edge(&mut self, edge: Edge) -> Result<(), String> {
        if edge.source.trim().is_empty() || edge.target.trim().is_empty() || edge.kind.trim().is_empty() {
            return Err("edge source, kind and target must be non-empty".into());
        }
        if !self.nodes.contains_key(&edge.source) || !self.nodes.contains_key(&edge.target) {
            return Err("edge references unknown node".into());
        }
        if self.edges.iter().any(|existing| {
            existing.source == edge.source && existing.kind == edge.kind && existing.target == edge.target
        }) {
            return Err("duplicate relationship".into());
        }
        self.edges.push(edge);
        Ok(())
    }

    pub fn outgoing<'a>(&'a self, source: &'a str) -> impl Iterator<Item = &'a Edge> {
        self.edges.iter().filter(move |e| e.source == source)
    }

    pub fn reachable(&self, start: &str, max_depth: usize) -> Vec<Vec<String>> {
        self.reachable_limited(start, max_depth, usize::MAX)
    }

    pub fn reachable_limited(&self, start: &str, max_depth: usize, max_paths: usize) -> Vec<Vec<String>> {
        if !self.nodes.contains_key(start) || max_paths == 0 {
            return Vec::new();
        }
        let mut queue = VecDeque::from([(start.to_owned(), vec![start.to_owned()])]);
        let mut paths = Vec::new();
        while let Some((current, path)) = queue.pop_front() {
            if paths.len() >= max_paths || path.len().saturating_sub(1) >= max_depth { continue; }
            for edge in self.outgoing(&current) {
                if path.contains(&edge.target) { continue; }
                let mut next = path.clone();
                next.push(edge.target.clone());
                paths.push(next.clone());
                if paths.len() >= max_paths { break; }
                queue.push_back((edge.target.clone(), next));
            }
        }
        paths
    }

    pub fn snapshot_hash(&self) -> String {
        let mut nodes: Vec<_> = self.nodes.values().cloned().collect();
        nodes.sort_by(|a, b| a.id.cmp(&b.id));
        let mut edges = self.edges.clone();
        edges.sort_by(|a, b| (&a.source, &a.kind, &a.target).cmp(&(&b.source, &b.kind, &b.target)));
        let payload = serde_json::to_vec(&(nodes, edges)).expect("serializable graph");
        format!("{:x}", Sha256::digest(payload))
    }

    pub fn diff(&self, current: &Self) -> GraphDiff {
        let baseline_ids: HashSet<&str> = self.nodes.keys().map(String::as_str).collect();
        let current_ids: HashSet<&str> = current.nodes.keys().map(String::as_str).collect();
        let mut added_nodes = Vec::new();
        let mut removed_nodes = Vec::new();
        let mut changed_nodes = Vec::new();
        for (id, node) in &current.nodes {
            match self.nodes.get(id) {
                None => added_nodes.push(node.clone()),
                Some(previous) if previous != node => changed_nodes.push(NodeChange { before: previous.clone(), after: node.clone() }),
                _ => {}
            }
        }
        for (id, node) in &self.nodes {
            if !current_ids.contains(id.as_str()) { removed_nodes.push(node.clone()); }
        }

        let baseline_edges: HashSet<(&str, &str, &str)> = self.edges.iter().map(|e| (e.source.as_str(), e.kind.as_str(), e.target.as_str())).collect();
        let current_edges: HashSet<(&str, &str, &str)> = current.edges.iter().map(|e| (e.source.as_str(), e.kind.as_str(), e.target.as_str())).collect();
        let added_edges = current.edges.iter().filter(|e| !baseline_edges.contains(&(e.source.as_str(), e.kind.as_str(), e.target.as_str()))).cloned().collect();
        let removed_edges = self.edges.iter().filter(|e| !current_edges.contains(&(e.source.as_str(), e.kind.as_str(), e.target.as_str()))).cloned().collect();

        added_nodes.sort_by(|a, b| a.id.cmp(&b.id));
        removed_nodes.sort_by(|a, b| a.id.cmp(&b.id));
        changed_nodes.sort_by(|a, b| a.after.id.cmp(&b.after.id));
        GraphDiff { added_nodes, removed_nodes, changed_nodes, added_edges, removed_edges }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphDiff {
    pub added_nodes: Vec<Node>,
    pub removed_nodes: Vec<Node>,
    #[serde(default)]
    pub changed_nodes: Vec<NodeChange>,
    pub added_edges: Vec<Edge>,
    pub removed_edges: Vec<Edge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeChange {
    pub before: Node,
    pub after: Node,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, kind: &str, name: &str) -> Node { Node { id: id.into(), kind: kind.into(), name: name.into(), properties: serde_json::json!({}) } }

    #[test]
    fn graph_rejects_duplicate_relationships() {
        let mut graph = SecurityGraph::default();
        graph.add_node(node("a", "agent", "agent")).unwrap();
        graph.add_node(node("b", "data", "prod-db")).unwrap();
        let edge = Edge { source: "a".into(), kind: "accesses".into(), target: "b".into(), properties: serde_json::json!({}) };
        graph.add_edge(edge.clone()).unwrap();
        assert!(graph.add_edge(edge).is_err());
    }

    #[test]
    fn graph_limits_path_explosion() {
        let mut graph = SecurityGraph::default();
        for id in ["a", "b", "c", "d"] { graph.add_node(node(id, "node", id)).unwrap(); }
        graph.add_edge(Edge { source: "a".into(), kind: "r".into(), target: "b".into(), properties: serde_json::json!({}) }).unwrap();
        graph.add_edge(Edge { source: "a".into(), kind: "r".into(), target: "c".into(), properties: serde_json::json!({}) }).unwrap();
        graph.add_edge(Edge { source: "b".into(), kind: "r".into(), target: "d".into(), properties: serde_json::json!({}) }).unwrap();
        graph.add_edge(Edge { source: "c".into(), kind: "r".into(), target: "d".into(), properties: serde_json::json!({}) }).unwrap();
        assert_eq!(graph.reachable_limited("a", 3, 2).len(), 2);
    }

    #[test]
    fn diff_detects_node_property_changes() {
        let mut baseline = SecurityGraph::default();
        baseline.add_node(node("a", "agent", "agent")).unwrap();
        let mut current = baseline.clone();
        current.nodes.get_mut("a").unwrap().properties = serde_json::json!({"authority":"admin"});
        let diff = baseline.diff(&current);
        assert_eq!(diff.changed_nodes.len(), 1);
    }
}
