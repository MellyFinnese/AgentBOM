use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Node {
    pub id: String,
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub properties: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
    pub fn add_node(&mut self, node: Node) {
        self.nodes.insert(node.id.clone(), node);
    }

    pub fn add_edge(&mut self, edge: Edge) -> Result<(), String> {
        if !self.nodes.contains_key(&edge.source) || !self.nodes.contains_key(&edge.target) {
            return Err("edge references unknown node".into());
        }
        self.edges.push(edge);
        Ok(())
    }

    pub fn outgoing<'a>(&'a self, source: &'a str) -> impl Iterator<Item = &'a Edge> {
        self.edges.iter().filter(move |e| e.source == source)
    }

    pub fn reachable(&self, start: &str, max_depth: usize) -> Vec<Vec<String>> {
        let mut queue = VecDeque::from([(start.to_owned(), vec![start.to_owned()])]);
        let mut paths = Vec::new();
        while let Some((current, path)) = queue.pop_front() {
            if path.len().saturating_sub(1) >= max_depth {
                continue;
            }
            for edge in self.outgoing(&current) {
                if path.contains(&edge.target) {
                    continue;
                }
                let mut next = path.clone();
                next.push(edge.target.clone());
                paths.push(next.clone());
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

    pub fn diff(&self, other: &Self) -> GraphDiff {
        let self_nodes: HashSet<_> = self.nodes.values().collect();
        let other_nodes: HashSet<_> = other.nodes.values().collect();
        let self_edges: HashSet<_> = self.edges.iter().collect();
        let other_edges: HashSet<_> = other.edges.iter().collect();
        GraphDiff {
            added_nodes: other_nodes.difference(&self_nodes).cloned().cloned().collect(),
            removed_nodes: self_nodes.difference(&other_nodes).cloned().cloned().collect(),
            added_edges: other_edges.difference(&self_edges).cloned().cloned().collect(),
            removed_edges: self_edges.difference(&other_edges).cloned().cloned().collect(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphDiff {
    pub added_nodes: Vec<Node>,
    pub removed_nodes: Vec<Node>,
    pub added_edges: Vec<Edge>,
    pub removed_edges: Vec<Edge>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, kind: &str, name: &str) -> Node {
        Node { id: id.into(), kind: kind.into(), name: name.into(), properties: serde_json::json!({}) }
    }

    #[test]
    fn graph_is_deterministic() {
        let mut graph = SecurityGraph::default();
        graph.add_node(node("a", "agent", "agent"));
        graph.add_node(node("b", "data", "prod-db"));
        graph.add_edge(Edge { source: "a".into(), kind: "accesses".into(), target: "b".into(), properties: serde_json::json!({}) }).unwrap();
        assert_eq!(graph.snapshot_hash(), graph.snapshot_hash());
        assert_eq!(graph.reachable("a", 2), vec![vec!["a".into(), "b".into()]]);
    }
}
