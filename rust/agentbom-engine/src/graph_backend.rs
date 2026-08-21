use crate::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphRecord {
    pub id: String,
    pub kind: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphRelation {
    pub source: String,
    pub relation: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CypherStatement {
    pub query: String,
    pub parameters: serde_json::Value,
}

pub trait GraphTransport {
    type Error;
    fn execute(&self, statement: &CypherStatement) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone)]
pub struct CypherExporter;

impl CypherExporter {
    pub fn export(engine: &Engine) -> Result<Vec<CypherStatement>, String> {
        let payload = engine.export_json()?;
        let graph: serde_json::Value = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
        let mut statements = Vec::new();
        if let Some(nodes) = graph.get("nodes").and_then(|v| v.as_object()) {
            for node in nodes.values() {
                let id = node.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let kind = node.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                let name = node.get("name").and_then(|v| v.as_str()).unwrap_or("");
                statements.push(CypherStatement {
                    query: "MERGE (n:AgentBOM {id: $id}) SET n.kind = $kind, n.name = $name".into(),
                    parameters: serde_json::json!({"id": id, "kind": kind, "name": name}),
                });
            }
        }
        if let Some(edges) = graph.get("edges").and_then(|v| v.as_array()) {
            for edge in edges {
                let source = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
                let target = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
                let relation = edge.get("kind").and_then(|v| v.as_str()).unwrap_or("RELATED_TO");
                let relation = relation.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect::<String>().to_ascii_uppercase();
                statements.push(CypherStatement {
                    query: format!("MATCH (a:AgentBOM {{id: $source}}), (b:AgentBOM {{id: $target}}) MERGE (a)-[:{relation}]->(b)"),
                    parameters: serde_json::json!({"source": source, "target": target}),
                });
            }
        }
        Ok(statements)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MemgraphTransport;
impl GraphTransport for MemgraphTransport {
    type Error = String;
    fn execute(&self, _statement: &CypherStatement) -> Result<(), Self::Error> {
        Err("Memgraph transport is intentionally dependency-free; provide a connector implementation over Bolt/HTTP.".into())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Neo4jTransport;
impl GraphTransport for Neo4jTransport {
    type Error = String;
    fn execute(&self, _statement: &CypherStatement) -> Result<(), Self::Error> {
        Err("Neo4j transport is intentionally dependency-free; provide a connector implementation over Bolt/HTTP.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentbom_core::{Edge, Node};

    #[test]
    fn exporter_uses_parameterized_cypher() {
        let mut engine = Engine::new();
        engine.add_node(Node { id: "a".into(), kind: "agent".into(), name: "agent".into(), properties: serde_json::json!({}) });
        engine.add_node(Node { id: "b".into(), kind: "data_source".into(), name: "prod".into(), properties: serde_json::json!({}) });
        engine.add_edge(Edge { source: "a".into(), kind: "accesses".into(), target: "b".into(), properties: serde_json::json!({}) }).unwrap();
        let statements = CypherExporter::export(&engine).unwrap();
        assert_eq!(statements.len(), 3);
        assert!(statements.iter().all(|s| s.query.contains("$")));
    }
}
