use crate::Engine;
use serde_json::Value;

pub fn export_cypher(engine: &Engine) -> String {
    let payload = engine.export_json().unwrap_or_else(|_| "{\"nodes\":{},\"edges\":[]}".into());
    let value: Value = serde_json::from_str(&payload).unwrap_or(Value::Null);
    let mut out = String::new();
    if let Some(nodes) = value.get("nodes").and_then(Value::as_object) {
        let mut ids: Vec<_> = nodes.keys().collect();
        ids.sort();
        for id in ids {
            if let Some(node) = nodes.get(id) {
                let kind = node.get("kind").and_then(Value::as_str).unwrap_or("entity");
                let name = node.get("name").and_then(Value::as_str).unwrap_or("");
                out.push_str(&format!("MERGE (n:AgentBOM {{id: {id:?}}}) SET n.kind = {kind:?}, n.name = {name:?};\n"));
            }
        }
    }
    if let Some(edges) = value.get("edges").and_then(Value::as_array) {
        for edge in edges {
            let source = edge.get("source").and_then(Value::as_str).unwrap_or("");
            let target = edge.get("target").and_then(Value::as_str).unwrap_or("");
            let kind = edge.get("kind").and_then(Value::as_str).unwrap_or("RELATED_TO").replace('-', "_").replace(' ', "_").to_ascii_uppercase();
            out.push_str(&format!("MATCH (a:AgentBOM {{id: {source:?}}}), (b:AgentBOM {{id: {target:?}}}) CREATE (a)-[:{kind}]->(b);\n"));
        }
    }
    out
}
