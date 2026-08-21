use crate::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphQueryResult {
    pub start: String,
    pub target_kind: Option<String>,
    pub paths: Vec<Vec<String>>,
}

impl Engine {
    pub fn paths_to_kind(&self, start: &str, target_kind: &str, max_depth: usize) -> GraphQueryResult {
        let paths = self.reachable(start, max_depth).into_iter().filter(|path| {
            path.last().and_then(|id| self.node_kind(id)).as_deref() == Some(target_kind)
        }).collect();
        GraphQueryResult { start: start.into(), target_kind: Some(target_kind.into()), paths }
    }

    pub fn agents_reaching_kind(&self, target_kind: &str, max_depth: usize) -> Vec<GraphQueryResult> {
        self.agent_ids().into_iter().map(|agent| self.paths_to_kind(&agent, target_kind, max_depth)).filter(|r| !r.paths.is_empty()).collect()
    }

    fn node_kind(&self, id: &str) -> Option<String> {
        self.export_json().ok().and_then(|payload| serde_json::from_str::<serde_json::Value>(&payload).ok()).and_then(|value| {
            value.get("nodes")?.get(id)?.get("kind")?.as_str().map(ToOwned::to_owned)
        })
    }

    fn agent_ids(&self) -> Vec<String> {
        self.export_json().ok().and_then(|payload| serde_json::from_str::<serde_json::Value>(&payload).ok()).and_then(|value| value.get("nodes")?.as_object().map(|nodes| {
            nodes.iter().filter_map(|(id, node)| (node.get("kind").and_then(|v| v.as_str()) == Some("agent")).then(|| id.clone())).collect()
        })).unwrap_or_default()
    }
}
