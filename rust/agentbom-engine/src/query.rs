use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphQueryResult {
    pub start: String,
    pub target_kind: Option<String>,
    pub paths: Vec<Vec<String>>,
}
