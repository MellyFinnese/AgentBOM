use crate::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attestation {
    pub schema_version: String,
    pub created_at: String,
    pub engine_version: String,
    pub graph_digest: String,
    pub summary: String,
}

impl Engine {
    pub fn attest(&self, created_at: impl Into<String>, engine_version: impl Into<String>) -> Attestation {
        Attestation {
            schema_version: "1".into(),
            created_at: created_at.into(),
            engine_version: engine_version.into(),
            graph_digest: self.stable_digest(),
            summary: format!("nodes={},edges={}", self.summary().node_count, self.summary().edge_count),
        }
    }

    pub fn attestation_digest(attestation: &Attestation) -> String {
        let payload = serde_json::to_vec(attestation).expect("attestation serializable");
        format!("{:x}", Sha256::digest(payload))
    }
}
