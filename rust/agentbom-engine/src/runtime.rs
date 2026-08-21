use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub agent_id: String,
    pub event_type: String,
    pub target: String,
    pub timestamp_ms: u128,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeFinding {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub event: RuntimeEvent,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeMonitor {
    declared_targets: HashSet<String>,
}

impl RuntimeMonitor {
    pub fn new<I, S>(declared_targets: I) -> Self
    where I: IntoIterator<Item = S>, S: Into<String> {
        Self { declared_targets: declared_targets.into_iter().map(Into::into).collect() }
    }

    pub fn observe(&self, mut event: RuntimeEvent) -> Option<RuntimeFinding> {
        if event.timestamp_ms == 0 { event.timestamp_ms = now_ms(); }
        if self.declared_targets.contains(&event.target) { return None; }
        Some(RuntimeFinding {
            rule_id: "RUNTIME-UNDECLARED-TARGET".into(),
            severity: "high".into(),
            title: "Agent reached an undeclared runtime target".into(),
            description: format!("Agent {} emitted {} toward an undeclared target {}.", event.agent_id, event.event_type, event.target),
            event,
        })
    }
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}
