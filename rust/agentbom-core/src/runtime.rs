use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub timestamp: String,
    pub agent_id: String,
    pub event_type: String,
    pub target: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RuntimeState {
    pub events: Vec<RuntimeEvent>,
}

impl RuntimeState {
    pub fn record(&mut self, event: RuntimeEvent) {
        self.events.push(event);
    }

    pub fn unexpected_targets<'a>(&'a self, declared: &[String]) -> Vec<&'a RuntimeEvent> {
        self.events.iter().filter(|event| !declared.iter().any(|value| value == &event.target)).collect()
    }
}
