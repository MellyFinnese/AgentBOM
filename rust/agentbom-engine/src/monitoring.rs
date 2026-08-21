use crate::{Engine, RuntimeEvent, RuntimeFinding, RuntimeMonitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MonitoringReport {
    pub events: usize,
    pub findings: Vec<RuntimeFinding>,
    pub event_counts: HashMap<String, usize>,
}

#[derive(Debug, Default)]
pub struct RuntimeSession {
    monitor: RuntimeMonitor,
    report: MonitoringReport,
}

impl RuntimeSession {
    pub fn new<I, S>(declared_targets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self { monitor: RuntimeMonitor::new(declared_targets), report: MonitoringReport::default() }
    }

    pub fn observe(&mut self, event: RuntimeEvent) -> Option<RuntimeFinding> {
        self.report.events += 1;
        *self.report.event_counts.entry(event.event_type.clone()).or_default() += 1;
        let finding = self.monitor.observe(event);
        if let Some(value) = finding.clone() { self.report.findings.push(value); }
        finding
    }

    pub fn report(&self) -> &MonitoringReport { &self.report }
    pub fn export_json(&self) -> Result<String, String> { serde_json::to_string(&self.report).map_err(|e| e.to_string()) }
}

impl Engine {
    pub fn monitor_events<I, S>(&self, declared_targets: I, events: impl IntoIterator<Item = RuntimeEvent>) -> MonitoringReport
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut session = RuntimeSession::new(declared_targets);
        for event in events { session.observe(event); }
        session.report.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn aggregates_runtime_events() {
        let engine = Engine::new();
        let report = engine.monitor_events(["allowed"], vec![
            RuntimeEvent { agent_id: "a".into(), event_type: "network.connect".into(), target: "allowed".into(), timestamp_ms: 1, metadata: json!({}) },
            RuntimeEvent { agent_id: "a".into(), event_type: "network.connect".into(), target: "unexpected".into(), timestamp_ms: 2, metadata: json!({}) },
        ]);
        assert_eq!(report.events, 2);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.event_counts["network.connect"], 2);
    }
}
