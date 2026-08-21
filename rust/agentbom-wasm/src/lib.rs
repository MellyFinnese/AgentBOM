use agentbom_engine::Engine;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct AgentBOM {
    inner: Engine,
}

#[wasm_bindgen]
impl AgentBOM {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self { Self { inner: Engine::new() } }

    pub fn import_json(payload: &str) -> Result<AgentBOM, JsValue> {
        Engine::import_json(payload)
            .map(|inner| AgentBOM { inner })
            .map_err(|err| JsValue::from_str(&err))
    }

    pub fn export_json(&self) -> Result<String, JsValue> { self.inner.export_json().map_err(|err| JsValue::from_str(&err)) }
    pub fn snapshot_hash(&self) -> String { self.inner.snapshot_hash() }

    pub fn policy_findings_json(&self, max_depth: usize) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner.policy_findings(max_depth)).map_err(|err| JsValue::from_str(&err.to_string()))
    }

    pub fn attack_paths_json(&self, max_depth: usize) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner.attack_paths(max_depth)).map_err(|err| JsValue::from_str(&err.to_string()))
    }

    pub fn blast_radius_json(&self, max_depth: usize) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner.blast_radius(max_depth)).map_err(|err| JsValue::from_str(&err.to_string()))
    }

    pub fn drift_json(&self, baseline_json: &str) -> Result<String, JsValue> {
        let baseline = Engine::import_json(baseline_json).map_err(|err| JsValue::from_str(&err))?;
        serde_json::to_string(&self.inner.drift_findings(&baseline)).map_err(|err| JsValue::from_str(&err.to_string()))
    }
}
