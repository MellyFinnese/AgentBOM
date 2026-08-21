use agentbom_core::{Edge, Node};
use agentbom_engine::{AuthorizationAdapter, Engine, PolicyRule, RuntimeEvent};
use pyo3::prelude::*;

#[pyclass]
struct NativeGraph { inner: Engine }

#[pymethods]
impl NativeGraph {
    #[new]
    fn new() -> Self { Self { inner: Engine::new() } }
    fn add_node(&mut self, id: String, kind: String, name: String) { self.inner.add_node(Node { id, kind, name, properties: serde_json::json!({}) }); }
    fn add_node_json(&mut self, id: String, kind: String, name: String, properties_json: String) -> PyResult<()> { let properties = serde_json::from_str(&properties_json).map_err(pyo3::exceptions::PyValueError::new_err)?; self.inner.add_node(Node { id, kind, name, properties }); Ok(()) }
    fn add_edge_json(&mut self, source: String, kind: String, target: String, properties_json: String) -> PyResult<()> { let properties = serde_json::from_str(&properties_json).map_err(pyo3::exceptions::PyValueError::new_err)?; self.inner.add_edge(Edge { source, kind, target, properties }).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn policy_findings_json(&self, max_depth: usize) -> PyResult<String> { serde_json::to_string(&self.inner.policy_findings(max_depth)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn attack_paths_json(&self, max_depth: usize) -> PyResult<String> { serde_json::to_string(&self.inner.attack_paths(max_depth)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn blast_radius_json(&self, max_depth: usize) -> PyResult<String> { serde_json::to_string(&self.inner.blast_radius(max_depth)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn drift_json(&self, baseline_json: String) -> PyResult<String> { let baseline = Engine::import_json(&baseline_json).map_err(pyo3::exceptions::PyValueError::new_err)?; serde_json::to_string(&self.inner.drift_findings(&baseline)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn parse_authorization_json(&self, provider: String, payload: String) -> PyResult<String> {
        let model = match provider.as_str() {
            "aws-iam" => agentbom_engine::parse_aws_iam(&payload),
            "gcp-iam" => agentbom_engine::parse_gcp_iam(&payload),
            "azure-rbac" => agentbom_engine::parse_azure_rbac(&payload),
            "kubernetes-rbac" => agentbom_engine::parse_kubernetes_rbac(&payload),
            "oauth" | "oauth-scopes" => agentbom_engine::parse_oauth_scopes(&payload),
            "mcp" | "mcp-auth" => agentbom_engine::parse_mcp_auth(&payload),
            _ => return Err(pyo3::exceptions::PyValueError::new_err(format!("unsupported authorization provider: {provider}"))),
        }.map_err(pyo3::exceptions::PyValueError::new_err)?;
        serde_json::to_string(&model).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn monitor_runtime_json(&self, declared_json: String, events_json: String) -> PyResult<String> {
        let declared: Vec<String> = serde_json::from_str(&declared_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        let events: Vec<RuntimeEvent> = serde_json::from_str(&events_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        let monitor = agentbom_engine::RuntimeMonitor::new(declared);
        let findings = events.into_iter().filter_map(|event| monitor.observe(event)).collect::<Vec<_>>();
        serde_json::to_string(&findings).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn export_cypher(&self) -> String { self.inner.export_cypher() }
    fn evaluate_policy_json(&self, action: String, resource: String, rules_json: String) -> PyResult<String> { let rules: Vec<PolicyRule> = serde_json::from_str(&rules_json).map_err(pyo3::exceptions::PyValueError::new_err)?; serde_json::to_string(&self.inner.evaluate_policy(&action, &resource, &rules)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn attestation_json(&self, timestamp: String, engine_version: String, metadata_json: String) -> PyResult<String> { let metadata: serde_json::Value = serde_json::from_str(&metadata_json).map_err(pyo3::exceptions::PyValueError::new_err)?; serde_json::to_string(&self.inner.attest_with_metadata(&timestamp, &engine_version, metadata)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn sign_attestation_json(&self, attestation_json: String) -> PyResult<String> { let attestation: agentbom_engine::Attestation = serde_json::from_str(&attestation_json).map_err(pyo3::exceptions::PyValueError::new_err)?; Ok(agentbom_engine::DigestSigner.sign(&agentbom_engine::canonical_attestation_bytes(&attestation)).map_err(pyo3::exceptions::PyValueError::new_err)?) }
    fn export_json(&self) -> PyResult<String> { self.inner.export_json().map_err(pyo3::exceptions::PyValueError::new_err) }
}

#[pymodule]
fn agentbom_native(m: &Bound<'_, PyModule>) -> PyResult<()> { m.add_class::<NativeGraph>()?; Ok(()) }
