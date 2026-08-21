use agentbom_core::{Edge, Node};
use agentbom_engine::{AttestationSigner, CypherExporter, Engine, McpToolCall, McpToolDefinition, PolicyRule, RuntimeEvent, ToolRequest};
use pyo3::prelude::*;
use std::collections::HashMap;

#[pyclass]
struct NativeGraph { inner: Engine }

#[pymethods]
impl NativeGraph {
    #[new]
    fn new() -> Self { Self { inner: Engine::new() } }
    fn add_node_json(&mut self, id: String, kind: String, name: String, properties_json: String) -> PyResult<()> {
        let properties = serde_json::from_str(&properties_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        self.inner.add_node(Node { id, kind, name, properties }); Ok(())
    }
    fn add_edge_json(&mut self, source: String, kind: String, target: String, properties_json: String) -> PyResult<()> {
        let properties = serde_json::from_str(&properties_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        self.inner.add_edge(Edge { source, kind, target, properties }).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn policy_findings_json(&self, max_depth: usize) -> PyResult<String> { serde_json::to_string(&self.inner.policy_findings(max_depth)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn attack_paths_json(&self, max_depth: usize) -> PyResult<String> { serde_json::to_string(&self.inner.attack_paths(max_depth)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn blast_radius_json(&self, max_depth: usize) -> PyResult<String> { serde_json::to_string(&self.inner.blast_radius(max_depth)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn drift_json(&self, baseline_json: String) -> PyResult<String> { let baseline = Engine::import_json(&baseline_json).map_err(pyo3::exceptions::PyValueError::new_err)?; serde_json::to_string(&self.inner.drift_findings(&baseline)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn parse_authorization_json(&self, provider: String, payload: String) -> PyResult<String> {
        let model = parse_provider(&provider, &payload)?;
        serde_json::to_string(&model).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn authorization_decision_json(&self, provider: String, payload: String, principal: String, action: String, resource: String, context_json: String) -> PyResult<String> {
        let model = parse_provider(&provider, &payload)?;
        let context: HashMap<String, String> = serde_json::from_str(&context_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        let decision = model.evaluate(&principal, &action, &resource, &context);
        serde_json::to_string(&decision).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn parse_mcp_tools_json(&self, payload: String) -> PyResult<String> {
        serde_json::to_string(&agentbom_engine::McpGateway::parse_tools_list(&payload).map_err(pyo3::exceptions::PyValueError::new_err)?)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn monitor_runtime_json(&self, declared_json: String, events_json: String) -> PyResult<String> {
        let declared: Vec<String> = serde_json::from_str(&declared_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        let events: Vec<RuntimeEvent> = serde_json::from_str(&events_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        let monitor = agentbom_engine::RuntimeMonitor::new(declared);
        let findings = events.into_iter().filter_map(|event| monitor.observe(event)).collect::<Vec<_>>();
        serde_json::to_string(&findings).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn correlate_behavior_json(&self, events_json: String, max_hops: usize, max_depth: usize) -> PyResult<String> {
        let events: Vec<RuntimeEvent> = serde_json::from_str(&events_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        let findings = events.iter().flat_map(|event| self.inner.correlate_behavior(event, max_hops, max_depth)).collect::<Vec<_>>();
        serde_json::to_string(&findings).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn enforce_request_json(&self, request_json: String, rules_json: String) -> PyResult<String> {
        let request: ToolRequest = serde_json::from_str(&request_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        let rules: Vec<PolicyRule> = serde_json::from_str(&rules_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        serde_json::to_string(&self.inner.enforce_request(&request, &rules)).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn inspect_mcp_call_json(&self, call_json: String, action: String, resource: String, rules_json: String) -> PyResult<String> {
        let call: McpToolCall = serde_json::from_str(&call_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        let rules: Vec<PolicyRule> = serde_json::from_str(&rules_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        serde_json::to_string(&self.inner.inspect_mcp_call(&call, &action, &resource, &rules)).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn inspect_mcp_call_with_definitions_json(&self, call_json: String, definitions_json: String, action_override: Option<String>, resource_override: Option<String>, rules_json: String) -> PyResult<String> {
        let call: McpToolCall = serde_json::from_str(&call_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        let definitions: Vec<McpToolDefinition> = serde_json::from_str(&definitions_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        let rules: Vec<PolicyRule> = serde_json::from_str(&rules_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        serde_json::to_string(&self.inner.inspect_mcp_call_with_definitions(&call, &definitions, action_override.as_deref(), resource_override.as_deref(), &rules)).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn cypher_json(&self) -> PyResult<String> { serde_json::to_string(&CypherExporter::export(&self.inner).map_err(pyo3::exceptions::PyValueError::new_err)?).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn policy_decision_json(&self, action: String, resource: String, rules_json: String) -> PyResult<String> { let rules: Vec<PolicyRule> = serde_json::from_str(&rules_json).map_err(pyo3::exceptions::PyValueError::new_err)?; serde_json::to_string(&self.inner.evaluate_policy(&action, &resource, &rules)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn attestation_json(&self, timestamp: String, engine_version: String) -> PyResult<String> { serde_json::to_string(&self.inner.attest(timestamp, engine_version)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn sign_attestation_json(&self, attestation_json: String) -> PyResult<String> { let attestation: agentbom_engine::Attestation = serde_json::from_str(&attestation_json).map_err(pyo3::exceptions::PyValueError::new_err)?; agentbom_engine::DigestSigner.sign(&agentbom_engine::canonical_attestation_bytes(&attestation)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn effective_authority_json(&self, principal: String, max_hops: usize) -> PyResult<String> { serde_json::to_string(&self.inner.effective_authority(&principal, max_hops)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn correlated_security_paths_json(&self, principal: String, max_hops: usize, max_depth: usize) -> PyResult<String> { serde_json::to_string(&self.inner.correlated_security_paths(&principal, max_hops, max_depth)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn correlated_findings_json(&self, principal: String, max_hops: usize, max_depth: usize) -> PyResult<String> { serde_json::to_string(&self.inner.correlated_findings(&principal, max_hops, max_depth)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn export_json(&self) -> PyResult<String> { self.inner.export_json().map_err(pyo3::exceptions::PyValueError::new_err) }
}

fn parse_provider(provider: &str, payload: &str) -> PyResult<agentbom_engine::AuthorizationModel> {
    match provider.trim().to_lowercase().replace('_', "-").as_str() {
        "aws-iam" => agentbom_engine::parse_aws_iam(payload),
        "gcp-iam" => agentbom_engine::parse_gcp_iam(payload),
        "azure-rbac" => agentbom_engine::parse_azure_rbac(payload),
        "kubernetes-rbac" => agentbom_engine::parse_kubernetes_rbac(payload),
        "oauth" | "oauth-scopes" => agentbom_engine::parse_oauth_scopes(payload),
        "mcp" | "mcp-auth" => agentbom_engine::parse_mcp_auth(payload),
        _ => return Err(pyo3::exceptions::PyValueError::new_err(format!("unsupported authorization provider: {provider}"))),
    }.map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pymodule]
fn agentbom_native(m: &Bound<'_, PyModule>) -> PyResult<()> { m.add_class::<NativeGraph>()?; Ok(()) }
