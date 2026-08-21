use agentbom_core::{Edge, Node};
use agentbom_engine::Engine;
use pyo3::prelude::*;

#[pyclass]
struct NativeGraph { inner: Engine }

#[pymethods]
impl NativeGraph {
    #[new]
    fn new() -> Self { Self { inner: Engine::new() } }
    fn add_node(&mut self, id: String, kind: String, name: String) { self.inner.add_node(Node { id, kind, name, properties: serde_json::json!({}) }); }
    fn add_node_json(&mut self, id: String, kind: String, name: String, properties_json: String) -> PyResult<()> {
        let properties = serde_json::from_str(&properties_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        self.inner.add_node(Node { id, kind, name, properties });
        Ok(())
    }
    fn add_edge(&mut self, source: String, kind: String, target: String) -> PyResult<()> {
        self.inner.add_edge(Edge { source, kind, target, properties: serde_json::json!({}) }).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn add_edge_json(&mut self, source: String, kind: String, target: String, properties_json: String) -> PyResult<()> {
        let properties = serde_json::from_str(&properties_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        self.inner.add_edge(Edge { source, kind, target, properties }).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn reachable(&self, start: String, max_depth: usize) -> Vec<Vec<String>> { self.inner.reachable(&start, max_depth) }
    fn snapshot_hash(&self) -> String { self.inner.snapshot_hash() }
    fn stable_digest(&self) -> String { self.inner.stable_digest() }
    fn policy_findings_json(&self, max_depth: usize) -> PyResult<String> { serde_json::to_string(&self.inner.policy_findings(max_depth)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn attack_paths_json(&self, max_depth: usize) -> PyResult<String> { serde_json::to_string(&self.inner.attack_paths(max_depth)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn blast_radius_json(&self, max_depth: usize) -> PyResult<String> { serde_json::to_string(&self.inner.blast_radius(max_depth)).map_err(pyo3::exceptions::PyValueError::new_err) }
    fn drift_json(&self, baseline_json: String) -> PyResult<String> {
        let baseline = Engine::import_json(&baseline_json).map_err(pyo3::exceptions::PyValueError::new_err)?;
        serde_json::to_string(&self.inner.drift_findings(&baseline)).map_err(pyo3::exceptions::PyValueError::new_err)
    }
    fn export_json(&self) -> PyResult<String> { self.inner.export_json().map_err(pyo3::exceptions::PyValueError::new_err) }
    fn node_count(&self) -> usize { self.inner.summary().node_count }
    fn edge_count(&self) -> usize { self.inner.summary().edge_count }
}

#[pymodule]
fn agentbom_native(m: &Bound<'_, PyModule>) -> PyResult<()> { m.add_class::<NativeGraph>()?; Ok(()) }
