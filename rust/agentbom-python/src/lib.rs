use agentbom_core::{Edge, Node};
use agentbom_engine::Engine;
use pyo3::prelude::*;

#[pyclass]
struct NativeGraph {
    inner: Engine,
}

#[pymethods]
impl NativeGraph {
    #[new]
    fn new() -> Self {
        Self { inner: Engine::new() }
    }

    fn add_node(&mut self, id: String, kind: String, name: String) {
        self.inner.add_node(Node { id, kind, name });
    }

    fn add_edge(&mut self, source: String, kind: String, target: String) -> PyResult<()> {
        self.inner
            .add_edge(Edge { source, kind, target })
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    fn reachable(&self, start: String, max_depth: usize) -> Vec<Vec<String>> {
        self.inner.reachable(&start, max_depth)
    }

    fn snapshot_hash(&self) -> String {
        self.inner.snapshot_hash()
    }

    fn stable_digest(&self) -> String {
        self.inner.stable_digest()
    }

    fn export_json(&self) -> PyResult<String> {
        self.inner
            .export_json()
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    fn node_count(&self) -> usize {
        self.inner.summary().node_count
    }

    fn edge_count(&self) -> usize {
        self.inner.summary().edge_count
    }
}

#[pymodule]
fn agentbom_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeGraph>()?;
    Ok(())
}
