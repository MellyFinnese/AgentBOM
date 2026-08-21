use agentbom_core::{Edge, Node, SecurityGraph};
use pyo3::prelude::*;

#[pyclass]
struct NativeGraph {
    inner: SecurityGraph,
}

#[pymethods]
impl NativeGraph {
    #[new]
    fn new() -> Self {
        Self { inner: SecurityGraph::default() }
    }

    fn add_node(&mut self, id: String, kind: String, name: String) {
        self.inner.add_node(Node { id, kind, name });
    }

    fn add_edge(&mut self, source: String, kind: String, target: String) -> PyResult<()> {
        self.inner.add_edge(Edge { source, kind, target })
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    fn outgoing(&self, source: String) -> Vec<(String, String, String)> {
        self.inner
            .edges
            .iter()
            .filter(|edge| edge.source == source)
            .map(|edge| (edge.source.clone(), edge.kind.clone(), edge.target.clone()))
            .collect()
    }

    fn reachable(&self, start: String, max_depth: usize) -> Vec<Vec<String>> {
        self.inner.reachable(&start, max_depth)
    }

    fn snapshot_hash(&self) -> String {
        self.inner.snapshot_hash()
    }

    fn node_count(&self) -> usize {
        self.inner.nodes.len()
    }

    fn edge_count(&self) -> usize {
        self.inner.edges.len()
    }
}

#[pymodule]
fn agentbom_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeGraph>()?;
    Ok(())
}
