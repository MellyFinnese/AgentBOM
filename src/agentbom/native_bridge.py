"""Thin adapter from Python discovery models to the Rust security engine."""

from __future__ import annotations

import json
from typing import Any

try:
    from agentbom_native import NativeGraph
except ImportError as exc:  # pragma: no cover - depends on native build environment
    NativeGraph = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


def _require_native() -> Any:
    if NativeGraph is None:
        raise RuntimeError(
            "AgentBOM Rust engine is not installed. Build the native binding with "
            "maturin develop in rust/agentbom-python before running native analysis."
        ) from _IMPORT_ERROR
    return NativeGraph


def build_native_graph(graph: Any) -> Any:
    Native = _require_native()
    native = Native()
    for entity in graph.entities.values():
        native.add_node_json(entity.id, entity.kind.value, entity.name, json.dumps(dict(entity.properties), sort_keys=True))
    for relationship in graph.relationships:
        native.add_edge_json(
            relationship.source_id,
            relationship.kind.value,
            relationship.target_id,
            json.dumps(dict(relationship.properties), sort_keys=True),
        )
    return native


def policy_findings(graph: Any, max_depth: int) -> list[dict[str, Any]]:
    return json.loads(build_native_graph(graph).policy_findings_json(max_depth))


def attack_paths(graph: Any, max_depth: int) -> list[dict[str, Any]]:
    return json.loads(build_native_graph(graph).attack_paths_json(max_depth))


def blast_radius(graph: Any, max_depth: int) -> list[dict[str, Any]]:
    return json.loads(build_native_graph(graph).blast_radius_json(max_depth))


def drift_findings(graph: Any, baseline: Any) -> list[dict[str, Any]]:
    native = build_native_graph(graph)
    baseline_payload = {
        "nodes": {
            item["id"]: {
                "id": item["id"],
                "kind": item["kind"],
                "name": item["name"],
                "properties": item.get("properties", {}),
            }
            for item in baseline.entities
        },
        "edges": [
            {
                "source": item["source"],
                "kind": item["kind"],
                "target": item["target"],
                "properties": item.get("properties", {}),
            }
            for item in baseline.relationships
        ],
    }
    return json.loads(native.drift_json(json.dumps(baseline_payload, sort_keys=True)))
