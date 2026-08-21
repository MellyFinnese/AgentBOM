"""Extended Python bindings for the native AgentBOM engine."""

from __future__ import annotations

import json
from typing import Any

from .native_bridge import _require_native, build_native_graph


def _native_auth_provider(provider: str) -> str:
    return provider.strip().lower().replace("_", "-")


def parse_authorization(provider: str, payload: str) -> list[dict[str, Any]]:
    """Normalize provider authorization JSON using the Rust engine's parser."""
    Native = _require_native()
    native = Native()
    result = native.parse_authorization_json(_native_auth_provider(provider), payload)
    model = json.loads(result)
    return list(model.get("permissions", []))


def runtime_monitor_json(declared_targets: list[str], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    Native = _require_native()
    native = Native()
    return json.loads(native.monitor_runtime_json(json.dumps(declared_targets), json.dumps(events)))


def export_cypher(graph: Any) -> str:
    native = build_native_graph(graph)
    return native.export_cypher()


def enforcement_decision(action: str, resource: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
    Native = _require_native()
    native = Native()
    return json.loads(native.evaluate_policy_json(action, resource, json.dumps(rules, sort_keys=True)))


def create_attestation(graph: Any, timestamp: str, engine_version: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    native = build_native_graph(graph)
    return json.loads(native.attestation_json(timestamp, engine_version, json.dumps(metadata or {}, sort_keys=True)))


def sign_attestation(attestation: dict[str, Any]) -> str:
    Native = _require_native()
    native = Native()
    return native.sign_attestation_json(json.dumps(attestation, sort_keys=True))
