"""Thin Python bridge to the Rust AgentBOM engine's extended APIs."""
from __future__ import annotations
import json
from typing import Any
from .native_bridge import _require_native, build_native_graph

def parse_authorization(provider: str, payload: str) -> list[dict[str, Any]]:
    native = _require_native()()
    return json.loads(native.parse_authorization_json(provider.strip().lower().replace("_", "-"), payload))["permissions"]

def authorization_decision(provider: str, payload: str, principal: str, action: str, resource: str, context: dict[str, str] | None = None) -> str:
    native = _require_native()()
    return json.loads(native.authorization_decision_json(
        provider.strip().lower().replace("_", "-"),
        payload,
        principal,
        action,
        resource,
        json.dumps(context or {}, sort_keys=True),
    ))

def parse_mcp_tools(payload: str) -> dict[str, Any]:
    """Parse an MCP tools/list response through the Rust engine."""
    native = _require_native()()
    return json.loads(native.parse_mcp_tools_json(payload))

def runtime_monitor_json(declared_targets: list[str], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    native = _require_native()()
    return json.loads(native.monitor_runtime_json(json.dumps(declared_targets), json.dumps(events)))

def correlate_behavior(graph: Any, events: list[dict[str, Any]], max_hops: int = 8, max_depth: int = 8) -> list[dict[str, Any]]:
    native = build_native_graph(graph)
    return json.loads(native.correlate_behavior_json(json.dumps(events, sort_keys=True), max_hops, max_depth))

def enforce_request(graph: Any, request: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, Any]:
    native = build_native_graph(graph)
    return json.loads(native.enforce_request_json(json.dumps(request, sort_keys=True), json.dumps(rules, sort_keys=True)))

def inspect_mcp_call(graph: Any, call: dict[str, Any], action: str, resource: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
    native = build_native_graph(graph)
    return json.loads(native.inspect_mcp_call_json(json.dumps(call, sort_keys=True), action, resource, json.dumps(rules, sort_keys=True)))

def inspect_mcp_call_with_definitions(graph: Any, call: dict[str, Any], definitions: list[dict[str, Any]], rules: list[dict[str, Any]], action_override: str | None = None, resource_override: str | None = None) -> dict[str, Any]:
    native = build_native_graph(graph)
    return json.loads(native.inspect_mcp_call_with_definitions_json(json.dumps(call, sort_keys=True), json.dumps(definitions, sort_keys=True), action_override, resource_override, json.dumps(rules, sort_keys=True)))

def export_cypher(graph: Any) -> list[dict[str, Any]]:
    return json.loads(build_native_graph(graph).cypher_json())

def enforcement_decision(action: str, resource: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
    native = _require_native()()
    return json.loads(native.policy_decision_json(action, resource, json.dumps(rules, sort_keys=True)))

def create_attestation(graph: Any, timestamp: str, engine_version: str) -> dict[str, Any]:
    return json.loads(build_native_graph(graph).attestation_json(timestamp, engine_version))

def sign_attestation(attestation: dict[str, Any]) -> str:
    native = _require_native()()
    return native.sign_attestation_json(json.dumps(attestation, sort_keys=True))

def effective_authority(graph: Any, principal: str, max_hops: int = 8) -> list[dict[str, Any]]:
    return json.loads(build_native_graph(graph).effective_authority_json(principal, max_hops))

def correlated_security_paths(graph: Any, principal: str, max_hops: int = 8, max_depth: int = 8) -> list[dict[str, Any]]:
    return json.loads(build_native_graph(graph).correlated_security_paths_json(principal, max_hops, max_depth))

def correlated_findings(graph: Any, principal: str, max_hops: int = 8, max_depth: int = 8) -> list[dict[str, Any]]:
    return json.loads(build_native_graph(graph).correlated_findings_json(principal, max_hops, max_depth))
