"""Deterministic policy analysis for AgentBOM security graphs."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from .domain import Entity, EntityKind, RelationKind
from .graph import GraphStore
from .path_analysis import BoundedPathAnalyzer


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class PolicyFinding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    entity_ids: tuple[str, ...]
    evidence: tuple[str, ...]


DANGEROUS_OPERATIONS = {"execute", "delete", "assume_role", "admin", "write"}
SENSITIVE_KEYWORDS = ("prod", "production", "secret", "credential", "database", "admin")
WILDCARDS = {"*", "all", "any", "admin:*", "*:*")


def analyze_policies(graph: GraphStore, *, max_depth: int = 8) -> tuple[PolicyFinding, ...]:
    findings: list[PolicyFinding] = []
    findings.extend(_wildcard_permissions(graph))
    findings.extend(_production_permissions(graph))
    findings.extend(_credential_exposure(graph))
    findings.extend(_dangerous_capabilities(graph))
    findings.extend(_privilege_chains(graph, max_depth=max_depth))
    return tuple(_dedupe(findings))


def _wildcard_permissions(graph: GraphStore) -> Iterable[PolicyFinding]:
    for entity in graph.entities.values():
        if entity.kind != EntityKind.PERMISSION:
            continue
        action = str(entity.properties.get("action", ""))
        resource = _permission_resource(entity)
        if action.lower() in WILDCARDS or resource.lower() in WILDCARDS or "*" in action or resource == "*":
            yield PolicyFinding(
                "AUTH-WILDCARD",
                Severity.HIGH,
                "Wildcard authorization grant",
                f"Permission grants broad action/resource scope: {action} on {resource}.",
                (entity.id,),
                (f"permission={action}", f"resource={resource}"),
            )


def _production_permissions(graph: GraphStore) -> Iterable[PolicyFinding]:
    for permission in graph.entities.values():
        if permission.kind != EntityKind.PERMISSION:
            continue
        action = str(permission.properties.get("action", "")).lower()
        resource = _permission_resource(permission).lower()
        if not any(keyword in resource for keyword in ("prod", "production")):
            continue
        if action in {"write", "delete", "admin", "execute", "assume_role"}:
            yield PolicyFinding(
                "AUTH-PROD-WRITE",
                Severity.CRITICAL,
                "Production modification authority",
                f"A principal has {action} authority over a production resource.",
                (permission.id,),
                (f"action={action}", f"resource={resource}"),
            )


def _credential_exposure(graph: GraphStore) -> Iterable[PolicyFinding]:
    for credential in graph.entities.values():
        if credential.kind != EntityKind.CREDENTIAL:
            continue
        props = {str(key): str(value) for key, value in credential.properties.items()}
        if props.get("secret") == "True" and props.get("source"):
            yield PolicyFinding(
                "CRED-CONFIG-EXPOSED",
                Severity.HIGH,
                "Credential material referenced by configuration",
                "A credential is represented as a secret-backed configuration value; review storage, rotation, and scope.",
                (credential.id,),
                (f"source={props['source']}", f"env_var={props.get('env_var', '')}"),
            )


def _dangerous_capabilities(graph: GraphStore) -> Iterable[PolicyFinding]:
    for tool in graph.entities.values():
        if tool.kind != EntityKind.TOOL:
            continue
        operation = str(tool.properties.get("operation", tool.name)).lower()
        description = str(tool.properties.get("description", "")).lower()
        if any(token in operation for token in DANGEROUS_OPERATIONS) or any(token in description for token in ("shell", "execute", "arbitrary command")):
            yield PolicyFinding(
                "TOOL-DANGEROUS-CAP",
                Severity.HIGH,
                "Dangerous tool capability",
                "A tool exposes an operation or description associated with high-impact execution or mutation.",
                (tool.id,),
                (f"operation={operation}",),
            )


def _privilege_chains(graph: GraphStore, *, max_depth: int) -> Iterable[PolicyFinding]:
    analyzer = BoundedPathAnalyzer(max_depth=max_depth)
    for agent in graph.entities.values():
        if agent.kind != EntityKind.AGENT:
            continue
        for path in analyzer.find_high_impact_paths(graph, agent):
            target_id = path.entity_ids[-1]
            target = graph.get_entity(target_id)
            if target is None:
                continue
            if target.kind not in {EntityKind.DATA_SOURCE, EntityKind.DATABASE, EntityKind.DEPLOYMENT}:
                continue
            names = [graph.get_entity(entity_id).name for entity_id in path.entity_ids if graph.get_entity(entity_id)]
            joined = " -> ".join(names)
            severity = Severity.CRITICAL if any(token in joined.lower() for token in SENSITIVE_KEYWORDS) else Severity.HIGH
            yield PolicyFinding(
                "PATH-HIGH-IMPACT",
                severity,
                "Agent has a reachable high-impact resource",
                f"The agent can traverse a graph path to {target.kind.value}: {target.name}.",
                path.entity_ids,
                (joined,),
            )


def _permission_resource(permission: Entity) -> str:
    raw = permission.properties.get("resource")
    if raw is not None:
        return str(raw)
    return permission.name.split(" ", 1)[-1]


def _dedupe(findings: Iterable[PolicyFinding]) -> list[PolicyFinding]:
    seen: set[tuple[str, tuple[str, ...]]] = set()
    result: list[PolicyFinding] = []
    for finding in findings:
        key = (finding.rule_id, finding.entity_ids)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result
