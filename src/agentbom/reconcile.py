"""Compare declared AgentBOM authority with runtime observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .domain import Entity, EntityKind, RelationKind
from .graph import GraphStore


@dataclass(frozen=True, slots=True)
class ReconciliationFinding:
    rule_id: str
    severity: str
    title: str
    description: str
    entity_ids: tuple[str, ...]


def reconcile_runtime(graph: GraphStore, runtime_entities: Iterable[Entity]) -> tuple[ReconciliationFinding, ...]:
    """Identify runtime authority that is absent from the declared graph."""
    findings: list[ReconciliationFinding] = []
    declared_credentials = {
        entity.properties.get("env_var")
        for entity in graph.entities.values()
        if entity.kind == EntityKind.CREDENTIAL
    }

    for observed in runtime_entities:
        if observed.kind != EntityKind.CREDENTIAL:
            continue
        env_var = observed.properties.get("env_var")
        if env_var and env_var not in declared_credentials:
            findings.append(
                ReconciliationFinding(
                    "RUNTIME-UNDECLARED-CREDENTIAL",
                    "high",
                    "Runtime credential not present in declared inventory",
                    f"Runtime observed credential {env_var!s}, but no matching declared credential was found.",
                    (observed.id,),
                )
            )

    return tuple(findings)
