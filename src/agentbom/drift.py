"""Semantic drift analysis for AgentBOM snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from .snapshot import Snapshot, verify_snapshot


class DriftType(StrEnum):
    ADDED_ENTITY = "added_entity"
    REMOVED_ENTITY = "removed_entity"
    CHANGED_ENTITY = "changed_entity"
    ADDED_RELATIONSHIP = "added_relationship"
    REMOVED_RELATIONSHIP = "removed_relationship"


@dataclass(frozen=True, slots=True)
class DriftFinding:
    drift_type: DriftType
    severity: str
    title: str
    description: str
    key: str


SENSITIVE_KINDS = {"credential", "permission", "identity", "deployment", "database", "data_source"}
HIGH_IMPACT_RELATIONS = {"grants", "accesses", "authenticates_as", "assumes", "delegates", "writes", "calls"}


def compare_snapshots(previous: Snapshot, current: Snapshot) -> tuple[DriftFinding, ...]:
    if not verify_snapshot(previous):
        raise ValueError("Previous snapshot digest verification failed")
    if not verify_snapshot(current):
        raise ValueError("Current snapshot digest verification failed")

    findings: list[DriftFinding] = []
    previous_entities = {str(item["id"]): item for item in previous.entities}
    current_entities = {str(item["id"]): item for item in current.entities}
    previous_relationships = {_relationship_key(item): item for item in previous.relationships}
    current_relationships = {_relationship_key(item): item for item in current.relationships}

    for key in sorted(current_entities.keys() - previous_entities.keys()):
        entity = current_entities[key]
        kind = str(entity.get("kind", "unknown"))
        severity = "high" if kind in SENSITIVE_KINDS else "medium"
        findings.append(
            DriftFinding(
                DriftType.ADDED_ENTITY,
                severity,
                f"New {kind} appeared",
                f"Entity {entity.get('name', key)} was not present in the previous baseline.",
                key,
            )
        )

    for key in sorted(previous_entities.keys() - current_entities.keys()):
        entity = previous_entities[key]
        findings.append(
            DriftFinding(
                DriftType.REMOVED_ENTITY,
                "low",
                f"{entity.get('kind', 'entity').title()} removed",
                f"Entity {entity.get('name', key)} is no longer present.",
                key,
            )
        )

    for key in sorted(current_entities.keys() & previous_entities.keys()):
        before = previous_entities[key]
        after = current_entities[key]
        if before != after:
            kind = str(after.get("kind", "unknown"))
            severity = "high" if kind in SENSITIVE_KINDS else "medium"
            findings.append(
                DriftFinding(
                    DriftType.CHANGED_ENTITY,
                    severity,
                    f"{kind.title()} changed",
                    f"Entity {after.get('name', key)} changed since the previous baseline.",
                    key,
                )
            )

    for key in sorted(current_relationships.keys() - previous_relationships.keys()):
        relationship = current_relationships[key]
        relation = str(relationship.get("kind", "unknown"))
        severity = "high" if relation in HIGH_IMPACT_RELATIONS else "medium"
        findings.append(
            DriftFinding(
                DriftType.ADDED_RELATIONSHIP,
                severity,
                "New security relationship appeared",
                f"Relationship {relation} connects {relationship.get('source')} to {relationship.get('target')}.",
                key,
            )
        )

    for key in sorted(previous_relationships.keys() - current_relationships.keys()):
        relationship = previous_relationships[key]
        findings.append(
            DriftFinding(
                DriftType.REMOVED_RELATIONSHIP,
                "low",
                "Security relationship removed",
                f"Relationship {relationship.get('kind', 'unknown')} no longer connects {relationship.get('source')} to {relationship.get('target')}.",
                key,
            )
        )

    return tuple(findings)


def summarize_drift(findings: Iterable[DriftFinding]) -> dict[str, object]:
    findings = tuple(findings)
    counts = {severity: sum(1 for finding in findings if finding.severity == severity) for severity in ("critical", "high", "medium", "low")}
    return {"total": len(findings), "counts": counts}


def _relationship_key(item: dict[str, object]) -> str:
    return f"{item.get('source')}|{item.get('kind')}|{item.get('target')}"
