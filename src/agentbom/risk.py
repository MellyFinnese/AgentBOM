"""Shared, deterministic AgentBOM risk taxonomy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping

from .domain import Entity, EntityKind


class RiskTier(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


DEFAULT_SENSITIVE_PATTERNS: tuple[str, ...] = (
    "production",
    "prod",
    "root",
    "admin",
    "secret",
    "payment",
)

SENSITIVE_KINDS = frozenset({
    EntityKind.CREDENTIAL,
    EntityKind.PERMISSION,
    EntityKind.IDENTITY,
    EntityKind.DEPLOYMENT,
    EntityKind.DATABASE,
    EntityKind.DATA_SOURCE,
})

BASE_ENTITY_TIERS: Mapping[EntityKind, RiskTier] = {
    EntityKind.DEPLOYMENT: RiskTier.CRITICAL,
    EntityKind.DATABASE: RiskTier.CRITICAL,
    EntityKind.DATA_SOURCE: RiskTier.HIGH,
    EntityKind.CREDENTIAL: RiskTier.HIGH,
    EntityKind.IDENTITY: RiskTier.HIGH,
    EntityKind.PERMISSION: RiskTier.MEDIUM,
}

HIGH_IMPACT_RELATIONS = frozenset({
    "grants",
    "accesses",
    "authenticates_as",
    "assumes",
    "delegates",
    "writes",
    "reads",
    "calls",
})


@dataclass(frozen=True, slots=True)
class Sensitivity:
    tier: RiskTier | None
    matched_patterns: tuple[str, ...]

    @property
    def auditable_reason(self) -> str | None:
        if not self.matched_patterns:
            return None
        return ", ".join(self.matched_patterns)


def entity_sensitivity(entity: Entity, patterns: tuple[str, ...] = DEFAULT_SENSITIVE_PATTERNS) -> Sensitivity:
    base = BASE_ENTITY_TIERS.get(entity.kind)
    searchable = " ".join((entity.name, *(str(value) for value in entity.properties.values()))).casefold()
    matched = tuple(sorted({pattern.casefold() for pattern in patterns if pattern and pattern.casefold() in searchable}))
    if matched and base in {RiskTier.CRITICAL, RiskTier.HIGH, RiskTier.MEDIUM}:
        return Sensitivity(RiskTier.CRITICAL, matched)
    if matched:
        return Sensitivity(RiskTier.CRITICAL, matched)
    return Sensitivity(base, ())


def relationship_severity(relation: str, target: Entity | None, patterns: tuple[str, ...] = DEFAULT_SENSITIVE_PATTERNS) -> tuple[RiskTier, Sensitivity]:
    relation = relation.casefold()
    if target is None:
        return (RiskTier.HIGH if relation in HIGH_IMPACT_RELATIONS else RiskTier.MEDIUM, Sensitivity(None, ()))

    sensitivity = entity_sensitivity(target, patterns)
    if sensitivity.tier is RiskTier.CRITICAL and relation in HIGH_IMPACT_RELATIONS:
        return RiskTier.CRITICAL, sensitivity
    if sensitivity.tier in {RiskTier.HIGH, RiskTier.CRITICAL} and relation in HIGH_IMPACT_RELATIONS:
        return RiskTier.HIGH, sensitivity
    if relation in HIGH_IMPACT_RELATIONS:
        return RiskTier.HIGH, sensitivity
    return RiskTier.MEDIUM, sensitivity


def tier_weight(tier: RiskTier | None) -> int:
    return {
        RiskTier.CRITICAL: 4,
        RiskTier.HIGH: 3,
        RiskTier.MEDIUM: 2,
        RiskTier.LOW: 1,
    }.get(tier, 0)
