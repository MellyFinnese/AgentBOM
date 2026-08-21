"""Deterministic blast-radius analysis for AgentBOM graphs."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import StrEnum

from .domain import Entity, EntityKind
from .graph import GraphStore


class ImpactTier(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class ImpactedResource:
    entity_id: str
    name: str
    kind: EntityKind
    tier: ImpactTier
    distance: int
    path_count: int


@dataclass(frozen=True, slots=True)
class BlastRadius:
    origin_id: str
    origin_name: str
    resources: tuple[ImpactedResource, ...]

    @property
    def score(self) -> int:
        weights = {
            ImpactTier.CRITICAL: 40,
            ImpactTier.HIGH: 20,
            ImpactTier.MEDIUM: 8,
            ImpactTier.LOW: 2,
        }
        additive_score = min(100, sum(weights[item.tier] * max(1, item.path_count) for item in self.resources))
        # A reachable critical resource is a severity floor. A single direct path to
        # production data/infrastructure must never be diluted to MEDIUM by additive scoring.
        if any(item.tier is ImpactTier.CRITICAL for item in self.resources):
            return max(additive_score, 80)
        return additive_score

    @property
    def tier(self) -> ImpactTier:
        if self.score >= 80:
            return ImpactTier.CRITICAL
        if self.score >= 45:
            return ImpactTier.HIGH
        if self.score >= 15:
            return ImpactTier.MEDIUM
        return ImpactTier.LOW


_RESOURCE_TIERS = {
    EntityKind.DEPLOYMENT: ImpactTier.CRITICAL,
    EntityKind.DATABASE: ImpactTier.CRITICAL,
    EntityKind.DATA_SOURCE: ImpactTier.HIGH,
    EntityKind.CREDENTIAL: ImpactTier.HIGH,
    EntityKind.IDENTITY: ImpactTier.HIGH,
    EntityKind.PERMISSION: ImpactTier.MEDIUM,
}


def analyze_blast_radius(graph: GraphStore, origin: Entity, *, max_depth: int = 8) -> BlastRadius:
    """Find reachable security-relevant resources and calculate a bounded impact score."""
    max_depth = max(1, max_depth)
    queue: deque[tuple[str, int]] = deque([(origin.id, 0)])
    distance: dict[str, int] = {origin.id: 0}
    path_counts: dict[str, int] = {origin.id: 1}

    while queue:
        current_id, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for relation in graph.outgoing(current_id):
            target_id = relation.target_id
            next_depth = depth + 1
            previous = distance.get(target_id)
            path_counts[target_id] = path_counts.get(target_id, 0) + path_counts.get(current_id, 1)
            if previous is None:
                distance[target_id] = next_depth
                queue.append((target_id, next_depth))
            elif next_depth < previous:
                distance[target_id] = next_depth
                queue.append((target_id, next_depth))

    resources: list[ImpactedResource] = []
    for entity_id, dist in distance.items():
        if entity_id == origin.id:
            continue
        entity = graph.get_entity(entity_id)
        if entity is None:
            continue
        tier = _classify(entity)
        if tier is None:
            continue
        resources.append(
            ImpactedResource(
                entity_id=entity.id,
                name=entity.name,
                kind=entity.kind,
                tier=tier,
                distance=dist,
                path_count=path_counts.get(entity.id, 1),
            )
        )

    resources.sort(key=lambda item: (-_tier_weight(item.tier), item.distance, item.name))
    return BlastRadius(origin.id, origin.name, tuple(resources))


def analyze_all_agents(graph: GraphStore, *, max_depth: int = 8) -> tuple[BlastRadius, ...]:
    return tuple(
        analyze_blast_radius(graph, entity, max_depth=max_depth)
        for entity in graph.entities.values()
        if entity.kind == EntityKind.AGENT
    )


def _classify(entity: Entity) -> ImpactTier | None:
    tier = _RESOURCE_TIERS.get(entity.kind)
    if tier is None:
        return None
    searchable = " ".join((entity.name, *(f"{k}={v}" for k, v in entity.properties.items()))).lower()
    if any(token in searchable for token in ("production", "prod", "root", "admin", "secret", "payment")):
        return ImpactTier.CRITICAL
    return tier


def _tier_weight(tier: ImpactTier) -> int:
    return {
        ImpactTier.CRITICAL: 4,
        ImpactTier.HIGH: 3,
        ImpactTier.MEDIUM: 2,
        ImpactTier.LOW: 1,
    }[tier]
