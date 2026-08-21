"""Deterministic blast-radius analysis for AgentBOM graphs."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .domain import Entity, EntityKind
from .graph import GraphStore
from .risk import DEFAULT_SENSITIVE_PATTERNS, RiskTier, entity_sensitivity, tier_weight

# Backwards-compatible public name; severity values now come from the shared taxonomy.
ImpactTier = RiskTier


@dataclass(frozen=True, slots=True)
class ImpactedResource:
    entity_id: str
    name: str
    kind: EntityKind
    tier: ImpactTier
    distance: int
    path_count: int
    sensitivity_reason: tuple[str, ...] = ()


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


def analyze_blast_radius(
    graph: GraphStore,
    origin: Entity,
    *,
    max_depth: int = 8,
    sensitive_patterns: tuple[str, ...] = DEFAULT_SENSITIVE_PATTERNS,
) -> BlastRadius:
    """Find reachable security-relevant resources and calculate bounded impact."""
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
            path_counts[target_id] = path_counts.get(target_id, 0) + path_counts.get(current_id, 1)
            previous = distance.get(target_id)
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
        sensitivity = entity_sensitivity(entity, sensitive_patterns)
        if sensitivity.tier is None:
            continue
        resources.append(
            ImpactedResource(
                entity_id=entity.id,
                name=entity.name,
                kind=entity.kind,
                tier=sensitivity.tier,
                distance=dist,
                path_count=path_counts.get(entity.id, 1),
                sensitivity_reason=sensitivity.matched_patterns,
            )
        )

    resources.sort(key=lambda item: (-tier_weight(item.tier), item.distance, item.name))
    return BlastRadius(origin.id, origin.name, tuple(resources))


def analyze_all_agents(
    graph: GraphStore,
    *,
    max_depth: int = 8,
    sensitive_patterns: tuple[str, ...] = DEFAULT_SENSITIVE_PATTERNS,
) -> tuple[BlastRadius, ...]:
    return tuple(
        analyze_blast_radius(graph, entity, max_depth=max_depth, sensitive_patterns=sensitive_patterns)
        for entity in graph.entities.values()
        if entity.kind == EntityKind.AGENT
    )


def _classify(entity: Entity) -> ImpactTier | None:
    """Compatibility helper backed by the shared taxonomy."""
    return entity_sensitivity(entity).tier


def _tier_weight(tier: ImpactTier) -> int:
    return tier_weight(tier)
