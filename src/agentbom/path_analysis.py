"""Concrete graph traversal for AgentBOM attack-path analysis."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable

from .analysis import AttackPath
from .domain import Entity, EntityKind, RelationKind
from .graph import GraphStore


HIGH_IMPACT_KINDS = {
    EntityKind.CREDENTIAL,
    EntityKind.DATA_SOURCE,
    EntityKind.DATABASE,
    EntityKind.DEPLOYMENT,
}


@dataclass(frozen=True, slots=True)
class BoundedPathAnalyzer:
    """Find shortest simple paths while keeping traversal bounded."""

    max_depth: int = 8

    def find_paths(self, graph: GraphStore, start: Entity, target: Entity) -> Iterable[AttackPath]:
        queue: deque[tuple[str, tuple[str, ...], tuple[RelationKind, ...]]] = deque(
            [(start.id, (start.id,), ())]
        )
        while queue:
            current_id, entity_ids, relation_kinds = queue.popleft()
            if current_id == target.id and entity_ids != (start.id,):
                yield AttackPath(entity_ids, relation_kinds)
                continue
            if len(relation_kinds) >= self.max_depth:
                continue
            for relationship in graph.outgoing(current_id):
                if relationship.target_id in entity_ids:
                    continue
                queue.append(
                    (
                        relationship.target_id,
                        entity_ids + (relationship.target_id,),
                        relation_kinds + (relationship.kind,),
                    )
                )

    def find_high_impact_paths(self, graph: GraphStore, start: Entity) -> Iterable[AttackPath]:
        seen_targets: set[str] = set()
        for entity_id in _reachable_ids(graph, start.id, self.max_depth):
            target = graph.get_entity(entity_id)
            if target is None or target.id in seen_targets or target.kind not in HIGH_IMPACT_KINDS:
                continue
            for path in self.find_paths(graph, start, target):
                seen_targets.add(target.id)
                yield path
                break


def _reachable_ids(graph: GraphStore, start_id: str, max_depth: int) -> set[str]:
    queue: deque[tuple[str, int]] = deque([(start_id, 0)])
    visited = {start_id}
    while queue:
        current_id, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for relationship in graph.outgoing(current_id):
            if relationship.target_id not in visited:
                visited.add(relationship.target_id)
                queue.append((relationship.target_id, depth + 1))
    return visited
