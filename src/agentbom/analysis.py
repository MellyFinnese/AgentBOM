"""Analysis boundaries for risk, attack paths, and blast radius."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol

from .domain import Entity, RelationKind
from .graph import GraphStore


@dataclass(frozen=True, slots=True)
class AttackPath:
    entity_ids: tuple[str, ...]
    relation_kinds: tuple[RelationKind, ...]

    @property
    def length(self) -> int:
        return len(self.relation_kinds)


class PathAnalyzer(Protocol):
    def find_paths(self, graph: GraphStore, start: Entity, target: Entity) -> Iterable[AttackPath]: ...


class BlastRadiusAnalyzer(Protocol):
    def impacted_entities(self, graph: GraphStore, origin: Entity) -> Iterable[Entity]: ...


class RiskAnalyzer(Protocol):
    def analyze(self, graph: GraphStore) -> Iterable[object]: ...
