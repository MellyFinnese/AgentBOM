"""Graph abstraction used by analysis and discovery layers."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Protocol

from .domain import Entity, RelationKind, Relationship


class GraphStore(Protocol):
    def add_entity(self, entity: Entity) -> None: ...
    def add_relationship(self, relationship: Relationship) -> None: ...
    def get_entity(self, entity_id: str) -> Entity | None: ...
    def outgoing(self, entity_id: str) -> Iterable[Relationship]: ...
    def incoming(self, entity_id: str) -> Iterable[Relationship]: ...


@dataclass
class InMemoryGraph:
    """Dependency-free graph implementation for local analysis and tests."""

    entities: dict[str, Entity] = field(default_factory=dict)
    relationships: list[Relationship] = field(default_factory=list)
    _outgoing: dict[str, list[Relationship]] = field(default_factory=lambda: defaultdict(list))
    _incoming: dict[str, list[Relationship]] = field(default_factory=lambda: defaultdict(list))

    def add_entity(self, entity: Entity) -> None:
        self.entities[entity.id] = entity

    def add_relationship(self, relationship: Relationship) -> None:
        if relationship.source_id not in self.entities:
            raise KeyError(f"Unknown source entity: {relationship.source_id}")
        if relationship.target_id not in self.entities:
            raise KeyError(f"Unknown target entity: {relationship.target_id}")
        self.relationships.append(relationship)
        self._outgoing[relationship.source_id].append(relationship)
        self._incoming[relationship.target_id].append(relationship)

    def get_entity(self, entity_id: str) -> Entity | None:
        return self.entities.get(entity_id)

    def outgoing(self, entity_id: str) -> Iterable[Relationship]:
        return tuple(self._outgoing.get(entity_id, ()))

    def incoming(self, entity_id: str) -> Iterable[Relationship]:
        return tuple(self._incoming.get(entity_id, ()))

    def neighbors(self, entity_id: str, relation: RelationKind | None = None) -> Iterable[Entity]:
        for relationship in self.outgoing(entity_id):
            if relation is None or relationship.kind == relation:
                target = self.get_entity(relationship.target_id)
                if target is not None:
                    yield target
