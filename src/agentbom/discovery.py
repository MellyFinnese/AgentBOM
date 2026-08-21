"""Discovery contracts. Concrete adapters belong outside the domain model."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Protocol

from .domain import Entity, Observation, Relationship


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    entities: tuple[Entity, ...] = field(default_factory=tuple)
    relationships: tuple[Relationship, ...] = field(default_factory=tuple)
    observations: tuple[Observation, ...] = field(default_factory=tuple)


class DiscoverySource(Protocol):
    name: str

    def discover(self, target: Path) -> DiscoveryResult: ...


class DiscoveryRegistry:
    """Small registry for composable discovery adapters."""

    def __init__(self, sources: Iterable[DiscoverySource] = ()) -> None:
        self._sources: dict[str, DiscoverySource] = {source.name: source for source in sources}

    def register(self, source: DiscoverySource) -> None:
        if source.name in self._sources:
            raise ValueError(f"Discovery source already registered: {source.name}")
        self._sources[source.name] = source

    def get(self, name: str) -> DiscoverySource:
        return self._sources[name]

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._sources))
