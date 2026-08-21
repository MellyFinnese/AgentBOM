"""Capability declarations and policy boundaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping

from .domain import Capability


@dataclass(frozen=True, slots=True)
class CapabilitySet:
    """Normalized capabilities granted to an agent, tool, or identity."""

    capabilities: tuple[Capability, ...] = field(default_factory=tuple)

    @classmethod
    def from_iterable(cls, values: Iterable[Capability]) -> "CapabilitySet":
        return cls(tuple(values))

    def can(self, operation: str, resource: str | None = None) -> bool:
        for capability in self.capabilities:
            if capability.operation != operation:
                continue
            if capability.resource is None or resource is None or capability.resource == resource:
                return True
        return False


@dataclass(frozen=True, slots=True)
class CapabilityPolicy:
    """Simple allow/deny boundary; richer policy evaluation comes later."""

    denied_operations: frozenset[str] = frozenset()
    denied_resources: frozenset[str] = frozenset()

    def permits(self, capability: Capability) -> bool:
        if capability.operation in self.denied_operations:
            return False
        return capability.resource not in self.denied_resources
