"""Core domain model for AgentBOM.

The domain deliberately uses stdlib dataclasses so the security model does not depend
on a particular graph database, discovery framework, or AI provider.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Mapping
from uuid import uuid4


class EntityKind(StrEnum):
    AGENT = "agent"
    MODEL = "model"
    TOOL = "tool"
    MCP_SERVER = "mcp_server"
    API = "api"
    IDENTITY = "identity"
    CREDENTIAL = "credential"
    PERMISSION = "permission"
    DATA_SOURCE = "data_source"
    MEMORY = "memory"
    DATABASE = "database"
    PACKAGE = "package"
    ARTIFACT = "artifact"
    RUNTIME = "runtime"
    DEPLOYMENT = "deployment"
    POLICY = "policy"
    FINDING = "finding"


class RelationKind(StrEnum):
    USES = "uses"
    EXPOSES = "exposes"
    CALLS = "calls"
    CONNECTS_TO = "connects_to"
    AUTHENTICATES_AS = "authenticates_as"
    ASSUMES = "assumes"
    DELEGATES = "delegates"
    GRANTS = "grants"
    ACCESSES = "accesses"
    READS = "reads"
    WRITES = "writes"
    DEPENDS_ON = "depends_on"
    DEPLOYED_AS = "deployed_as"
    CONTAINS = "contains"
    HAS_FINDING = "has_finding"
    SUPPORTED_BY = "supported_by"


@dataclass(frozen=True, slots=True)
class Entity:
    kind: EntityKind
    name: str
    id: str = field(default_factory=lambda: str(uuid4()))
    properties: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Relationship:
    source_id: str
    kind: RelationKind
    target_id: str
    properties: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Capability:
    name: str
    operation: str
    resource: str | None = None
    conditions: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Observation:
    id: str
    message: str
    source: str
    observed_at: datetime
    confidence: float = 1.0
    location: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)

    @classmethod
    def now(cls, message: str, source: str, **kwargs: object) -> "Observation":
        return cls(
            id=str(uuid4()),
            message=message,
            source=source,
            observed_at=datetime.now(timezone.utc),
            **kwargs,
        )
