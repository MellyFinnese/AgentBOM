"""Identity and authorization modeling for AgentBOM.

Authorization is modeled explicitly so analysis can distinguish an agent's
technical connection from the authority ultimately granted by that connection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Iterable, Mapping

from .domain import Entity, EntityKind, RelationKind, Relationship
from .graph import GraphStore


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class PermissionGrant:
    action: str
    resource: str
    effect: Effect = Effect.ALLOW
    conditions: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IdentityBinding:
    identity_name: str
    credential_name: str
    provider: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AuthorizationRecord:
    principal: Entity
    credential: Entity
    permissions: tuple[Entity, ...]
    resources: tuple[Entity, ...]


def build_authorization_record(
    identity_name: str,
    credential_name: str,
    grants: Iterable[PermissionGrant],
    provider: str | None = None,
) -> AuthorizationRecord:
    """Create normalized authorization entities without depending on a backend."""
    identity = Entity(
        kind=EntityKind.IDENTITY,
        id=f"identity:{identity_name}",
        name=identity_name,
        properties={"provider": provider} if provider else {},
    )
    credential = Entity(
        kind=EntityKind.CREDENTIAL,
        id=f"credential:{credential_name}",
        name=credential_name,
        properties={"provider": provider} if provider else {},
    )

    permissions: list[Entity] = []
    resources: dict[str, Entity] = {}
    for grant in grants:
        permission_id = f"permission:{identity_name}:{grant.action}:{grant.resource}"
        permissions.append(
            Entity(
                kind=EntityKind.PERMISSION,
                id=permission_id,
                name=f"{grant.action} {grant.resource}",
                properties={
                    "action": grant.action,
                    "resource": grant.resource,
                    "effect": grant.effect.value,
                    "conditions": dict(grant.conditions),
                },
            )
        )
        resources.setdefault(
            grant.resource,
            Entity(
                kind=EntityKind.DATA_SOURCE,
                id=f"resource:{grant.resource}",
                name=grant.resource,
                properties={"authorization_scope": grant.resource},
            ),
        )

    return AuthorizationRecord(identity, credential, tuple(permissions), tuple(resources.values()))


def connect_authorization(graph: GraphStore, record: AuthorizationRecord) -> None:
    """Insert an authorization record into an existing security graph."""
    for entity in (
        record.principal,
        record.credential,
        *record.permissions,
        *record.resources,
    ):
        graph.add_entity(entity)

    graph.add_relationship(
        Relationship(
            record.principal.id,
            RelationKind.AUTHENTICATES_AS,
            record.credential.id,
        )
    )
    for permission in record.permissions:
        graph.add_relationship(
            Relationship(record.credential.id, RelationKind.GRANTS, permission.id)
        )
        resource_name = str(permission.properties["resource"])
        for resource in record.resources:
            if resource.name == resource_name:
                graph.add_relationship(
                    Relationship(permission.id, RelationKind.ACCESSES, resource.id)
                )
                break


def effective_resources(graph: GraphStore, principal: Entity) -> tuple[Entity, ...]:
    """Return resources reachable through explicit identity/credential authority edges."""
    found: dict[str, Entity] = {}
    frontier = [principal.id]
    visited = set(frontier)
    while frontier:
        current = frontier.pop(0)
        for relationship in graph.outgoing(current):
            if relationship.target_id in visited:
                continue
            visited.add(relationship.target_id)
            target = graph.get_entity(relationship.target_id)
            if target is None:
                continue
            if target.kind == EntityKind.DATA_SOURCE:
                found[target.id] = target
            frontier.append(target.id)
    return tuple(found.values())
