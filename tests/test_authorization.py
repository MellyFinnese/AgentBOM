from agentbom.authorization import (
    Effect,
    PermissionGrant,
    build_authorization_record,
    connect_authorization,
    effective_resources,
)
from agentbom.domain import Entity, EntityKind, RelationKind, Relationship
from agentbom.graph import InMemoryGraph


def test_authorization_builds_explicit_authority_chain() -> None:
    record = build_authorization_record(
        "coding-agent-identity",
        "aws-prod-token",
        [
            PermissionGrant("s3:GetObject", "s3://prod-data/*"),
            PermissionGrant("s3:PutObject", "s3://prod-data/*", Effect.ALLOW),
        ],
        provider="aws",
    )
    graph = InMemoryGraph()
    connect_authorization(graph, record)

    assert record.principal.kind == EntityKind.IDENTITY
    assert len(record.permissions) == 2
    assert any(r.kind == RelationKind.GRANTS for r in graph.outgoing(record.credential.id))

    resources = effective_resources(graph, record.principal)
    assert [resource.name for resource in resources] == ["s3://prod-data/*"]


def test_agent_can_be_linked_to_authorization_identity() -> None:
    record = build_authorization_record(
        "agent-identity",
        "github-token",
        [PermissionGrant("repo:write", "github://org/repository")],
        provider="github",
    )
    graph = InMemoryGraph()
    agent = Entity(EntityKind.AGENT, "coding-agent", id="agent:coding-agent")
    graph.add_entity(agent)
    connect_authorization(graph, record)
    graph.add_relationship(Relationship(agent.id, RelationKind.AUTHENTICATES_AS, record.principal.id))

    resources = effective_resources(graph, agent)
    assert resources == (record.resources[0],)
