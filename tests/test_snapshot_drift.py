from agentbom.domain import Entity, EntityKind, RelationKind, Relationship
from agentbom.drift import DriftType, compare_snapshots
from agentbom.graph import InMemoryGraph
from agentbom.snapshot import snapshot_graph, verify_snapshot


def _graph(include_prod: bool = False) -> InMemoryGraph:
    graph = InMemoryGraph()
    agent = Entity(EntityKind.AGENT, "coding-agent", id="agent:coding")
    tool = Entity(EntityKind.TOOL, "filesystem:read", id="tool:filesystem-read")
    graph.add_entity(agent)
    graph.add_entity(tool)
    graph.add_relationship(Relationship(agent.id, RelationKind.USES, tool.id))
    if include_prod:
        resource = Entity(EntityKind.DATA_SOURCE, "production-db", id="resource:production-db")
        graph.add_entity(resource)
        graph.add_relationship(Relationship(agent.id, RelationKind.READS, resource.id))
    return graph


def test_snapshot_is_deterministic_and_verifiable() -> None:
    first = snapshot_graph(_graph())
    second = snapshot_graph(_graph())
    assert first.digest == second.digest
    assert verify_snapshot(first)


def test_drift_detects_new_sensitive_resource_and_relationship() -> None:
    previous = snapshot_graph(_graph())
    current = snapshot_graph(_graph(include_prod=True))
    findings = compare_snapshots(previous, current)

    assert any(f.drift_type == DriftType.ADDED_ENTITY and "production-db" in f.description for f in findings)
    assert any(f.drift_type == DriftType.ADDED_RELATIONSHIP and f.severity == "critical" for f in findings)
