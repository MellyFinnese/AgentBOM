from agentbom.drift import compare_snapshots
from agentbom.snapshot import snapshot_graph
from agentbom.domain import Entity, EntityKind, RelationKind, Relationship
from agentbom.graph import InMemoryGraph


def _snapshot(with_read: bool):
    graph = InMemoryGraph()
    agent = Entity(EntityKind.AGENT, "coding-agent", id="agent:coding")
    db = Entity(EntityKind.DATABASE, "production-db", id="db:prod")
    graph.add_entity(agent)
    graph.add_entity(db)
    if with_read:
        graph.add_relationship(Relationship(agent.id, RelationKind.READS, db.id))
    return snapshot_graph(graph)


def test_new_read_access_to_production_database_is_high_or_critical() -> None:
    previous = _snapshot(False)
    current = _snapshot(True)

    findings = compare_snapshots(previous, current)
    added = [finding for finding in findings if finding.drift_type.value == "added_relationship"]

    assert len(added) == 1
    assert added[0].severity in {"high", "critical"}


def test_new_read_access_to_credential_store_is_high() -> None:
    previous_graph = InMemoryGraph()
    current_graph = InMemoryGraph()
    agent = Entity(EntityKind.AGENT, "coding-agent", id="agent:coding")
    credential = Entity(EntityKind.CREDENTIAL, "prod-secret", id="credential:prod")
    for graph in (previous_graph, current_graph):
        graph.add_entity(agent)
        graph.add_entity(credential)
    current_graph.add_relationship(Relationship(agent.id, RelationKind.READS, credential.id))

    findings = compare_snapshots(snapshot_graph(previous_graph), snapshot_graph(current_graph))
    added = [finding for finding in findings if finding.drift_type.value == "added_relationship"]

    assert added[0].severity == "high"
