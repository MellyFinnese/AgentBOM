from agentbom.blast_radius import ImpactTier, analyze_blast_radius
from agentbom.domain import Entity, EntityKind, RelationKind, Relationship
from agentbom.graph import InMemoryGraph


def test_blast_radius_scores_production_database_as_critical() -> None:
    graph = InMemoryGraph()
    agent = Entity(EntityKind.AGENT, "coding-agent", id="agent:coding")
    tool = Entity(EntityKind.TOOL, "db-tool", id="tool:db")
    db = Entity(EntityKind.DATABASE, "production-db", id="db:prod")
    graph.add_entity(agent)
    graph.add_entity(tool)
    graph.add_entity(db)
    graph.add_relationship(Relationship(agent.id, RelationKind.USES, tool.id))
    graph.add_relationship(Relationship(tool.id, RelationKind.CONNECTS_TO, db.id))

    radius = analyze_blast_radius(graph, agent)

    assert radius.tier == ImpactTier.CRITICAL
    assert radius.score >= 40
    assert radius.resources[0].name == "production-db"
    assert radius.resources[0].tier == ImpactTier.CRITICAL


def test_blast_radius_is_bounded() -> None:
    graph = InMemoryGraph()
    entities = [Entity(EntityKind.AGENT, "agent", id="agent:1")]
    for index in range(1, 6):
        entities.append(Entity(EntityKind.TOOL, f"tool-{index}", id=f"tool:{index}"))
    for entity in entities:
        graph.add_entity(entity)
    for left, right in zip(entities, entities[1:]):
        graph.add_relationship(Relationship(left.id, RelationKind.USES, right.id))

    radius = analyze_blast_radius(graph, entities[0], max_depth=2)
    assert radius.resources == ()
