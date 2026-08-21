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


def test_blast_radius_counts_distinct_shortest_paths() -> None:
    graph = InMemoryGraph()
    agent = Entity(EntityKind.AGENT, "agent", id="agent:a")
    left = Entity(EntityKind.TOOL, "left", id="tool:left")
    right = Entity(EntityKind.TOOL, "right", id="tool:right")
    db = Entity(EntityKind.DATABASE, "production-db", id="db:prod")
    for entity in (agent, left, right, db):
        graph.add_entity(entity)

    graph.add_relationship(Relationship(agent.id, RelationKind.USES, left.id))
    graph.add_relationship(Relationship(agent.id, RelationKind.USES, right.id))
    graph.add_relationship(Relationship(left.id, RelationKind.CONNECTS_TO, db.id))
    graph.add_relationship(Relationship(right.id, RelationKind.CONNECTS_TO, db.id))

    radius = analyze_blast_radius(graph, agent)
    resource = next(item for item in radius.resources if item.entity_id == db.id)

    assert resource.distance == 2
    assert resource.path_count == 2


def test_blast_radius_cycle_does_not_inflate_path_count() -> None:
    graph = InMemoryGraph()
    agent = Entity(EntityKind.AGENT, "agent", id="agent:a")
    tool = Entity(EntityKind.TOOL, "tool", id="tool:t")
    helper = Entity(EntityKind.TOOL, "helper", id="tool:h")
    db = Entity(EntityKind.DATABASE, "production-db", id="db:prod")
    for entity in (agent, tool, helper, db):
        graph.add_entity(entity)

    graph.add_relationship(Relationship(agent.id, RelationKind.USES, tool.id))
    graph.add_relationship(Relationship(tool.id, RelationKind.USES, helper.id))
    graph.add_relationship(Relationship(helper.id, RelationKind.USES, tool.id))
    graph.add_relationship(Relationship(helper.id, RelationKind.CONNECTS_TO, db.id))

    radius = analyze_blast_radius(graph, agent)
    resource = next(item for item in radius.resources if item.entity_id == db.id)

    assert resource.distance == 3
    assert resource.path_count == 1
