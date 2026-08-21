from agentbom.capabilities import CapabilitySet
from agentbom.domain import Capability, Entity, EntityKind, RelationKind, Relationship
from agentbom.graph import InMemoryGraph


def test_graph_preserves_relationships() -> None:
    agent = Entity(EntityKind.AGENT, "coding-agent")
    tool = Entity(EntityKind.TOOL, "filesystem.read")
    graph = InMemoryGraph()
    graph.add_entity(agent)
    graph.add_entity(tool)
    graph.add_relationship(Relationship(agent.id, RelationKind.USES, tool.id))

    assert [entity.name for entity in graph.neighbors(agent.id)] == ["filesystem.read"]


def test_capability_matching() -> None:
    capabilities = CapabilitySet.from_iterable(
        [Capability(name="read workspace", operation="file.read", resource="workspace/")]
    )

    assert capabilities.can("file.read", "workspace/")
    assert not capabilities.can("file.write", "workspace/")
