from hypothesis import given, strategies as st

from agentbom.blast_radius import analyze_blast_radius
from agentbom.domain import Entity, EntityKind, RelationKind, Relationship
from agentbom.graph import InMemoryGraph


@st.composite
def dag_edges(draw: st.DrawFn, size: int) -> list[tuple[int, int]]:
    pairs = [(source, target) for source in range(size) for target in range(source + 1, size)]
    return [pair for pair, include in zip(pairs, draw(st.lists(st.booleans(), min_size=len(pairs), max_size=len(pairs), unique=False))) if include]


def build_graph(size: int, edges: list[tuple[int, int]]) -> tuple[InMemoryGraph, Entity]:
    graph = InMemoryGraph()
    origin = Entity(EntityKind.AGENT, "agent", id="agent:0")
    graph.add_entity(origin)
    for index in range(1, size):
        graph.add_entity(Entity(EntityKind.TOOL, f"tool-{index}", id=f"tool:{index}"))
    for source, target in edges:
        source_id = origin.id if source == 0 else f"tool:{source}"
        target_id = f"tool:{target}"
        graph.add_relationship(Relationship(source_id, RelationKind.USES, target_id))
    return graph, origin


@given(size=st.integers(min_value=2, max_value=8))
def test_blast_radius_score_is_non_negative(size: int) -> None:
    graph, origin = build_graph(size, [])
    radius = analyze_blast_radius(graph, origin)
    assert radius.score >= 0


@given(
    edges=dag_edges(size=6),
)
def test_adding_an_edge_does_not_reduce_reachable_path_counts(edges: list[tuple[int, int]]) -> None:
    base_graph, origin = build_graph(6, edges)
    baseline = {item.entity_id: item.path_count for item in analyze_blast_radius(base_graph, origin).resources}

    extra = next(
        (candidate for candidate in [(0, 1), (0, 2), (1, 2), (2, 3), (3, 4)] if candidate not in edges),
        None,
    )
    if extra is None:
        return

    expanded_graph, expanded_origin = build_graph(6, edges + [extra])
    expanded = {item.entity_id: item.path_count for item in analyze_blast_radius(expanded_graph, expanded_origin).resources}

    for entity_id, count in baseline.items():
        assert expanded.get(entity_id, 0) >= count
