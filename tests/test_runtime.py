from pathlib import Path

from agentbom.domain import Entity, EntityKind
from agentbom.graph import InMemoryGraph
from agentbom.reconcile import reconcile_runtime
from agentbom.runtime import discover_local_runtime


def test_runtime_discovery_is_read_only() -> None:
    result = discover_local_runtime()
    assert result.entities
    assert any(entity.kind == EntityKind.RUNTIME for entity in result.entities)
    assert all(observation.source.startswith("runtime:") or observation.source == "runtime:local" for observation in result.observations)


def test_reconcile_flags_undeclared_runtime_credential() -> None:
    graph = InMemoryGraph()
    declared = Entity(
        EntityKind.CREDENTIAL,
        "declared-key",
        id="credential:declared",
        properties={"env_var": "DECLARED_KEY"},
    )
    graph.add_entity(declared)

    observed = Entity(
        EntityKind.CREDENTIAL,
        "runtime:SECRET_KEY",
        id="credential:runtime:SECRET_KEY",
        properties={"env_var": "SECRET_KEY", "runtime_observed": True},
    )
    findings = reconcile_runtime(graph, [observed])

    assert findings
    assert findings[0].rule_id == "RUNTIME-UNDECLARED-CREDENTIAL"
    assert findings[0].severity == "high"
