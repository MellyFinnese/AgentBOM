from agentbom.authorization import Effect, PermissionGrant, build_authorization_record, connect_authorization
from agentbom.domain import Entity, EntityKind, RelationKind, Relationship
from agentbom.graph import InMemoryGraph
from agentbom.policy import Severity, analyze_policies


def test_policy_rules_detect_wildcard_and_production_access() -> None:
    graph = InMemoryGraph()
    permission = Entity(
        EntityKind.PERMISSION,
        "write prod-db",
        id="permission:p",
        properties={"action": "write", "resource": "production-db"},
    )
    graph.add_entity(permission)

    findings = analyze_policies(graph)
    rule_ids = {finding.rule_id for finding in findings}
    assert "AUTH-PROD-WRITE" in rule_ids

    wildcard = Entity(
        EntityKind.PERMISSION,
        "* *",
        id="permission:wildcard",
        properties={"action": "*", "resource": "*"},
    )
    graph.add_entity(wildcard)
    findings = analyze_policies(graph)
    assert any(f.rule_id == "AUTH-WILDCARD" and f.severity == Severity.HIGH for f in findings)


def test_policy_finds_authorized_path_to_sensitive_resource() -> None:
    graph = InMemoryGraph()
    agent = Entity(EntityKind.AGENT, "coding-agent", id="agent:coding-agent")
    graph.add_entity(agent)

    record = build_authorization_record(
        "coding-agent",
        "aws-prod",
        [PermissionGrant("write", "production-db", Effect.ALLOW)],
        provider="aws",
    )
    connect_authorization(graph, record)
    graph.add_relationship(Relationship(agent.id, RelationKind.AUTHENTICATES_AS, record.principal.id))

    findings = analyze_policies(graph)
    assert any(f.rule_id == "PATH-HIGH-IMPACT" for f in findings)
