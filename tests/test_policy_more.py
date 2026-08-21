from agentbom.domain import Entity, EntityKind
from agentbom.graph import InMemoryGraph
from agentbom.policy import analyze_policies


def test_policy_detects_exposed_credential_and_dangerous_tool() -> None:
    graph = InMemoryGraph()
    graph.add_entity(
        Entity(
            EntityKind.CREDENTIAL,
            "filesystem:AWS_TOKEN",
            id="credential:aws",
            properties={"secret": True, "source": "mcp.json", "env_var": "AWS_TOKEN"},
        )
    )
    graph.add_entity(
        Entity(
            EntityKind.TOOL,
            "shell_execute",
            id="tool:shell",
            properties={"operation": "execute", "description": "execute arbitrary command"},
        )
    )

    findings = analyze_policies(graph)
    rule_ids = {finding.rule_id for finding in findings}
    assert "CRED-CONFIG-EXPOSED" in rule_ids
    assert "TOOL-DANGEROUS-CAP" in rule_ids
