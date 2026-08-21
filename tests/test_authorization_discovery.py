from pathlib import Path
import json

from agentbom.discovery_mcp import discover_mcp_config
from agentbom.domain import EntityKind, RelationKind
from agentbom.graph import InMemoryGraph
from agentbom.path_analysis import BoundedPathAnalyzer


def build_graph(result):
    graph = InMemoryGraph()
    for entity in result.entities:
        graph.add_entity(entity)
    for relationship in result.relationships:
        graph.add_relationship(relationship)
    return graph


def test_agent_authorization_chain_is_discovered(tmp_path: Path) -> None:
    manifest = {
        "agents": [
            {
                "name": "coding-agent",
                "identity": "ci-prod",
                "mcpServers": ["filesystem"],
            }
        ],
        "identities": {
            "ci-prod": {
                "provider": "aws",
                "credential": "ci-prod-role",
                "permissions": [
                    {"action": "s3:GetObject", "resource": "s3://prod-artifacts/*"},
                    {"action": "secrets:Get", "resource": "secrets/prod/*"},
                ],
            }
        },
        "mcpServers": {
            "filesystem": {
                "tools": [
                    {
                        "name": "read_file",
                        "capabilities": [
                            {"operation": "read", "resource": "secrets/prod/DB_PASSWORD"}
                        ],
                    }
                ]
            }
        },
    }
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    graph = build_graph(discover_mcp_config(path))

    assert any(e.kind == EntityKind.IDENTITY and e.name == "ci-prod" for e in graph.entities.values())
    assert any(e.kind == EntityKind.PERMISSION and e.properties.get("action") == "secrets:Get" for e in graph.entities.values())
    assert any(r.kind == RelationKind.GRANTS for r in graph.relationships)
    assert any(r.kind == RelationKind.ACCESSES for r in graph.relationships)


def test_authorization_path_reaches_scoped_resource(tmp_path: Path) -> None:
    manifest = {
        "agents": [{"name": "release-agent", "identity": "release", "mcpServers": []}],
        "identities": {
            "release": {
                "credential": "release-role",
                "permissions": [
                    {"action": "s3:GetObject", "resource": "s3://release-artifacts/*"}
                ],
            }
        },
    }
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    graph = build_graph(discover_mcp_config(path))
    agent = next(e for e in graph.entities.values() if e.name == "release-agent")
    paths = list(BoundedPathAnalyzer().find_high_impact_paths(graph, agent))

    assert paths
    assert any("release-artifacts" in graph.get_entity(node_id).name for p in paths for node_id in p.entity_ids if graph.get_entity(node_id))
