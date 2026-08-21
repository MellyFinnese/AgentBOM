from pathlib import Path
import json

from agentbom.discovery_mcp import discover_mcp_config
from agentbom.graph import InMemoryGraph
from agentbom.path_analysis import BoundedPathAnalyzer


def test_mcp_manifest_builds_graph(tmp_path: Path) -> None:
    manifest = {
        "agents": [{"name": "coding-agent", "mcpServers": ["filesystem"]}],
        "mcpServers": {
            "filesystem": {
                "command": "node",
                "args": ["server.js"],
                "env": {"AWS_ACCESS_KEY_ID": "${AWS_ACCESS_KEY_ID}"},
                "tools": [
                    {
                        "name": "read_file",
                        "capabilities": [{"name": "read-env", "operation": "read", "resource": ".env"}],
                    }
                ],
            }
        },
    }
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    result = discover_mcp_config(path)
    graph = InMemoryGraph()
    for entity in result.entities:
        graph.add_entity(entity)
    for relationship in result.relationships:
        graph.add_relationship(relationship)

    assert any(entity.name == "coding-agent" for entity in graph.entities.values())
    assert any(entity.name == "filesystem:read_file" for entity in graph.entities.values())
    assert any(entity.kind.value == "credential" for entity in graph.entities.values())
    assert any(entity.name == ".env" for entity in graph.entities.values())
    assert len(graph.relationships) >= 4


def test_attack_path_reaches_data_source(tmp_path: Path) -> None:
    manifest = {
        "agents": [{"name": "coding-agent", "mcpServers": ["filesystem"]}],
        "mcpServers": {
            "filesystem": {
                "tools": [
                    {"name": "read_file", "capabilities": [{"operation": "read", "resource": "secrets.env"}]}
                ]
            }
        },
    }
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = discover_mcp_config(path)

    graph = InMemoryGraph()
    for entity in result.entities:
        graph.add_entity(entity)
    for relationship in result.relationships:
        graph.add_relationship(relationship)

    agent = next(entity for entity in graph.entities.values() if entity.name == "coding-agent")
    paths = list(BoundedPathAnalyzer().find_high_impact_paths(graph, agent))

    assert paths
    assert any(path.relation_kinds for path in paths)
