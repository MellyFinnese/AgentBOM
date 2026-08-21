"""AgentBOM command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .discovery_mcp import MCPConfigSource, discover_mcp_config
from .graph import InMemoryGraph
from .path_analysis import BoundedPathAnalyzer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentbom",
        description="AI agent security and attack-surface intelligence.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("info", help="Show the AgentBOM foundation status")

    scan = subparsers.add_parser("scan", help="Discover an AgentBOM from a project or MCP JSON manifest")
    scan.add_argument("target", type=Path)
    scan.add_argument("--json", action="store_true", dest="as_json", help="Emit normalized JSON")
    scan.add_argument("--paths", action="store_true", help="Show reachable high-impact attack paths")
    scan.add_argument("--max-depth", type=int, default=8)
    return parser


def _scan(target: Path) -> tuple[InMemoryGraph, tuple[object, ...]]:
    source = MCPConfigSource()
    result = discover_mcp_config(target) if target.is_file() else source.discover(target)
    graph = InMemoryGraph()
    for entity in result.entities:
        graph.add_entity(entity)
    for relationship in result.relationships:
        graph.add_relationship(relationship)
    return graph, result.observations


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "info":
        print("AgentBOM: discovery → normalized graph → capabilities → attack paths")
        return 0
    if args.command == "scan":
        graph, observations = _scan(args.target)
        if args.as_json:
            payload = {
                "entities": [
                    {
                        "id": entity.id,
                        "kind": entity.kind.value,
                        "name": entity.name,
                        "properties": dict(entity.properties),
                    }
                    for entity in graph.entities.values()
                ],
                "relationships": [
                    {
                        "source": rel.source_id,
                        "kind": rel.kind.value,
                        "target": rel.target_id,
                        "properties": dict(rel.properties),
                    }
                    for rel in graph.relationships
                ],
                "observations": [observation.message for observation in observations],
            }
            if args.paths:
                analyzer = BoundedPathAnalyzer(max_depth=max(1, args.max_depth))
                paths = []
                for agent in (e for e in graph.entities.values() if e.kind.value == "agent"):
                    for path in analyzer.find_high_impact_paths(graph, agent):
                        paths.append(
                            {
                                "start": agent.name,
                                "entities": [graph.get_entity(entity_id).name for entity_id in path.entity_ids if graph.get_entity(entity_id)],
                                "relations": [kind.value for kind in path.relation_kinds],
                            }
                        )
                payload["attack_paths"] = paths
            print(json.dumps(payload, indent=2, default=str))
        else:
            print(f"Entities: {len(graph.entities)}")
            print(f"Relationships: {len(graph.relationships)}")
            for observation in observations:
                print(f"Observation: {observation.message}")
            if args.paths:
                analyzer = BoundedPathAnalyzer(max_depth=max(1, args.max_depth))
                for agent in (e for e in graph.entities.values() if e.kind.value == "agent"):
                    for path in analyzer.find_high_impact_paths(graph, agent):
                        names = [graph.get_entity(entity_id).name for entity_id in path.entity_ids if graph.get_entity(entity_id)]
                        print(f"Attack path: {' -> '.join(names)}")
        return 0

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
