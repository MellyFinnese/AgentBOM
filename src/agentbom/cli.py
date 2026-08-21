"""AgentBOM command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .discovery_mcp import MCPConfigSource, discover_mcp_config
from .domain import EntityKind
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
    scan.add_argument("--auth", action="store_true", help="Show discovered identity and authorization chains")
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


def _authorization_chains(graph: InMemoryGraph) -> list[dict[str, object]]:
    chains: list[dict[str, object]] = []
    for agent in (e for e in graph.entities.values() if e.kind == EntityKind.AGENT):
        for identity_rel in graph.outgoing(agent.id):
            identity = graph.get_entity(identity_rel.target_id)
            if identity is None or identity.kind != EntityKind.IDENTITY:
                continue
            for credential_rel in graph.outgoing(identity.id):
                credential = graph.get_entity(credential_rel.target_id)
                if credential is None or credential.kind != EntityKind.CREDENTIAL:
                    continue
                for grant_rel in graph.outgoing(credential.id):
                    permission = graph.get_entity(grant_rel.target_id)
                    if permission is None or permission.kind != EntityKind.PERMISSION:
                        continue
                    for access_rel in graph.outgoing(permission.id):
                        resource = graph.get_entity(access_rel.target_id)
                        if resource is None or resource.kind != EntityKind.DATA_SOURCE:
                            continue
                        chains.append(
                            {
                                "agent": agent.name,
                                "identity": identity.name,
                                "credential": credential.name,
                                "permission": permission.name,
                                "resource": resource.name,
                                "action": permission.properties.get("action"),
                                "effect": permission.properties.get("effect"),
                            }
                        )
    return chains


def _path_records(graph: InMemoryGraph, max_depth: int) -> list[dict[str, object]]:
    analyzer = BoundedPathAnalyzer(max_depth=max(1, max_depth))
    paths: list[dict[str, object]] = []
    for agent in (e for e in graph.entities.values() if e.kind == EntityKind.AGENT):
        for path in analyzer.find_high_impact_paths(graph, agent):
            paths.append(
                {
                    "start": agent.name,
                    "entities": [
                        graph.get_entity(entity_id).name
                        for entity_id in path.entity_ids
                        if graph.get_entity(entity_id)
                    ],
                    "relations": [kind.value for kind in path.relation_kinds],
                }
            )
    return paths


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "info":
        print("AgentBOM: discovery -> normalized graph -> authorization -> attack paths")
        return 0
    if args.command == "scan":
        graph, observations = _scan(args.target)
        authorization = _authorization_chains(graph) if args.auth else None
        paths = _path_records(graph, args.max_depth) if args.paths else None
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
            if authorization is not None:
                payload["authorization"] = authorization
            if paths is not None:
                payload["attack_paths"] = paths
            print(json.dumps(payload, indent=2, default=str))
        else:
            print(f"Entities: {len(graph.entities)}")
            print(f"Relationships: {len(graph.relationships)}")
            for observation in observations:
                print(f"Observation: {observation.message}")
            if authorization is not None:
                for chain in authorization:
                    print(
                        "Authorization: "
                        f"{chain['agent']} -> {chain['identity']} -> {chain['credential']} -> "
                        f"{chain['permission']} -> {chain['resource']}"
                    )
            if paths is not None:
                for path in paths:
                    print(f"Attack path: {' -> '.join(path['entities'])}")
        return 0

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
