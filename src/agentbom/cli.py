"""AgentBOM command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .blast_radius import analyze_all_agents
from .discovery_mcp import MCPConfigSource, discover_mcp_config
from .domain import EntityKind
from .graph import InMemoryGraph
from .path_analysis import BoundedPathAnalyzer
from .policy import analyze_policies
from .reconcile import reconcile_runtime
from .runtime import discover_local_runtime


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
    scan.add_argument("--policy", action="store_true", help="Run deterministic security policy analysis")
    scan.add_argument("--blast-radius", action="store_true", help="Calculate reachable impact and blast-radius scores")
    scan.add_argument("--runtime", action="store_true", help="Inspect the current local runtime")
    scan.add_argument("--runtime-network", action="store_true", help="Include coarse local network identity observations")
    scan.add_argument("--reconcile", action="store_true", help="Compare runtime observations with declared authority")
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
                        chains.append({
                            "agent": agent.name,
                            "identity": identity.name,
                            "credential": credential.name,
                            "permission": permission.name,
                            "resource": resource.name,
                            "action": permission.properties.get("action"),
                            "effect": permission.properties.get("effect"),
                        })
    return chains


def _path_records(graph: InMemoryGraph, max_depth: int) -> list[dict[str, object]]:
    analyzer = BoundedPathAnalyzer(max_depth=max(1, max_depth))
    paths: list[dict[str, object]] = []
    for agent in (e for e in graph.entities.values() if e.kind == EntityKind.AGENT):
        for path in analyzer.find_high_impact_paths(graph, agent):
            paths.append({
                "start": agent.name,
                "entities": [
                    graph.get_entity(entity_id).name
                    for entity_id in path.entity_ids
                    if graph.get_entity(entity_id)
                ],
                "relations": [kind.value for kind in path.relation_kinds],
            })
    return paths


def _blast_radius_records(graph: InMemoryGraph, max_depth: int) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for radius in analyze_all_agents(graph, max_depth=max_depth):
        records.append({
            "agent": radius.origin_name,
            "score": radius.score,
            "tier": radius.tier.value,
            "resources": [
                {
                    "name": resource.name,
                    "kind": resource.kind.value,
                    "tier": resource.tier.value,
                    "distance": resource.distance,
                    "path_count": resource.path_count,
                }
                for resource in radius.resources
            ],
        })
    return records


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "info":
        print("AgentBOM: discovery -> normalized graph -> authorization -> policy -> runtime -> blast radius")
        return 0
    if args.command == "scan":
        graph, observations = _scan(args.target)
        authorization = _authorization_chains(graph) if args.auth else None
        paths = _path_records(graph, args.max_depth) if args.paths else None
        findings = analyze_policies(graph, max_depth=args.max_depth) if args.policy else None
        blast = _blast_radius_records(graph, args.max_depth) if args.blast_radius else None
        runtime_result = discover_local_runtime(include_connections=args.runtime_network) if args.runtime else None
        runtime_findings = reconcile_runtime(graph, runtime_result.entities) if args.runtime and args.reconcile else None

        if args.as_json:
            payload: dict[str, object] = {
                "entities": [
                    {"id": entity.id, "kind": entity.kind.value, "name": entity.name, "properties": dict(entity.properties)}
                    for entity in graph.entities.values()
                ],
                "relationships": [
                    {"source": rel.source_id, "kind": rel.kind.value, "target": rel.target_id, "properties": dict(rel.properties)}
                    for rel in graph.relationships
                ],
                "observations": [observation.message for observation in observations],
            }
            if authorization is not None:
                payload["authorization"] = authorization
            if paths is not None:
                payload["attack_paths"] = paths
            if findings is not None:
                payload["policy_findings"] = [
                    {
                        "rule_id": finding.rule_id,
                        "severity": finding.severity.value,
                        "title": finding.title,
                        "description": finding.description,
                        "entity_ids": list(finding.entity_ids),
                        "evidence": list(finding.evidence),
                    }
                    for finding in findings
                ]
            if blast is not None:
                payload["blast_radius"] = blast
            if runtime_result is not None:
                payload["runtime"] = {
                    "entities": [
                        {"id": entity.id, "kind": entity.kind.value, "name": entity.name, "properties": dict(entity.properties)}
                        for entity in runtime_result.entities
                    ],
                    "observations": [observation.message for observation in runtime_result.observations],
                }
            if runtime_findings is not None:
                payload["runtime_findings"] = [
                    {
                        "rule_id": finding.rule_id,
                        "severity": finding.severity,
                        "title": finding.title,
                        "description": finding.description,
                        "entity_ids": list(finding.entity_ids),
                    }
                    for finding in runtime_findings
                ]
            print(json.dumps(payload, indent=2, default=str))
        else:
            print(f"Entities: {len(graph.entities)}")
            print(f"Relationships: {len(graph.relationships)}")
            for observation in observations:
                print(f"Observation: {observation.message}")
            if authorization is not None:
                for chain in authorization:
                    print("Authorization: " + " -> ".join([str(chain["agent"]), str(chain["identity"]), str(chain["credential"]), str(chain["permission"]), str(chain["resource"])]))
            if paths is not None:
                for path in paths:
                    print(f"Attack path: {' -> '.join(path['entities'])}")
            if findings is not None:
                print(f"Policy findings: {len(findings)}")
                for finding in findings:
                    evidence = "; ".join(finding.evidence)
                    print(f"[{finding.severity.value.upper()}] {finding.rule_id}: {finding.title}")
                    print(f"  {finding.description}")
                    if evidence:
                        print(f"  Evidence: {evidence}")
            if blast is not None:
                for item in blast:
                    print(f"Blast radius: {item['agent']} score={item['score']} tier={str(item['tier']).upper()}")
                    for resource in item["resources"]:
                        print(f"  {resource['tier'].upper()}: {resource['name']} ({resource['kind']}, distance={resource['distance']}, paths={resource['path_count']})")
            if runtime_result is not None:
                for entity in runtime_result.entities:
                    print(f"Runtime: {entity.kind.value} {entity.name}")
                for observation in runtime_result.observations:
                    print(f"Runtime observation: {observation.message}")
            if runtime_findings is not None:
                print(f"Runtime reconciliation findings: {len(runtime_findings)}")
                for finding in runtime_findings:
                    print(f"[{finding.severity.upper()}] {finding.rule_id}: {finding.title}")
                    print(f"  {finding.description}")
        return 0

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
