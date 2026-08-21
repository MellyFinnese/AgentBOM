"""AgentBOM command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .discovery_mcp import MCPConfigSource, discover_mcp_config
from .domain import EntityKind
from .graph import InMemoryGraph
from .native_bridge import attack_paths, blast_radius, drift_findings, policy_findings
from .reconcile import reconcile_runtime
from .runtime import discover_local_runtime
from .snapshot import load_snapshot, save_snapshot, snapshot_graph, verify_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentbom", description="AI agent security and attack-surface intelligence.")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("info", help="Show the AgentBOM foundation status")
    scan = subparsers.add_parser("scan", help="Discover an AgentBOM from a project or MCP JSON manifest")
    scan.add_argument("target", type=Path)
    scan.add_argument("--json", action="store_true", dest="as_json", help="Emit normalized JSON")
    scan.add_argument("--paths", action="store_true", help="Show reachable high-impact attack paths (Rust)")
    scan.add_argument("--auth", action="store_true", help="Show discovered identity and authorization chains")
    scan.add_argument("--policy", action="store_true", help="Run deterministic security policy analysis (Rust)")
    scan.add_argument("--blast-radius", action="store_true", help="Calculate reachable impact and blast-radius scores (Rust)")
    scan.add_argument("--runtime", action="store_true", help="Inspect the current local runtime")
    scan.add_argument("--runtime-network", action="store_true", help="Include coarse local network identity observations")
    scan.add_argument("--reconcile", action="store_true", help="Compare runtime observations with declared authority")
    scan.add_argument("--save-baseline", type=Path, help="Save the normalized graph as a verified baseline snapshot")
    scan.add_argument("--compare-baseline", type=Path, help="Compare the current graph against a previous baseline snapshot")
    scan.add_argument("--max-depth", type=int, default=8)
    return parser


def _scan(target: Path) -> tuple[InMemoryGraph, tuple[object, ...]]:
    result = discover_mcp_config(target) if target.is_file() else MCPConfigSource().discover(target)
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
                            "agent": agent.name, "identity": identity.name, "credential": credential.name,
                            "permission": permission.name, "resource": resource.name,
                            "action": permission.properties.get("action"), "effect": permission.properties.get("effect"),
                        })
    return chains


def _native_drift(graph: InMemoryGraph, baseline_path: Path) -> list[dict[str, object]]:
    baseline = load_snapshot(baseline_path)
    if not verify_snapshot(baseline):
        raise ValueError(f"Refusing unverified baseline: {baseline_path}")
    return drift_findings(graph, baseline)


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "info":
        print("AgentBOM: discovery -> Rust graph -> authorization -> policy -> paths -> blast radius -> drift")
        return 0
    if args.command == "scan":
        graph, observations = _scan(args.target)
        authorization = _authorization_chains(graph) if args.auth else None
        paths = attack_paths(graph, args.max_depth) if args.paths else None
        findings = policy_findings(graph, args.max_depth) if args.policy else None
        blast = blast_radius(graph, args.max_depth) if args.blast_radius else None
        runtime_result = discover_local_runtime(include_connections=args.runtime_network) if args.runtime else None
        runtime_findings = reconcile_runtime(graph, runtime_result.entities) if args.runtime and args.reconcile else None
        current_snapshot = snapshot_graph(graph) if (args.save_baseline or args.compare_baseline) else None
        drift = _native_drift(graph, args.compare_baseline) if args.compare_baseline else None

        if args.save_baseline and current_snapshot is not None:
            save_snapshot(current_snapshot, args.save_baseline)

        if args.as_json:
            payload: dict[str, object] = {
                "entities": [{"id": e.id, "kind": e.kind.value, "name": e.name, "properties": dict(e.properties)} for e in graph.entities.values()],
                "relationships": [{"source": r.source_id, "kind": r.kind.value, "target": r.target_id, "properties": dict(r.properties)} for r in graph.relationships],
                "observations": [o.message for o in observations],
                "analysis_engine": "rust",
            }
            if current_snapshot is not None:
                payload["snapshot"] = {"created_at": current_snapshot.created_at, "digest": current_snapshot.digest, "verified": verify_snapshot(current_snapshot)}
            if authorization is not None: payload["authorization"] = authorization
            if paths is not None: payload["attack_paths"] = paths
            if findings is not None: payload["policy_findings"] = findings
            if blast is not None: payload["blast_radius"] = blast
            if runtime_result is not None:
                payload["runtime"] = {"entities": [{"id": e.id, "kind": e.kind.value, "name": e.name, "properties": dict(e.properties)} for e in runtime_result.entities], "observations": [o.message for o in runtime_result.observations]}
            if runtime_findings is not None:
                payload["runtime_findings"] = [{"rule_id": f.rule_id, "severity": f.severity, "title": f.title, "description": f.description, "entity_ids": list(f.entity_ids)} for f in runtime_findings]
            if drift is not None: payload["drift"] = drift
            print(json.dumps(payload, indent=2, default=str))
        else:
            print(f"Entities: {len(graph.entities)}")
            print(f"Relationships: {len(graph.relationships)}")
            print("Analysis engine: Rust")
            for observation in observations: print(f"Observation: {observation.message}")
            if args.save_baseline and current_snapshot is not None: print(f"Baseline saved: {args.save_baseline} ({current_snapshot.digest[:12]})")
            if drift is not None:
                print(f"Drift findings: {len(drift)}")
                for item in drift: print(f"[{item['severity'].upper()}] {item['drift_type']}: {item['title']} — {item['description']}")
            if authorization is not None:
                for chain in authorization: print("Authorization: " + " -> ".join(map(str, [chain["agent"], chain["identity"], chain["credential"], chain["permission"], chain["resource"]])))
            if paths is not None:
                for path in paths: print(f"Attack path: {' -> '.join(path['node_ids'])} ({path['start']} -> {path['target']})")
            if findings is not None:
                print(f"Policy findings: {len(findings)}")
                for finding in findings: print(f"[{finding['severity'].upper()}] {finding['rule_id']}: {finding['title']}\n  {finding['description']}\n  Evidence: {'; '.join(finding['evidence'])}")
            if blast is not None:
                for item in blast:
                    print(f"Blast radius: {item['agent']} score={item['score']} tier={item['tier'].upper()}")
                    for resource in item["resources"]: print(f"  {resource['tier'].upper()}: {resource['name']} ({resource['kind']}, distance={resource['distance']}, paths={resource['path_count']})")
            if runtime_result is not None:
                for entity in runtime_result.entities: print(f"Runtime: {entity.kind.value} {entity.name}")
                for observation in runtime_result.observations: print(f"Runtime observation: {observation.message}")
            if runtime_findings is not None:
                print(f"Runtime reconciliation findings: {len(runtime_findings)}")
                for finding in runtime_findings: print(f"[{finding.severity.upper()}] {finding.rule_id}: {finding.title}\n  {finding.description}")
        return 0

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
