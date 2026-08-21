"""AgentBOM command-line interface."""
from __future__ import annotations
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from . import __version__
from .discovery_mcp import MCPConfigSource, discover_mcp_config
from .domain import EntityKind
from .graph import InMemoryGraph
from .native_bridge import attack_paths, blast_radius, drift_findings, policy_findings
from .native_bridge_extended import create_attestation, enforcement_decision, export_cypher, parse_authorization, runtime_monitor_json, sign_attestation, effective_authority, correlated_security_paths, correlated_findings
from .reconcile import reconcile_runtime
from .runtime import discover_local_runtime
from .snapshot import load_snapshot, save_snapshot, snapshot_graph, verify_snapshot

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentbom", description="AI agent security and attack-surface intelligence.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("info", help="Show AgentBOM status")
    scan = sub.add_parser("scan", help="Discover and analyze an AgentBOM")
    scan.add_argument("target", type=Path); scan.add_argument("--json", action="store_true", dest="as_json")
    scan.add_argument("--paths", action="store_true"); scan.add_argument("--auth", action="store_true"); scan.add_argument("--policy", action="store_true"); scan.add_argument("--blast-radius", action="store_true")
    scan.add_argument("--runtime", action="store_true"); scan.add_argument("--runtime-network", action="store_true"); scan.add_argument("--reconcile", action="store_true")
    scan.add_argument("--save-baseline", type=Path); scan.add_argument("--compare-baseline", type=Path); scan.add_argument("--max-depth", type=int, default=8)
    auth = sub.add_parser("auth-parse", help="Normalize provider authorization JSON with Rust")
    auth.add_argument("provider", choices=["aws-iam","gcp-iam","azure-rbac","kubernetes-rbac","oauth","mcp"]); auth.add_argument("policy", type=Path)
    mon = sub.add_parser("monitor", help="Analyze runtime events with the Rust monitoring engine")
    mon.add_argument("events", type=Path); mon.add_argument("--declared", type=Path, required=True)
    cy = sub.add_parser("cypher", help="Export a discovered graph as parameterized Cypher statements")
    cy.add_argument("target", type=Path)
    pc = sub.add_parser("policy-check", help="Evaluate one action/resource against Rust policy rules")
    pc.add_argument("action"); pc.add_argument("resource"); pc.add_argument("--rules", type=Path, required=True)
    at = sub.add_parser("attest", help="Create and deterministically sign an AgentBOM attestation")
    at.add_argument("target", type=Path); at.add_argument("--engine-version", default=__version__); at.add_argument("--output", type=Path)
    authz = sub.add_parser("authority", help="Resolve effective and delegated authority for a principal")
    authz.add_argument("target", type=Path); authz.add_argument("principal"); authz.add_argument("--max-hops", type=int, default=8); authz.add_argument("--max-depth", type=int, default=8); authz.add_argument("--findings", action="store_true")
    ap = sub.add_parser("attack-paths", help="Correlate authority, delegation, tools, and resources into security paths")
    ap.add_argument("target", type=Path); ap.add_argument("principal"); ap.add_argument("--max-hops", type=int, default=8); ap.add_argument("--max-depth", type=int, default=8); ap.add_argument("--findings", action="store_true")
    return parser

def _scan(target: Path) -> tuple[InMemoryGraph, tuple[object, ...]]:
    result = discover_mcp_config(target) if target.is_file() else MCPConfigSource().discover(target)
    graph = InMemoryGraph(); [graph.add_entity(e) for e in result.entities]; [graph.add_relationship(r) for r in result.relationships]
    return graph, result.observations

def main() -> int:
    args=build_parser().parse_args()
    if args.command == "info": print("AgentBOM: Rust-native agent security engine"); return 0
    if args.command == "auth-parse": print(json.dumps(parse_authorization(args.provider, args.policy.read_text(encoding="utf-8")), indent=2)); return 0
    if args.command == "monitor":
        declared=json.loads(args.declared.read_text(encoding="utf-8")); events=json.loads(args.events.read_text(encoding="utf-8")); print(json.dumps(runtime_monitor_json(declared, events), indent=2)); return 0
    if args.command == "cypher":
        graph,_=_scan(args.target); print(json.dumps(export_cypher(graph), indent=2)); return 0
    if args.command == "policy-check":
        rules=json.loads(args.rules.read_text(encoding="utf-8")); print(json.dumps(enforcement_decision(args.action,args.resource,rules), indent=2)); return 0
    if args.command == "attest":
        graph,_=_scan(args.target); att=create_attestation(graph, datetime.now(timezone.utc).isoformat(), args.engine_version); att["signature"]=sign_attestation(att); payload=json.dumps(att, indent=2, sort_keys=True); args.output.write_text(payload+"\n", encoding="utf-8") if args.output else print(payload); return 0
    if args.command in {"authority", "attack-paths"}:
        graph,_=_scan(args.target)
        if args.command == "authority":
            result = effective_authority(graph, args.principal, args.max_hops)
            payload = {"principal": args.principal, "effective_authority": result}
            if args.findings: payload["findings"] = correlated_findings(graph, args.principal, args.max_hops, args.max_depth)
        else:
            result = correlated_security_paths(graph, args.principal, args.max_hops, args.max_depth)
            payload = {"principal": args.principal, "attack_paths": result}
            if args.findings: payload["findings"] = correlated_findings(graph, args.principal, args.max_hops, args.max_depth)
        print(json.dumps(payload, indent=2, default=str)); return 0
    if args.command == "scan":
        graph, observations=_scan(args.target); payload={"entities":[{"id":e.id,"kind":e.kind.value,"name":e.name,"properties":dict(e.properties)} for e in graph.entities.values()],"relationships":[{"source":r.source_id,"kind":r.kind.value,"target":r.target_id,"properties":dict(r.properties)} for r in graph.relationships],"observations":[o.message for o in observations],"analysis_engine":"rust"}
        if args.auth: payload["authorization"]=[{"agent":e.name} for e in graph.entities.values() if e.kind == EntityKind.AGENT]
        if args.paths: payload["attack_paths"]=attack_paths(graph,args.max_depth)
        if args.policy: payload["policy_findings"]=policy_findings(graph,args.max_depth)
        if args.blast_radius: payload["blast_radius"]=blast_radius(graph,args.max_depth)
        if args.runtime:
            rr=discover_local_runtime(include_connections=args.runtime_network); payload["runtime"]={"entities":[{"id":e.id,"kind":e.kind.value,"name":e.name,"properties":dict(e.properties)} for e in rr.entities],"observations":[o.message for o in rr.observations]}
            if args.reconcile: payload["runtime_findings"]=runtime_monitor_json([e.name for e in graph.entities.values()], [ {"agent_id":"local","event_type":"runtime.observation","target":e.name,"timestamp_ms":0,"metadata":{}} for e in rr.entities ])
        if args.save_baseline:
            snap=snapshot_graph(graph); save_snapshot(snap,args.save_baseline); payload["baseline"]={"digest":snap.digest,"verified":verify_snapshot(snap)}
        if args.compare_baseline: payload["drift"]=drift_findings(graph,load_snapshot(args.compare_baseline))
        if args.as_json: print(json.dumps(payload, indent=2, default=str))
        else:
            print(f"Entities: {len(graph.entities)}"); print(f"Relationships: {len(graph.relationships)}"); print("Analysis engine: Rust")
            for item in payload.get("policy_findings",[]): print(f"[{item['severity'].upper()}] {item['rule_id']}: {item['title']}")
            for item in payload.get("attack_paths",[]): print(f"Attack path: {' -> '.join(item['node_ids'])}")
        return 0
    build_parser().print_help(); return 0

if __name__ == "__main__": raise SystemExit(main())
