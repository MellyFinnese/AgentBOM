"""Offline discovery for MCP-style agent configuration manifests.

This adapter intentionally does not execute MCP servers. It inspects local JSON
configuration and turns declared agents, servers, tools, credentials, and data
resources into the neutral AgentBOM graph model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .domain import Capability, Entity, EntityKind, Observation, RelationKind, Relationship
from .discovery import DiscoveryResult


DEFAULT_FILENAMES = {
    "mcp.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "agent.config.json",
}


def _entity_id(kind: EntityKind, name: str) -> str:
    return f"{kind.value}:{name}"


def _capabilities(raw: Any) -> list[Capability]:
    if not isinstance(raw, list):
        return []
    result: list[Capability] = []
    for item in raw:
        if isinstance(item, str):
            result.append(Capability(name=item, operation=item))
            continue
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or item.get("operation") or "unknown")
        operation = str(item.get("operation") or name)
        resource = item.get("resource")
        result.append(
            Capability(
                name=name,
                operation=operation,
                resource=str(resource) if resource is not None else None,
                conditions=dict(item.get("conditions") or {}),
            )
        )
    return result


def discover_mcp_config(path: Path) -> DiscoveryResult:
    """Parse one MCP/agent JSON manifest without executing arbitrary code."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError(f"MCP configuration must be a JSON object: {path}")

    entities: dict[str, Entity] = {}
    relationships: list[Relationship] = []
    observations: list[Observation] = []

    def add(kind: EntityKind, name: str, **properties: object) -> Entity:
        entity = Entity(kind=kind, id=_entity_id(kind, name), name=name, properties=properties)
        entities.setdefault(entity.id, entity)
        return entity

    def relate(source: Entity, relation: RelationKind, target: Entity, **properties: object) -> None:
        relationships.append(
            Relationship(source.id, relation, target.id, properties=properties)
        )

    servers = raw.get("mcpServers", {})
    if not isinstance(servers, Mapping):
        servers = {}

    agent_defs = raw.get("agents", [])
    if isinstance(agent_defs, Mapping):
        agent_defs = [agent_defs]
    if not isinstance(agent_defs, list):
        agent_defs = []

    for agent_def in agent_defs:
        if not isinstance(agent_def, Mapping):
            continue
        agent_name = str(agent_def.get("name") or "unnamed-agent")
        agent = add(EntityKind.AGENT, agent_name, source=str(path))
        configured_servers = agent_def.get("mcpServers", list(servers.keys()))
        if isinstance(configured_servers, str):
            configured_servers = [configured_servers]
        if not isinstance(configured_servers, list):
            configured_servers = []
        for server_name in configured_servers:
            server_def = servers.get(server_name, {})
            if not isinstance(server_def, Mapping):
                server_def = {}
            server = add(
                EntityKind.MCP_SERVER,
                str(server_name),
                command=server_def.get("command"),
                args=server_def.get("args", []),
                source=str(path),
            )
            relate(agent, RelationKind.USES, server)

            tools = server_def.get("tools", [])
            if not isinstance(tools, list):
                tools = []
            for tool_def in tools:
                if not isinstance(tool_def, Mapping):
                    continue
                tool_name = str(tool_def.get("name") or "unnamed-tool")
                tool = add(
                    EntityKind.TOOL,
                    f"{server_name}:{tool_name}",
                    server=server_name,
                    description=tool_def.get("description", ""),
                    source=str(path),
                )
                relate(server, RelationKind.EXPOSES, tool)

                caps = _capabilities(tool_def.get("capabilities", []))
                if not caps and any(k in tool_name.lower() for k in ("read", "write", "exec", "shell", "request")):
                    caps = [Capability(name=tool_name, operation=tool_name)]
                for cap in caps:
                    target_name = cap.resource or f"capability:{cap.name}"
                    data = add(
                        EntityKind.DATA_SOURCE,
                        target_name,
                        operation=cap.operation,
                        source=str(path),
                    )
                    relation = RelationKind.WRITES if cap.operation.lower() in {"write", "execute", "delete"} else RelationKind.READS
                    relate(tool, relation, data, capability=cap.name)

            env = server_def.get("env", {})
            if isinstance(env, Mapping):
                for key, value in env.items():
                    key_name = str(key)
                    value_str = str(value)
                    if any(token in key_name.upper() for token in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")):
                        credential = add(
                            EntityKind.CREDENTIAL,
                            f"{server_name}:{key_name}",
                            env_var=key_name,
                            reference=value_str,
                            secret=True,
                            source=str(path),
                        )
                        relate(server, RelationKind.AUTHENTICATES_AS, credential, env_var=key_name)

    observations.append(
        Observation.now(
            f"Discovered {len(entities)} entities and {len(relationships)} relationships",
            source=str(path),
            location=str(path),
        )
    )
    return DiscoveryResult(tuple(entities.values()), tuple(relationships), tuple(observations))


class MCPConfigSource:
    """Discovery registry adapter that searches a project for known MCP files."""

    name = "mcp-config"

    def discover(self, target: Path) -> DiscoveryResult:
        files = [target] if target.is_file() else [p for p in target.rglob("*.json") if p.name in DEFAULT_FILENAMES]
        combined_entities: dict[str, Entity] = {}
        combined_relationships: list[Relationship] = []
        combined_observations: list[Observation] = []
        for config in sorted(files):
            try:
                result = discover_mcp_config(config)
            except (OSError, json.JSONDecodeError, ValueError):
                continue
            combined_entities.update({entity.id: entity for entity in result.entities})
            combined_relationships.extend(result.relationships)
            combined_observations.extend(result.observations)
        return DiscoveryResult(
            tuple(combined_entities.values()),
            tuple(combined_relationships),
            tuple(combined_observations),
        )
