"""Read-only runtime discovery for AgentBOM.

The runtime adapter inspects local process metadata and network state without
executing agent code or modifying the host. It is intentionally best-effort:
platform differences or permission restrictions become observations rather
than fatal scan errors.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .domain import Entity, EntityKind, Observation, RelationKind, Relationship
from .discovery import DiscoveryResult


@dataclass(frozen=True, slots=True)
class RuntimeProcess:
    pid: int
    name: str
    command: str
    cwd: str | None = None


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def discover_local_runtime(*, pid: int | None = None, include_connections: bool = False) -> DiscoveryResult:
    """Discover the current host/process context using read-only interfaces."""
    target_pid = pid or os.getpid()
    entities: dict[str, Entity] = {}
    relationships: list[Relationship] = []
    observations: list[Observation] = []

    process_name = _read_text(Path(f"/proc/{target_pid}/comm")) or f"pid-{target_pid}"
    command = _read_text(Path(f"/proc/{target_pid}/cmdline"))
    if command:
        command = command.replace("\x00", " ").strip()
    cwd: str | None
    try:
        cwd = os.readlink(f"/proc/{target_pid}/cwd")
    except OSError:
        cwd = None

    process = Entity(
        EntityKind.RUNTIME,
        process_name,
        id=f"runtime:process:{target_pid}",
        properties={"pid": target_pid, "command": command or "", "cwd": cwd},
    )
    entities[process.id] = process

    env_path = Path(f"/proc/{target_pid}/environ")
    try:
        raw_env = env_path.read_bytes()
    except OSError:
        raw_env = b""
    sensitive = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
    for item in raw_env.split(b"\x00"):
        if b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        key_text = key.decode("utf-8", "replace")
        if not any(token in key_text.upper() for token in sensitive):
            continue
        credential = Entity(
            EntityKind.CREDENTIAL,
            f"runtime:{key_text}",
            id=f"credential:runtime:{key_text}",
            properties={"env_var": key_text, "secret": True, "runtime_observed": True},
        )
        entities[credential.id] = credential
        relationships.append(Relationship(process.id, RelationKind.AUTHENTICATES_AS, credential.id))

    if include_connections:
        observations.append(_connection_observation())

    observations.append(
        Observation.now(
            f"Observed runtime process pid={target_pid} name={process_name}",
            source="runtime:local",
            location=f"/proc/{target_pid}",
        )
    )
    return DiscoveryResult(tuple(entities.values()), tuple(relationships), tuple(observations))


def _connection_observation() -> Observation:
    """Capture coarse local socket capability without requiring packet inspection."""
    try:
        hostname = socket.gethostname()
        addresses = sorted({addr[4][0] for addr in socket.getaddrinfo(hostname, None) if addr[4]})
    except OSError:
        addresses = []
    return Observation.now(
        "Observed local network identity",
        source="runtime:network",
        metadata={"hostname": socket.gethostname(), "addresses": addresses},
    )


class RuntimeSource:
    """DiscoverySource adapter for explicit local runtime inspection."""

    name = "runtime-local"

    def discover(self, target: Path) -> DiscoveryResult:
        del target
        return discover_local_runtime()
