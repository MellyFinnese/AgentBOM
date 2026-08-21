"""Deterministic AgentBOM snapshots and local baseline storage."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .domain import Entity, Relationship
from .graph import GraphStore


@dataclass(frozen=True, slots=True)
class Snapshot:
    schema_version: str
    created_at: str
    digest: str
    entities: tuple[dict[str, object], ...]
    relationships: tuple[dict[str, object], ...]


def snapshot_graph(graph: GraphStore) -> Snapshot:
    entities = tuple(
        {
            "id": entity.id,
            "kind": entity.kind.value,
            "name": entity.name,
            "properties": _stable_mapping(entity.properties),
        }
        for entity in sorted(_all_entities(graph), key=lambda e: e.id)
    )
    relationships = tuple(
        {
            "source": relationship.source_id,
            "kind": relationship.kind.value,
            "target": relationship.target_id,
            "properties": _stable_mapping(relationship.properties),
        }
        for relationship in sorted(_all_relationships(graph), key=lambda r: (r.source_id, r.kind.value, r.target_id))
    )
    canonical = json.dumps(
        {"entities": entities, "relationships": relationships},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    return Snapshot(
        schema_version="1",
        created_at=datetime.now(timezone.utc).isoformat(),
        digest=digest,
        entities=entities,
        relationships=relationships,
    )


def save_snapshot(snapshot: Snapshot, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": snapshot.schema_version,
        "created_at": snapshot.created_at,
        "digest": snapshot.digest,
        "entities": list(snapshot.entities),
        "relationships": list(snapshot.relationships),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_snapshot(path: Path) -> Snapshot:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("AgentBOM snapshot must be a JSON object")
    return Snapshot(
        schema_version=str(payload.get("schema_version", "1")),
        created_at=str(payload["created_at"]),
        digest=str(payload["digest"]),
        entities=tuple(payload.get("entities", ())),
        relationships=tuple(payload.get("relationships", ())),
    )


def verify_snapshot(snapshot: Snapshot) -> bool:
    canonical = json.dumps(
        {"entities": snapshot.entities, "relationships": snapshot.relationships},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest() == snapshot.digest


def _stable_mapping(values: Mapping[str, object]) -> dict[str, object]:
    return {str(key): values[key] for key in sorted(values, key=str)}


def _all_entities(graph: GraphStore) -> tuple[Entity, ...]:
    entities = getattr(graph, "entities", None)
    if isinstance(entities, dict):
        return tuple(entities.values())
    raise TypeError("GraphStore implementation must expose entities for snapshotting")


def _all_relationships(graph: GraphStore) -> tuple[Relationship, ...]:
    relationships = getattr(graph, "relationships", None)
    if isinstance(relationships, list):
        return tuple(relationships)
    raise TypeError("GraphStore implementation must expose relationships for snapshotting")
