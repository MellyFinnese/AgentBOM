"""Portable AgentBOM document validation and SARIF interop."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schema" / "agentbom-v1.schema.json"


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_document(document: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(load_schema())
    return [error.json_path + ": " + error.message for error in sorted(validator.iter_errors(document), key=str)]


def load_and_validate(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("AgentBOM document must be a JSON object")
    errors = validate_document(document)
    if errors:
        raise ValueError("invalid AgentBOM v1 document:\n" + "\n".join(errors))
    return document


def _severity_level(value: Any) -> str:
    value = str(value or "warning").lower()
    return value if value in {"none", "note", "warning", "error"} else "warning"


def findings_to_sarif(findings: list[dict[str, Any]], tool_version: str = "0.1.0") -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rule_id = str(finding.get("rule_id") or finding.get("id") or "AGENTBOM")
        rules.setdefault(rule_id, {"id": rule_id, "name": rule_id, "shortDescription": {"text": str(finding.get("title") or finding.get("message") or rule_id)}})
        results.append({
            "ruleId": rule_id,
            "level": _severity_level(finding.get("severity")),
            "message": {"text": str(finding.get("message") or finding.get("reason") or rule_id)},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "AgentBOM", "version": tool_version, "rules": list(rules.values())}},
            "results": results,
        }],
    }
