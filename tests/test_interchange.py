import json
from pathlib import Path

from agentbom.interchange import findings_to_sarif, load_and_validate

ROOT = Path(__file__).resolve().parents[1]


def test_third_party_document_is_consumable():
    document = load_and_validate(ROOT / "examples/spec/go-producer/agentbom.json")
    assert document["schema_version"] == "1.0"
    assert document["document"]["source"] == "example-go-producer"


def test_sarif_contract_is_valid_shape():
    sarif = findings_to_sarif([{"rule_id": "AGENTBOM-TEST", "severity": "high", "message": "test finding"}])
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "AgentBOM"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "AGENTBOM-TEST"
