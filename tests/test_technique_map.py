import json
from src.ingestion.technique_map import extract_techniques


def test_extract_techniques_reads_stix_attack_patterns(tmp_path):
    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Exploit Public-Facing Application",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1190"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            },
            {
                "type": "course-of-action",
                "name": "not a technique",
            },
        ]
    }
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    result = extract_techniques(stix_path)

    assert len(result) == 1
    row = result.iloc[0]
    assert row["technique_id"] == "T1190"
    assert row["technique_name"] == "Exploit Public-Facing Application"
    assert row["tactic"] == "initial-access"
    assert row["cwe_ids"] == ""
