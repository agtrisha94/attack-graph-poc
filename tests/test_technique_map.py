import json
from src.ingestion.technique_map import build_technique_cwe_map, extract_techniques


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


def test_build_technique_cwe_map_pairs_attack_and_cwe_refs_from_same_capec_entry(tmp_path):
    capec_bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "external_references": [
                    {"source_name": "capec", "external_id": "CAPEC-112"},
                    {"source_name": "cwe", "external_id": "CWE-330"},
                    {"source_name": "cwe", "external_id": "CWE-326"},
                    {"source_name": "ATTACK", "external_id": "T1110"},
                ],
            },
            {
                "type": "attack-pattern",
                "external_references": [
                    {"source_name": "capec", "external_id": "CAPEC-1"},
                    {"source_name": "cwe", "external_id": "CWE-276"},
                    # no ATTACK reference on this entry - must not appear in the map
                ],
            },
        ]
    }
    capec_path = tmp_path / "stix-capec.json"
    capec_path.write_text(json.dumps(capec_bundle))

    result = build_technique_cwe_map(capec_path)

    assert result == {"T1110": ["CWE-326", "CWE-330"]}


def test_build_technique_cwe_map_merges_cwes_from_multiple_capec_entries_for_same_technique(tmp_path):
    capec_bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "external_references": [
                    {"source_name": "cwe", "external_id": "CWE-330"},
                    {"source_name": "ATTACK", "external_id": "T1110"},
                ],
            },
            {
                "type": "attack-pattern",
                "external_references": [
                    {"source_name": "cwe", "external_id": "CWE-521"},
                    {"source_name": "ATTACK", "external_id": "T1110"},
                ],
            },
        ]
    }
    capec_path = tmp_path / "stix-capec.json"
    capec_path.write_text(json.dumps(capec_bundle))

    result = build_technique_cwe_map(capec_path)

    assert result == {"T1110": ["CWE-330", "CWE-521"]}


def test_extract_techniques_populates_cwe_ids_from_capec_map(tmp_path):
    stix_bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Brute Force",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1110"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
                ],
            },
        ]
    }
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(stix_bundle))

    capec_bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "external_references": [
                    {"source_name": "cwe", "external_id": "CWE-330"},
                    {"source_name": "cwe", "external_id": "CWE-326"},
                    {"source_name": "ATTACK", "external_id": "T1110"},
                ],
            },
        ]
    }
    capec_path = tmp_path / "stix-capec.json"
    capec_path.write_text(json.dumps(capec_bundle))

    result = extract_techniques(stix_path, capec_path)

    assert result.iloc[0]["cwe_ids"] == "CWE-326;CWE-330"
