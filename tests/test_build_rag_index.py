import json

from scripts.build_rag_index import build_chunks


def _bundle(objects):
    return {"objects": objects}


def test_build_chunks_extracts_technique_mitigation_and_threat_actor(tmp_path):
    bundle = _bundle([
        {
            "type": "attack-pattern", "name": "Valid Accounts", "description": "Adversaries may use valid accounts.",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1078"}],
        },
        {
            "type": "course-of-action", "name": "Multi-factor Authentication", "description": "Use MFA.",
            "external_references": [{"source_name": "mitre-attack", "external_id": "M1032"}],
        },
        {"type": "intrusion-set", "name": "APT38", "description": "A North Korean threat group."},
    ])
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    chunks = build_chunks(stix_path)

    assert chunks == [
        {"id": "T1078", "source_type": "technique", "name": "Valid Accounts",
         "text": "Valid Accounts: Adversaries may use valid accounts."},
        {"id": "M1032", "source_type": "mitigation", "name": "Multi-factor Authentication",
         "text": "Multi-factor Authentication: Use MFA."},
        {"id": "APT38", "source_type": "threat_actor", "name": "APT38",
         "text": "APT38: A North Korean threat group."},
    ]


def test_build_chunks_skips_revoked_and_deprecated_objects(tmp_path):
    bundle = _bundle([
        {
            "type": "attack-pattern", "name": "Old Technique", "description": "No longer valid.",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
        },
        {
            "type": "attack-pattern", "name": "Deprecated Technique", "description": "Also gone.",
            "x_mitre_deprecated": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T0002"}],
        },
    ])
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    assert build_chunks(stix_path) == []


def test_build_chunks_skips_unrelated_stix_types_and_missing_description(tmp_path):
    bundle = _bundle([
        {"type": "malware", "name": "Some Malware", "description": "Not a chunk source type."},
        {"type": "attack-pattern", "name": "No Description Technique"},
    ])
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    assert build_chunks(stix_path) == []


def test_build_chunks_falls_back_to_name_when_no_mitre_external_id(tmp_path):
    bundle = _bundle([
        {"type": "intrusion-set", "name": "Unnamed Group", "description": "No external ID on this one."},
    ])
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    chunks = build_chunks(stix_path)

    assert chunks[0]["id"] == "Unnamed Group"
