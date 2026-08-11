import json

from src.reasoning.mitre_lookup import build_technique_facts, resolve_facts_for_techniques


def _bundle(objects):
    return {"objects": objects}


def test_build_technique_facts_maps_intrusion_set_uses_to_threat_actors(tmp_path):
    bundle = _bundle([
        {
            "type": "attack-pattern", "id": "attack-pattern--ap1", "name": "Exploit Public-Facing Application",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
        },
        {"type": "intrusion-set", "id": "intrusion-set--g1", "name": "APT38"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--g1", "target_ref": "attack-pattern--ap1"},
    ])
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    result = build_technique_facts(stix_path)

    assert result == {"T1190": {"threat_actors": ["APT38"], "mitigations": []}}


def test_build_technique_facts_excludes_non_intrusion_set_uses_relationships(tmp_path):
    bundle = _bundle([
        {
            "type": "attack-pattern", "id": "attack-pattern--ap1", "name": "Exploit Public-Facing Application",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
        },
        {"type": "malware", "id": "malware--m1", "name": "Not A Threat Actor"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "malware--m1", "target_ref": "attack-pattern--ap1"},
    ])
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    result = build_technique_facts(stix_path)

    assert result == {}


def test_build_technique_facts_maps_course_of_action_mitigates_to_mitigations(tmp_path):
    bundle = _bundle([
        {
            "type": "attack-pattern", "id": "attack-pattern--ap1", "name": "Exploit Public-Facing Application",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
        },
        {"type": "course-of-action", "id": "course-of-action--c1", "name": "Vulnerability Scanning"},
        {"type": "relationship", "relationship_type": "mitigates", "source_ref": "course-of-action--c1", "target_ref": "attack-pattern--ap1"},
    ])
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    result = build_technique_facts(stix_path)

    assert result == {"T1190": {"threat_actors": [], "mitigations": ["Vulnerability Scanning"]}}


def test_build_technique_facts_dedupes_and_sorts_names(tmp_path):
    bundle = _bundle([
        {
            "type": "attack-pattern", "id": "attack-pattern--ap1", "name": "T",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
        },
        {"type": "intrusion-set", "id": "intrusion-set--g1", "name": "Zeta Group"},
        {"type": "intrusion-set", "id": "intrusion-set--g2", "name": "Alpha Group"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--g1", "target_ref": "attack-pattern--ap1"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--g2", "target_ref": "attack-pattern--ap1"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--g1", "target_ref": "attack-pattern--ap1"},
    ])
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    result = build_technique_facts(stix_path)

    assert result["T1190"]["threat_actors"] == ["Alpha Group", "Zeta Group"]


def test_resolve_facts_for_techniques_unions_across_multiple_technique_ids():
    technique_facts = {
        "T1190": {"threat_actors": ["APT38"], "mitigations": ["Vulnerability Scanning"]},
        "T1059": {"threat_actors": ["Lazarus Group"], "mitigations": ["Vulnerability Scanning"]},
    }

    result = resolve_facts_for_techniques(["T1190", "T1059"], technique_facts)

    assert result == {
        "threat_actors": ["APT38", "Lazarus Group"],
        "mitigations": ["Vulnerability Scanning"],
    }


def test_resolve_facts_for_techniques_empty_technique_ids_returns_empty_lists():
    assert resolve_facts_for_techniques([], {"T1190": {"threat_actors": ["APT38"], "mitigations": []}}) == {
        "threat_actors": [], "mitigations": [],
    }


def test_resolve_facts_for_techniques_unknown_technique_id_yields_empty_lists():
    assert resolve_facts_for_techniques(["T9999"], {}) == {"threat_actors": [], "mitigations": []}
