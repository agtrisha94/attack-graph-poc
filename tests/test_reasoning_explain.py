from src.reasoning.explain import build_explanation


def _path(**overrides):
    base = {
        "source_cve": "CVE-2023-1234", "base_score": 8.8, "epss_score": 0.94,
        "source_asset_id": "computer-0002", "target_asset_id": "sql-prod-01",
        "target_criticality_tier": "Crown Jewel", "hop_count": 3, "technique_ids": [],
    }
    base.update(overrides)
    return base


def test_build_explanation_covers_path_facts_with_no_technique():
    result = build_explanation(_path(technique_ids=[]), {"threat_actors": [], "mitigations": []})

    assert result == (
        "CVE-2023-1234 (CVSS 8.8, EPSS 0.94) exploits computer-0002 and reaches "
        "sql-prod-01 (Crown Jewel) via 3 hop(s)."
    )


def test_build_explanation_appends_technique_and_grounded_facts():
    result = build_explanation(
        _path(technique_ids=["T1190"]),
        {"threat_actors": ["APT29", "APT38", "Lazarus Group"], "mitigations": ["Vulnerability Scanning"]},
    )

    assert "Maps to ATT&CK technique(s) T1190." in result
    assert "Used by APT29, APT38, Lazarus Group." in result
    assert "Mitigations: Vulnerability Scanning." in result


def test_build_explanation_caps_long_lists_with_a_remainder_count():
    result = build_explanation(
        _path(technique_ids=["T1190"]),
        {"threat_actors": ["A", "B", "C", "D", "E"], "mitigations": []},
    )

    assert "Used by A, B, C, and 2 other(s)." in result


def test_build_explanation_notes_absence_of_threat_actors_and_mitigations():
    result = build_explanation(_path(technique_ids=["T1190"]), {"threat_actors": [], "mitigations": []})

    assert "No known threat-actor group on record." in result
    assert "No known mitigation on record." in result
