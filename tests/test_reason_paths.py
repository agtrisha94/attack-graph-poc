from unittest.mock import MagicMock, patch


def _run_main(monkeypatch, capsys, paths, total_count):
    monkeypatch.setenv("NEO4J_PASSWORD", "test-password")
    fake_session = MagicMock()
    fake_session.run.return_value.single.return_value = {"n": total_count}
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = fake_session

    technique_facts = {"T1190": {"threat_actors": ["APT38"], "mitigations": []}}
    resolved = {"threat_actors": ["APT38"], "mitigations": []}

    with patch("scripts.reason_paths.GraphDatabase") as fake_gdb, \
         patch("scripts.reason_paths.build_technique_facts", return_value=technique_facts), \
         patch("scripts.reason_paths.resolve_facts_for_techniques", return_value=resolved), \
         patch("scripts.reason_paths.build_explanation", return_value="explained."), \
         patch("scripts.reason_paths.read_attack_paths", return_value=paths), \
         patch("scripts.reason_paths.clear_previous_results"), \
         patch("scripts.reason_paths.write_reasoning", return_value=len(paths)):
        fake_gdb.driver.return_value = fake_driver

        from scripts.reason_paths import main
        main()

    return fake_session, capsys.readouterr()


def test_main_reads_resolves_explains_and_writes_back(monkeypatch, capsys):
    fake_session = MagicMock()
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = fake_session
    fake_session.run.return_value.single.return_value = {"n": 1}

    paths = [{
        "path_id": "abc123", "source_cve": "CVE-2023-1234", "source_asset_id": "computer-0002",
        "target_asset_id": "sql-prod-01", "hop_count": 3, "base_score": 8.8, "epss_score": 0.94,
        "target_criticality_tier": "Crown Jewel", "technique_ids": ["T1190"],
    }]
    technique_facts = {"T1190": {"threat_actors": ["APT38"], "mitigations": []}}
    resolved = {"threat_actors": ["APT38"], "mitigations": []}

    monkeypatch.setenv("NEO4J_PASSWORD", "test-password")
    with patch("scripts.reason_paths.GraphDatabase") as fake_gdb, \
         patch("scripts.reason_paths.build_technique_facts", return_value=technique_facts) as fake_build_facts, \
         patch("scripts.reason_paths.resolve_facts_for_techniques", return_value=resolved) as fake_resolve, \
         patch("scripts.reason_paths.build_explanation", return_value="explained.") as fake_explain, \
         patch("scripts.reason_paths.read_attack_paths", return_value=paths) as fake_read, \
         patch("scripts.reason_paths.clear_previous_results") as fake_clear, \
         patch("scripts.reason_paths.write_reasoning", return_value=1) as fake_write:
        fake_gdb.driver.return_value = fake_driver

        from scripts.reason_paths import main
        main()

        fake_build_facts.assert_called_once()
        fake_clear.assert_called_once_with(fake_session)
        fake_read.assert_called_once_with(fake_session)
        fake_resolve.assert_called_once_with(["T1190"], technique_facts)
        fake_explain.assert_called_once_with(paths[0], resolved)
        fake_write.assert_called_once_with(fake_session, [{
            "path_id": "abc123", "explanation": "explained.",
            "technique_ids": ["T1190"], "threat_actors": ["APT38"], "mitigations": [],
        }])

    captured = capsys.readouterr()
    assert "Read 1 AttackPath node(s), wrote 1 Reasoning node(s)" in captured.out
    assert "WARNING" not in captured.out


def test_main_warns_when_attack_paths_are_dropped(monkeypatch, capsys):
    paths = [{
        "path_id": "abc123", "source_cve": "CVE-2023-1234", "source_asset_id": "computer-0002",
        "target_asset_id": "sql-prod-01", "hop_count": 3, "base_score": 8.8, "epss_score": 0.94,
        "target_criticality_tier": "Crown Jewel", "technique_ids": ["T1190"],
    }]
    # Graph has 3 AttackPath nodes total, but only 1 was read back (2 dropped
    # by the non-optional CVE/Asset MATCH in READ_PATHS_QUERY).
    _, captured = _run_main(monkeypatch, capsys, paths, total_count=3)

    assert "WARNING" in captured.out
    assert "3 AttackPath node(s)" in captured.out
    assert "1 were read" in captured.out
    assert "2 dropped" in captured.out
