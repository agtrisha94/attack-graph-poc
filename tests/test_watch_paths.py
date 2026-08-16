from unittest.mock import MagicMock, patch


def test_main_applies_scenarios_rescores_diffs_and_writes_alerts(monkeypatch, capsys):
    monkeypatch.setenv("NEO4J_PASSWORD", "test-password")
    fake_session = MagicMock()
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = fake_session

    baseline = {"old123": {
        "path_id": "old123", "score": 32.76, "rank": 6, "source_cve": "CVE-2021-26855",
        "source_asset_id": "computer-0078", "target_asset_id": "computer-0160",
    }}
    candidates = [{"cve_id": "CVE-2021-26855"}]
    routes = [{
        "node_ids": ["computer-0078", "computer-0160"], "score": 81.9, "rank": 1,
        "hop_count": 1, "source_cve": "CVE-2021-26855",
        "source_asset_id": "computer-0078", "target_asset_id": "computer-0160",
    }]
    alerts = [{"alert_id": "new_top50_entry:new456", "alert_type": "new_top50_entry", "path_id": "new456"}]

    with patch("scripts.watch_paths.GraphDatabase") as fake_gdb, \
         patch("scripts.watch_paths.apply_kev_disclosure", return_value={"cve_id": "CVE-2009-0133", "before": False, "after": True}) as fake_kev, \
         patch("scripts.watch_paths.apply_epss_spike", return_value={"cve_id": "CVE-2024-29988", "before": 0.45151, "after": 0.95}) as fake_epss, \
         patch("scripts.watch_paths.apply_new_topology_edge", return_value={"source_asset_id": "computer-0078", "target_asset_id": "computer-0160"}) as fake_edge, \
         patch("scripts.watch_paths.read_baseline_paths", return_value=baseline) as fake_read_baseline, \
         patch("scripts.watch_paths.extract_candidate_paths", return_value=candidates) as fake_extract, \
         patch("scripts.watch_paths.dedupe_and_rank", return_value=routes) as fake_rank, \
         patch("scripts.watch_paths.diff_paths", return_value=alerts) as fake_diff, \
         patch("scripts.watch_paths.clear_previous_alerts") as fake_clear, \
         patch("scripts.watch_paths.write_alerts", return_value=1) as fake_write:
        fake_gdb.driver.return_value = fake_driver

        from scripts.watch_paths import main
        main()

        fake_read_baseline.assert_called_once_with(fake_session)
        fake_kev.assert_called_once_with(fake_session)
        fake_epss.assert_called_once_with(fake_session)
        fake_edge.assert_called_once_with(fake_session)
        fake_extract.assert_called_once_with(fake_session)
        fake_rank.assert_called_once_with(candidates, top_n=50)
        fake_diff.assert_called_once_with(baseline, routes)
        fake_clear.assert_called_once_with(fake_session)
        fake_write.assert_called_once_with(fake_session, alerts)

    captured = capsys.readouterr()
    assert "kev_disclosure(CVE-2009-0133: False -> True)" in captured.out
    assert "epss_spike(CVE-2024-29988: 0.45151 -> 0.95)" in captured.out
    assert "new_topology_edge(computer-0078 -> computer-0160)" in captured.out
    assert "wrote 1 Alert node(s)" in captured.out
