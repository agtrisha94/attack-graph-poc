# tests/test_find_paths.py
from unittest.mock import MagicMock, patch


def test_main_extracts_dedupes_analyzes_and_writes_back(monkeypatch, capsys):
    monkeypatch.setenv("NEO4J_PASSWORD", "test-password")
    fake_session = MagicMock()
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = fake_session

    candidates = [{"cve_id": "CVE-1"}]
    routes = [{"node_ids": ["a", "b"], "score": 10.0, "rank": 1}]

    with patch("scripts.find_paths.GraphDatabase") as fake_gdb, \
         patch("scripts.find_paths.extract_candidate_paths", return_value=candidates) as fake_extract, \
         patch("scripts.find_paths.dedupe_and_rank", return_value=routes) as fake_dedupe, \
         patch("scripts.find_paths.extract_blast_radius", return_value={"a": 5}) as fake_blast, \
         patch("scripts.find_paths.choke_point_counts", return_value={}) as fake_choke, \
         patch("scripts.find_paths.write_attack_paths", return_value=1) as fake_write_paths, \
         patch("scripts.find_paths.write_asset_metrics") as fake_write_metrics:
        fake_gdb.driver.return_value = fake_driver

        from scripts.find_paths import main
        main()

        fake_extract.assert_called_once_with(fake_session)
        fake_dedupe.assert_called_once_with(candidates, top_n=50)
        fake_blast.assert_called_once_with(fake_session)
        fake_choke.assert_called_once_with(routes)
        fake_write_paths.assert_called_once_with(fake_session, routes)
        fake_write_metrics.assert_called_once_with(fake_session, {"a": 5}, {})

    captured = capsys.readouterr()
    assert "1 candidate" in captured.out
    assert "1 distinct route" in captured.out
