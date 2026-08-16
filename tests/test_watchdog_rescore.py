from unittest.mock import MagicMock

from src.paths.writeback import path_id_for
from src.watchdog.rescore import READ_BASELINE_QUERY, diff_paths, read_baseline_paths


def test_read_baseline_query_reads_attack_path_fields():
    assert "MATCH (p:AttackPath)" in READ_BASELINE_QUERY
    assert "p.path_id" in READ_BASELINE_QUERY
    assert "p.score" in READ_BASELINE_QUERY
    assert "p.rank" in READ_BASELINE_QUERY


def test_read_baseline_paths_keys_rows_by_path_id():
    session = MagicMock()
    session.run.return_value = [{
        "path_id": "abc123", "score": 10.0, "rank": 5, "source_cve": "CVE-X",
        "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }]

    result = read_baseline_paths(session)

    assert result == {"abc123": {
        "path_id": "abc123", "score": 10.0, "rank": 5, "source_cve": "CVE-X",
        "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }}
    session.run.assert_called_once_with(READ_BASELINE_QUERY)


def _route(node_ids, **overrides):
    base = {
        "node_ids": node_ids, "score": 10.0, "rank": 1,
        "source_cve": "CVE-X", "source_asset_id": "computer-0001",
        "target_asset_id": "computer-0002", "hop_count": 1,
    }
    base.update(overrides)
    return base


def test_diff_paths_flags_new_top50_entry():
    route = _route(["computer-0078", "computer-0160"])
    pid = path_id_for(route["node_ids"])

    alerts = diff_paths({}, [route])

    assert alerts == [{
        "alert_id": f"new_top50_entry:{pid}", "alert_type": "new_top50_entry", "path_id": pid,
        "old_score": None, "new_score": 10.0, "old_rank": None, "new_rank": 1,
        "source_cve": "CVE-X", "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }]


def test_diff_paths_flags_score_change_above_threshold():
    route = _route(["a", "b"], score=20.0, rank=3)
    pid = path_id_for(route["node_ids"])
    baseline = {pid: {
        "path_id": pid, "score": 10.0, "rank": 10, "source_cve": "CVE-X",
        "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }}

    alerts = diff_paths(baseline, [route])

    assert alerts == [{
        "alert_id": f"score_change:{pid}", "alert_type": "score_change", "path_id": pid,
        "old_score": 10.0, "new_score": 20.0, "old_rank": 10, "new_rank": 3,
        "source_cve": "CVE-X", "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }]


def test_diff_paths_ignores_score_change_below_threshold():
    route = _route(["a", "b"], score=10.5, rank=10)
    pid = path_id_for(route["node_ids"])
    baseline = {pid: {
        "path_id": pid, "score": 10.0, "rank": 10, "source_cve": "CVE-X",
        "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }}

    assert diff_paths(baseline, [route]) == []


def test_diff_paths_flags_dropped_from_top50():
    baseline = {"gone123": {
        "path_id": "gone123", "score": 32.76, "rank": 6, "source_cve": "CVE-2021-26855",
        "source_asset_id": "computer-0078", "target_asset_id": "computer-0160",
    }}

    alerts = diff_paths(baseline, [])

    assert alerts == [{
        "alert_id": "dropped_from_top50:gone123", "alert_type": "dropped_from_top50", "path_id": "gone123",
        "old_score": 32.76, "new_score": None, "old_rank": 6, "new_rank": None,
        "source_cve": "CVE-2021-26855", "source_asset_id": "computer-0078", "target_asset_id": "computer-0160",
    }]


def test_diff_paths_no_alerts_when_unchanged():
    route = _route(["a", "b"], score=10.0, rank=1)
    pid = path_id_for(route["node_ids"])
    baseline = {pid: {
        "path_id": pid, "score": 10.0, "rank": 1, "source_cve": "CVE-X",
        "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }}

    assert diff_paths(baseline, [route]) == []
