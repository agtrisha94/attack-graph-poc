from unittest.mock import MagicMock

from src.paths.writeback import (
    clear_previous_results,
    path_id_for,
    write_asset_metrics,
    write_attack_paths,
)


def test_path_id_for_is_deterministic_and_order_sensitive():
    forward = path_id_for(["x", "y", "z"])
    forward_again = path_id_for(["x", "y", "z"])
    reversed_ = path_id_for(["z", "y", "x"])

    assert forward == forward_again
    assert forward != reversed_


def test_write_attack_paths_merges_on_path_id_with_route_fields():
    session = MagicMock()
    routes = [{
        "score": 36.85, "hop_count": 2, "source_cve": "CVE-1",
        "source_asset_id": "computer-0001", "target_asset_id": "group-0033",
        "node_ids": ["computer-0001", "computer-0018", "group-0033"], "rank": 1,
    }]

    written = write_attack_paths(session, routes)

    assert written == 1
    query, kwargs = session.run.call_args
    assert "MERGE (p:AttackPath {path_id: row.path_id})" in query[0]
    [row] = kwargs["rows"]
    assert row["path_id"] == path_id_for(routes[0]["node_ids"])
    assert row["source_cve"] == "CVE-1"
    assert row["rank"] == 1


def test_write_attack_paths_noop_on_empty_routes():
    session = MagicMock()

    assert write_attack_paths(session, []) == 0
    session.run.assert_not_called()


def test_write_asset_metrics_sets_blast_radius_and_choke_point_count():
    session = MagicMock()

    write_asset_metrics(session, {"computer-0002": 14}, {"computer-0018": 2})

    queries = [call.args[0] for call in session.run.call_args_list]
    assert any("a.blast_radius = row.blast_radius" in q for q in queries)
    assert any("a.choke_point_count = row.choke_point_count" in q for q in queries)


def test_write_asset_metrics_writes_only_choke_points_when_blast_radius_empty():
    session = MagicMock()

    write_asset_metrics(session, {}, {"computer-0018": 2})

    assert session.run.call_count == 1
    query = session.run.call_args[0][0]
    assert "a.choke_point_count = row.choke_point_count" in query
    assert "a.blast_radius" not in query


def test_write_asset_metrics_skips_run_when_both_mappings_empty():
    session = MagicMock()

    write_asset_metrics(session, {}, {})

    session.run.assert_not_called()


def test_clear_previous_results_deletes_attack_paths_and_removes_asset_metrics():
    session = MagicMock()

    clear_previous_results(session)

    assert session.run.call_count == 2
    queries = [call.args[0] for call in session.run.call_args_list]
    assert any("MATCH (p:AttackPath) DETACH DELETE p" in q for q in queries)
    assert any("REMOVE a.blast_radius, a.choke_point_count" in q for q in queries)
