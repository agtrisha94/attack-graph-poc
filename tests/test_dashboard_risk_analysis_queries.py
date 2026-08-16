from unittest.mock import MagicMock, call

from dashboard._risk_analysis_queries import (
    BLAST_RADIUS_QUERY,
    CHOKE_POINT_QUERY,
    PATHS_THROUGH_ASSET_QUERY,
    REACHABLE_ASSETS_QUERY,
    REACHABLE_EDGES_QUERY,
    read_blast_radius,
    read_choke_points,
    read_paths_through_asset,
    read_reachable_subgraph,
)


def test_reachable_assets_query_computes_hop_distance_via_shortest_path():
    assert "shortestPath" in REACHABLE_ASSETS_QUERY
    assert "hop_distance" in REACHABLE_ASSETS_QUERY


def test_blast_radius_query_reads_stored_property_not_a_live_traversal():
    # Reads the value scripts/find_paths.py already wrote onto each :Asset
    # (src/paths/writeback.py::write_asset_metrics) rather than re-deriving
    # it with a duplicated traversal query that could drift from
    # src/paths/analysis.py's BLAST_RADIUS_QUERY (edge types, hop cap).
    assert "blast_radius IS NOT NULL" in BLAST_RADIUS_QUERY
    assert "a.blast_radius AS blast_radius" in BLAST_RADIUS_QUERY
    for rel_type in ("RUNS", "CONNECTS_TO", "MEMBER_OF", "HAS_SESSION", "CONTROLS", "AFFECTS"):
        assert rel_type not in BLAST_RADIUS_QUERY


def test_reachable_queries_exclude_member_of_and_use_hop_cap_five():
    for query in (REACHABLE_ASSETS_QUERY, REACHABLE_EDGES_QUERY):
        assert "MEMBER_OF" not in query
        assert "*0..5" in query


def test_choke_point_query_filters_null_choke_point_count():
    assert "choke_point_count IS NOT NULL" in CHOKE_POINT_QUERY


def test_paths_through_asset_query_matches_interior_hops_only():
    assert "node_ids[1..-1]" in PATHS_THROUGH_ASSET_QUERY


def test_reachable_edges_query_dedupes_undirected_matches():
    assert "s.node_id < t.node_id" in REACHABLE_EDGES_QUERY


def test_read_blast_radius_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{"asset_id": "computer-0001", "display_name": "Host-1", "blast_radius": 12}]
    session.run.return_value = rows

    result = read_blast_radius(session)

    assert result == rows
    session.run.assert_called_once_with(BLAST_RADIUS_QUERY)


def test_read_choke_points_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{"asset_id": "computer-0002", "display_name": "Host-2", "choke_point_count": 3}]
    session.run.return_value = rows

    result = read_choke_points(session)

    assert result == rows
    session.run.assert_called_once_with(CHOKE_POINT_QUERY)


def test_read_paths_through_asset_runs_query_with_asset_id():
    session = MagicMock()
    rows = [{"path_id": "abc", "rank": 1, "source_cve": "CVE-A",
             "source_asset_id": "computer-0001", "target_asset_id": "computer-0300"}]
    session.run.return_value = rows

    result = read_paths_through_asset(session, "computer-0002")

    assert result == rows
    session.run.assert_called_once_with(PATHS_THROUGH_ASSET_QUERY, asset_id="computer-0002")


def test_read_reachable_subgraph_runs_both_queries_and_combines_results():
    session = MagicMock()
    nodes = [{"node_id": "computer-0003", "display_name": "Host-3",
              "node_type": "Computer", "criticality_tier": "Medium", "hop_distance": 1}]
    edges = [{"source_id": "computer-0001", "target_id": "computer-0003", "rel_type": "CONNECTS_TO"}]
    session.run.side_effect = [nodes, edges]

    result = read_reachable_subgraph(session, "computer-0001")

    assert result == {"nodes": nodes, "edges": edges}
    assert session.run.call_args_list == [
        call(REACHABLE_ASSETS_QUERY, asset_id="computer-0001"),
        call(REACHABLE_EDGES_QUERY, asset_id="computer-0001"),
    ]
