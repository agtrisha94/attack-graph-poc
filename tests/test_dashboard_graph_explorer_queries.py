from unittest.mock import MagicMock, call

from dashboard._graph_explorer_queries import (
    ASSET_DETAIL_QUERY,
    ASSET_NETWORK_EDGES_QUERY,
    ASSET_NETWORK_NODES_QUERY,
    read_asset_detail,
    read_asset_network,
)


def test_edges_query_covers_all_five_topology_relationship_types():
    for rel_type in ("RUNS", "CONNECTS_TO", "MEMBER_OF", "HAS_SESSION", "CONTROLS"):
        assert rel_type in ASSET_NETWORK_EDGES_QUERY


def test_asset_detail_query_joins_affects_and_optional_maps_to():
    assert "AFFECTS" in ASSET_DETAIL_QUERY
    assert "OPTIONAL MATCH" in ASSET_DETAIL_QUERY
    assert "MAPS_TO" in ASSET_DETAIL_QUERY


def test_read_asset_network_runs_both_queries_and_returns_nodes_and_edges():
    session = MagicMock()
    nodes = [{
        "node_id": "computer-0001", "display_name": "Host-1", "node_type": "Computer",
        "criticality_tier": "High", "blast_radius": 5, "choke_point_count": 2,
    }]
    edges = [{"source_id": "computer-0001", "target_id": "computer-0002", "rel_type": "CONNECTS_TO"}]
    session.run.side_effect = [nodes, edges]

    result = read_asset_network(session)

    assert result == {"nodes": nodes, "edges": edges}
    assert session.run.call_args_list == [
        call(ASSET_NETWORK_NODES_QUERY), call(ASSET_NETWORK_EDGES_QUERY),
    ]


def test_read_asset_detail_runs_query_with_node_id_and_returns_rows():
    session = MagicMock()
    rows = [{"cve_id": "CVE-2023-1234", "base_score": 8.8, "epss_score": 0.94, "technique_ids": ["T1190"]}]
    session.run.return_value = rows

    result = read_asset_detail(session, "computer-0001")

    assert result == rows
    session.run.assert_called_once_with(ASSET_DETAIL_QUERY, node_id="computer-0001")
