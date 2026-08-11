from unittest.mock import MagicMock

from src.paths.analysis import BLAST_RADIUS_QUERY, choke_point_counts, extract_blast_radius


def test_blast_radius_query_excludes_self_and_uses_hop_cap():
    assert "*0..6" in BLAST_RADIUS_QUERY
    assert "reachable <> start" in BLAST_RADIUS_QUERY
    assert "AFFECTS" in BLAST_RADIUS_QUERY


def test_extract_blast_radius_returns_asset_id_to_count_mapping():
    session = MagicMock()
    session.run.return_value = [
        {"asset_id": "computer-0002", "blast_radius": 14},
        {"asset_id": "computer-0005", "blast_radius": 3},
    ]

    result = extract_blast_radius(session)

    assert result == {"computer-0002": 14, "computer-0005": 3}
    session.run.assert_called_once_with(BLAST_RADIUS_QUERY)


def test_choke_point_counts_flags_assets_on_more_than_one_route():
    routes = [
        {"node_ids": ["computer-0001", "hub", "group-0033"]},
        {"node_ids": ["computer-0002", "hub", "group-0034"]},
        {"node_ids": ["computer-0003", "other", "group-0035"]},
    ]

    counts = choke_point_counts(routes)

    assert counts == {"hub": 2}


def test_choke_point_counts_excludes_source_and_target_endpoints():
    routes = [
        {"node_ids": ["computer-0001", "group-0033"]},
        {"node_ids": ["computer-0001", "group-0033"]},
    ]

    assert choke_point_counts(routes) == {}


def test_choke_point_counts_counts_each_route_at_most_once_per_asset():
    # A route whose hop sequence happens to repeat a node should not let that
    # single route count twice toward the >1-route threshold.
    routes = [{"node_ids": ["a", "hub", "hub", "b"]}]

    assert choke_point_counts(routes) == {}


def test_choke_point_counts_empty_routes_returns_empty_dict():
    assert choke_point_counts([]) == {}
