from unittest.mock import MagicMock

from dashboard._overview_queries import (
    COUNT_ATTACK_PATHS_QUERY,
    COUNT_CROWN_JEWEL_TARGETS_QUERY,
    PATH_COUNTS_BY_CRITICALITY_QUERY,
    TOP_BLAST_RADIUS_QUERY,
    TOP_CHOKE_POINTS_QUERY,
    count_attack_paths,
    count_crown_jewel_targets,
    path_counts_by_criticality,
    top_blast_radius,
    top_choke_points,
)


def test_count_attack_paths_runs_query_and_returns_count():
    session = MagicMock()
    session.run.return_value.single.return_value = {"n": 50}

    result = count_attack_paths(session)

    assert result == 50
    session.run.assert_called_once_with(COUNT_ATTACK_PATHS_QUERY)


def test_count_crown_jewel_targets_query_joins_attackpath_and_asset():
    assert "AttackPath" in COUNT_CROWN_JEWEL_TARGETS_QUERY
    assert "Crown Jewel" in COUNT_CROWN_JEWEL_TARGETS_QUERY
    assert "DISTINCT" in COUNT_CROWN_JEWEL_TARGETS_QUERY


def test_count_crown_jewel_targets_runs_query_and_returns_count():
    session = MagicMock()
    session.run.return_value.single.return_value = {"n": 3}

    result = count_crown_jewel_targets(session)

    assert result == 3
    session.run.assert_called_once_with(COUNT_CROWN_JEWEL_TARGETS_QUERY)


def test_top_choke_points_runs_query_with_limit_and_returns_rows():
    session = MagicMock()
    rows = [{"node_id": "computer-0001", "display_name": "Host-1", "choke_point_count": 4}]
    session.run.return_value = rows

    result = top_choke_points(session, limit=5)

    assert result == rows
    session.run.assert_called_once_with(TOP_CHOKE_POINTS_QUERY, limit=5)


def test_top_blast_radius_runs_query_with_limit_and_returns_rows():
    session = MagicMock()
    rows = [{"node_id": "computer-0002", "display_name": "Host-2", "blast_radius": 12}]
    session.run.return_value = rows

    result = top_blast_radius(session, limit=5)

    assert result == rows
    session.run.assert_called_once_with(TOP_BLAST_RADIUS_QUERY, limit=5)


def test_path_counts_by_criticality_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{"tier": "Crown Jewel", "count": 10}, {"tier": "High", "count": 5}]
    session.run.return_value = rows

    result = path_counts_by_criticality(session)

    assert result == rows
    session.run.assert_called_once_with(PATH_COUNTS_BY_CRITICALITY_QUERY)
