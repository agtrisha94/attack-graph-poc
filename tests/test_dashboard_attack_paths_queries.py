from unittest.mock import MagicMock

from dashboard._attack_paths_queries import (
    PATH_CHAIN_EDGE_TYPES_QUERY,
    READ_ATTACK_PATHS_WITH_REASONING_QUERY,
    SOURCE_TIER_WEIGHT_DEFAULTS,
    read_attack_paths_with_reasoning,
    read_path_chain_edge_types,
)


def test_query_joins_attack_path_cve_source_target_and_optional_reasoning():
    assert "AttackPath" in READ_ATTACK_PATHS_WITH_REASONING_QUERY
    assert "source:Asset" in READ_ATTACK_PATHS_WITH_REASONING_QUERY
    assert "target:Asset" in READ_ATTACK_PATHS_WITH_REASONING_QUERY
    assert "node_ids" in READ_ATTACK_PATHS_WITH_REASONING_QUERY
    assert "OPTIONAL MATCH" in READ_ATTACK_PATHS_WITH_REASONING_QUERY
    assert "EXPLAINED_BY" in READ_ATTACK_PATHS_WITH_REASONING_QUERY
    assert "ORDER BY p.rank" in READ_ATTACK_PATHS_WITH_REASONING_QUERY


def test_read_attack_paths_with_reasoning_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{
        "path_id": "abc123", "rank": 1, "pipeline_score": 33.44, "source_cve": "CVE-2023-1234",
        "source_asset_id": "computer-0002", "target_asset_id": "sql-prod-01",
        "node_ids": ["computer-0002", "group-0033", "sql-prod-01"], "hop_count": 2,
        "base_score": 8.8, "epss_score": 0.94, "source_criticality_tier": "Medium",
        "target_criticality_tier": "Crown Jewel", "explanation": "explained.",
        "technique_ids": ["T1190"], "threat_actors": ["APT38"], "mitigations": [],
    }]
    session.run.return_value = rows

    result = read_attack_paths_with_reasoning(session)

    assert result == rows
    session.run.assert_called_once_with(READ_ATTACK_PATHS_WITH_REASONING_QUERY)


def test_read_path_chain_edge_types_runs_query_with_node_ids():
    session = MagicMock()
    session.run.return_value = [{"i": 0, "rel_type": "RUNS"}, {"i": 1, "rel_type": "CONTROLS"}]

    result = read_path_chain_edge_types(session, ["computer-0002", "app-0003", "group-0033"])

    assert result == {0: "RUNS", 1: "CONTROLS"}
    session.run.assert_called_once_with(
        PATH_CHAIN_EDGE_TYPES_QUERY, node_ids=["computer-0002", "app-0003", "group-0033"],
    )


def test_read_path_chain_edge_types_skips_query_for_single_node():
    session = MagicMock()

    result = read_path_chain_edge_types(session, ["computer-0002"])

    assert result == {}
    session.run.assert_not_called()


def test_source_tier_weight_defaults_covers_all_four_tiers():
    assert set(SOURCE_TIER_WEIGHT_DEFAULTS) == {"Crown Jewel", "High", "Medium", "Low"}
