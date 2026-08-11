from unittest.mock import MagicMock

from dashboard._attack_paths_queries import (
    READ_ATTACK_PATHS_WITH_REASONING_QUERY,
    read_attack_paths_with_reasoning,
)


def test_query_joins_attack_path_cve_target_and_optional_reasoning():
    assert "AttackPath" in READ_ATTACK_PATHS_WITH_REASONING_QUERY
    assert "OPTIONAL MATCH" in READ_ATTACK_PATHS_WITH_REASONING_QUERY
    assert "EXPLAINED_BY" in READ_ATTACK_PATHS_WITH_REASONING_QUERY
    assert "ORDER BY p.rank" in READ_ATTACK_PATHS_WITH_REASONING_QUERY


def test_read_attack_paths_with_reasoning_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{
        "path_id": "abc123", "rank": 1, "source_cve": "CVE-2023-1234",
        "source_asset_id": "computer-0002", "target_asset_id": "sql-prod-01",
        "hop_count": 3, "base_score": 8.8, "epss_score": 0.94,
        "target_criticality_tier": "Crown Jewel", "explanation": "explained.",
        "technique_ids": ["T1190"], "threat_actors": ["APT38"], "mitigations": [],
    }]
    session.run.return_value = rows

    result = read_attack_paths_with_reasoning(session)

    assert result == rows
    session.run.assert_called_once_with(READ_ATTACK_PATHS_WITH_REASONING_QUERY)
