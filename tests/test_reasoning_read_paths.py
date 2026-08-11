from unittest.mock import MagicMock

from src.reasoning.read_paths import READ_PATHS_QUERY, read_attack_paths


def test_read_paths_query_joins_cve_target_and_optional_technique():
    assert "AttackPath" in READ_PATHS_QUERY
    assert "MAPS_TO" in READ_PATHS_QUERY
    assert "OPTIONAL MATCH" in READ_PATHS_QUERY
    assert "collect(DISTINCT t.technique_id)" in READ_PATHS_QUERY


def test_read_attack_paths_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{
        "path_id": "abc123", "source_cve": "CVE-2023-1234", "source_asset_id": "computer-0002",
        "target_asset_id": "sql-prod-01", "hop_count": 3, "base_score": 8.8, "epss_score": 0.94,
        "target_criticality_tier": "Crown Jewel", "technique_ids": ["T1190"],
    }]
    session.run.return_value = rows

    result = read_attack_paths(session)

    assert result == rows
    session.run.assert_called_once_with(READ_PATHS_QUERY)
