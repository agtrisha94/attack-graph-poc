from dashboard._chat_formatting import (
    format_asset_block,
    format_dataset_block,
    format_glossary_block,
    format_graph_block,
    format_mitre_block,
    mentioned_asset_ids,
    mentioned_path_ids,
)


def test_format_graph_block_returns_none_found_for_empty_list():
    assert format_graph_block([]) == "(none found)"


def test_format_graph_block_includes_score_components_and_route():
    paths = [{
        "path_id": "abc123", "rank": 1, "pipeline_score": 33.4, "source_cve": "CVE-2023-1234",
        "source_asset_id": "computer-0002", "target_asset_id": "sql-prod-01",
        "node_ids": ["computer-0002", "group-0033", "sql-prod-01"],
        "hop_count": 2, "base_score": 8.8, "epss_score": 0.94, "kev_flag": True,
        "attack_vector": "NETWORK", "source_internet_facing": True,
        "target_criticality_tier": "Crown Jewel", "explanation": "explained.",
        "edge_types": {0: "CONNECTS_TO", 1: "HAS_SESSION"},
    }]

    result = format_graph_block(paths)

    assert "score 33.40" in result
    assert "CVSS 8.8" in result
    assert "EPSS 0.94" in result
    assert "KEV" in result
    assert "internet-facing source" in result
    assert "2 hop(s)" in result
    assert "Route: CONNECTS_TO -> HAS_SESSION" in result
    assert "explained." in result


def test_format_graph_block_handles_missing_score_fields_gracefully():
    paths = [{
        "path_id": "1", "rank": 1, "source_cve": "CVE-2024-1", "source_asset_id": "a",
        "target_asset_id": "b", "target_criticality_tier": "High", "explanation": None,
    }]

    result = format_graph_block(paths)

    assert "No resolved MITRE technique mapping" in result
    assert "Route:" not in result


def test_format_asset_block_lists_through_paths_with_details():
    assets = [{
        "asset_id": "computer-0081", "display_name": "Connectivity-Server-computer-0081",
        "choke_point_count": 4, "blast_radius": 111,
        "through_paths": [
            {"path_id": "p1", "rank": 3, "source_cve": "CVE-2021-1", "target_asset_id": "db-01"},
        ],
    }]

    result = format_asset_block(assets)

    assert "choke-point count = 4" in result
    assert "blast radius = 111" in result
    assert "#p1 (rank 3, CVE-2021-1 -> db-01)" in result


def test_format_asset_block_handles_null_metrics_and_no_through_paths():
    assets = [{
        "asset_id": "sql-prod-01", "display_name": "SQL-Prod-01",
        "choke_point_count": None, "blast_radius": None, "through_paths": [],
    }]

    result = format_asset_block(assets)

    assert "not a choke point on any ranked path" in result
    assert "not computed" in result
    assert "interior hop on ranked path(s): none" in result


def test_format_dataset_block_renders_stats_severity_and_products():
    stats = {"total": 500, "kev_count": 42}
    severity_rows = [{"severity": "Critical", "count": 10}, {"severity": "High", "count": 20}]
    top_products = [{"product": "Windows", "count": 100}, {"product": "Exchange", "count": 50}]

    result = format_dataset_block(stats, severity_rows, top_products)

    assert "Total CVEs: 500" in result
    assert "KEV (known exploited): 42" in result
    assert "Critical: 10" in result
    assert "Windows (100)" in result


def test_format_glossary_block_returns_none_found_for_empty_list():
    assert format_glossary_block([]) == "(none found)"


def test_format_glossary_block_tags_scope():
    entries = [{"term": "cve", "scope": "general", "definition": "A vulnerability identifier."}]

    result = format_glossary_block(entries)

    assert "cve [general]: A vulnerability identifier." in result


def test_format_mitre_block_returns_none_found_for_empty_list():
    assert format_mitre_block([]) == "(none found)"


def test_format_mitre_block_lists_chunks():
    chunks = [{"id": "T1078", "name": "Valid Accounts", "text": "Adversaries may use valid accounts."}]

    result = format_mitre_block(chunks)

    assert "T1078 (Valid Accounts): Adversaries may use valid accounts." in result


def test_mentioned_path_ids_finds_ids_present_in_answer():
    paths = [{"path_id": "e06b81e2c476d21a"}, {"path_id": "abc123"}]
    answer = "The path needing most attention is #e06b81e2c476d21a."

    assert mentioned_path_ids(answer, paths) == ["e06b81e2c476d21a"]


def test_mentioned_path_ids_returns_empty_list_when_none_mentioned():
    paths = [{"path_id": "e06b81e2c476d21a"}]
    answer = "I don't have enough information to answer that."

    assert mentioned_path_ids(answer, paths) == []


def test_mentioned_asset_ids_finds_ids_present_in_answer():
    assets = [{"asset_id": "computer-0230"}, {"asset_id": "sql-prod-01"}]
    answer = "Asset computer-0230 is a choke point on 4 ranked paths."

    assert mentioned_asset_ids(answer, assets) == ["computer-0230"]


def test_mentioned_asset_ids_returns_empty_list_when_none_mentioned():
    assert mentioned_asset_ids("no assets referenced here", [{"asset_id": "computer-0230"}]) == []
