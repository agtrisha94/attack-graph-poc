from unittest.mock import MagicMock, patch

from dashboard._chatbot_queries import (
    PATH_CHAIN_EDGE_TYPES_QUERY,
    PATHS_THROUGH_ASSET_QUERY,
    READ_ATTACK_PATHS_FOR_CHAT_QUERY,
    extract_cve_ids,
    extract_technique_ids,
    read_attack_paths_for_chat,
    read_path_chain_edge_types,
    read_paths_through_asset,
    relevant_assets_for_question,
    relevant_paths_for_question,
)


def test_read_attack_paths_for_chat_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{
        "path_id": "abc123", "rank": 1, "pipeline_score": 33.4, "source_cve": "CVE-2023-1234",
        "source_asset_id": "computer-0002", "target_asset_id": "sql-prod-01", "node_ids": ["computer-0002", "sql-prod-01"],
        "hop_count": 1, "base_score": 8.8, "epss_score": 0.94, "kev_flag": True, "attack_vector": "NETWORK",
        "source_internet_facing": True, "target_criticality_tier": "Crown Jewel", "explanation": "explained.",
        "technique_ids": ["T1190"],
    }]
    session.run.return_value = rows

    result = read_attack_paths_for_chat(session)

    assert result == rows
    session.run.assert_called_once_with(READ_ATTACK_PATHS_FOR_CHAT_QUERY)


def test_read_attack_paths_for_chat_query_joins_cve_for_score_components():
    assert "MATCH (c:CVE {cve_id: p.source_cve})" in READ_ATTACK_PATHS_FOR_CHAT_QUERY
    for field in ("pipeline_score", "base_score", "epss_score", "kev_flag", "attack_vector",
                  "source_internet_facing", "hop_count", "node_ids"):
        assert field in READ_ATTACK_PATHS_FOR_CHAT_QUERY


def test_paths_through_asset_query_returns_path_details_not_just_id():
    for field in ("rank", "source_cve", "source_asset_id", "target_asset_id"):
        assert field in PATHS_THROUGH_ASSET_QUERY


def test_read_paths_through_asset_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{"path_id": "7", "rank": 2, "source_cve": "CVE-2024-1", "source_asset_id": "a", "target_asset_id": "b"}]
    session.run.return_value = rows

    result = read_paths_through_asset(session, "computer-0081")

    assert result == rows
    session.run.assert_called_once_with(PATHS_THROUGH_ASSET_QUERY, asset_id="computer-0081")


def test_read_path_chain_edge_types_runs_query_with_node_ids():
    session = MagicMock()
    session.run.return_value = [{"i": 0, "rel_type": "CONNECTS_TO"}, {"i": 1, "rel_type": "HAS_SESSION"}]

    result = read_path_chain_edge_types(session, ["a", "b", "c"])

    assert result == {0: "CONNECTS_TO", 1: "HAS_SESSION"}
    session.run.assert_called_once_with(PATH_CHAIN_EDGE_TYPES_QUERY, node_ids=["a", "b", "c"])


def test_read_path_chain_edge_types_skips_query_for_single_node():
    session = MagicMock()

    result = read_path_chain_edge_types(session, ["a"])

    assert result == {}
    session.run.assert_not_called()


def test_extract_cve_ids_finds_and_uppercases_ids():
    assert extract_cve_ids("what about cve-2024-1234 and CVE-2023-99999?") == [
        "CVE-2023-99999", "CVE-2024-1234",
    ]


def test_extract_cve_ids_returns_empty_list_when_none_present():
    assert extract_cve_ids("what's our highest-risk attack path?") == []


def test_extract_technique_ids_finds_base_and_subtechnique_ids():
    assert extract_technique_ids("explain t1078.004 and T1021") == ["T1021", "T1078.004"]


def test_relevant_paths_for_question_matches_on_source_cve():
    paths = [
        {"path_id": "1", "source_cve": "CVE-2024-1234", "technique_ids": []},
        {"path_id": "2", "source_cve": "CVE-2024-9999", "technique_ids": []},
    ]
    session = MagicMock()
    with patch("dashboard._chatbot_queries.read_attack_paths_for_chat", return_value=paths):
        result = relevant_paths_for_question(session, "What affects CVE-2024-1234?")

    assert result == [paths[0]]


def test_relevant_paths_for_question_matches_on_technique_id_overlap():
    paths = [
        {"path_id": "1", "source_cve": "CVE-2024-1234", "technique_ids": ["T1078"]},
        {"path_id": "2", "source_cve": "CVE-2024-9999", "technique_ids": ["T1021"]},
    ]
    session = MagicMock()
    with patch("dashboard._chatbot_queries.read_attack_paths_for_chat", return_value=paths):
        result = relevant_paths_for_question(session, "Tell me about T1021")

    assert result == [paths[1]]


def test_relevant_paths_for_question_falls_back_to_top_n_when_no_terms_found():
    paths = [{"path_id": str(i), "source_cve": f"CVE-2024-{i}", "technique_ids": []} for i in range(5)]
    session = MagicMock()
    with patch("dashboard._chatbot_queries.read_attack_paths_for_chat", return_value=paths):
        result = relevant_paths_for_question(session, "What's our highest-risk attack path?", top_n=3)

    assert result == paths[:3]


def test_relevant_paths_for_question_falls_back_when_terms_found_but_no_match():
    paths = [{"path_id": "1", "source_cve": "CVE-2024-1234", "technique_ids": ["T1078"]}]
    session = MagicMock()
    with patch("dashboard._chatbot_queries.read_attack_paths_for_chat", return_value=paths):
        result = relevant_paths_for_question(session, "What about CVE-2099-0001?", top_n=3)

    assert result == paths[:3]


def test_relevant_assets_for_question_matches_on_asset_id():
    assets = [
        {"asset_id": "computer-0081", "display_name": "Connectivity-Server-computer-0081",
         "choke_point_count": 4, "blast_radius": 12},
        {"asset_id": "sql-prod-01", "display_name": "SQL-Prod-01", "choke_point_count": None, "blast_radius": None},
    ]
    through_paths = [{"path_id": "7", "rank": 2, "source_cve": "CVE-2024-1",
                       "source_asset_id": "a", "target_asset_id": "b"}]
    session = MagicMock()
    with patch("dashboard._chatbot_queries.read_all_assets", return_value=assets), \
         patch("dashboard._chatbot_queries.read_paths_through_asset", return_value=through_paths):
        result = relevant_assets_for_question(session, "why is computer-0081 a choke point?")

    assert len(result) == 1
    assert result[0]["asset_id"] == "computer-0081"
    assert result[0]["through_paths"] == through_paths


def test_relevant_assets_for_question_matches_on_display_name_case_insensitive():
    assets = [{"asset_id": "computer-0081", "display_name": "Connectivity-Server-computer-0081",
               "choke_point_count": 4, "blast_radius": 12}]
    session = MagicMock()
    with patch("dashboard._chatbot_queries.read_all_assets", return_value=assets), \
         patch("dashboard._chatbot_queries.read_paths_through_asset", return_value=[]):
        result = relevant_assets_for_question(
            session, "why is connectivity-server-computer-0081 a choke point?",
        )

    assert len(result) == 1
    assert result[0]["through_paths"] == []


def test_relevant_assets_for_question_returns_empty_list_when_no_asset_named():
    assets = [{"asset_id": "computer-0081", "display_name": "Connectivity-Server-computer-0081",
               "choke_point_count": 4, "blast_radius": 12}]
    session = MagicMock()
    with patch("dashboard._chatbot_queries.read_all_assets", return_value=assets):
        result = relevant_assets_for_question(session, "what's our highest-risk attack path?")

    assert result == []
