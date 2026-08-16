import random
from unittest.mock import MagicMock

from src.paths.extract import HOP_CAP, PATH_QUERY, dedupe_and_rank, extract_candidate_paths
from src.paths.score import score_path


def _candidate(cve_id, base_score, epss_score, start_id, target_id, node_ids, hop_count,
                kev_flag=False, start_internet_facing=False, attack_vector=None):
    return {
        "cve_id": cve_id, "base_score": base_score, "epss_score": epss_score,
        "start_id": start_id, "target_id": target_id, "target_criticality": "Crown Jewel",
        "node_ids": node_ids, "hop_count": hop_count,
        "kev_flag": kev_flag, "start_internet_facing": start_internet_facing,
        "attack_vector": attack_vector,
    }


def test_path_query_uses_hop_cap_edge_types_and_crown_jewel_target():
    assert "allShortestPaths" in PATH_QUERY
    assert "AFFECTS" in PATH_QUERY
    assert f"*0..{HOP_CAP}" in PATH_QUERY
    assert "RUNS|CONNECTS_TO|HAS_SESSION|CONTROLS" in PATH_QUERY
    assert "MEMBER_OF" not in PATH_QUERY
    assert "Crown Jewel" in PATH_QUERY


def test_extract_candidate_paths_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [_candidate("CVE-1", 8.8, 0.5, "computer-0001", "group-0033",
                        ["computer-0001", "computer-0018", "group-0033"], 2)]
    session.run.return_value = rows

    result = extract_candidate_paths(session)

    assert result == rows
    session.run.assert_called_once_with(PATH_QUERY)


def test_dedupe_and_rank_keeps_max_scoring_cve_per_physical_route():
    candidates = [
        _candidate("CVE-LOW", 2.0, 0.1, "computer-0001", "group-0033",
                   ["computer-0001", "computer-0018", "group-0033"], 2),
        _candidate("CVE-HIGH", 9.8, 0.9, "computer-0001", "group-0033",
                   ["computer-0001", "computer-0018", "group-0033"], 2),
    ]

    routes = dedupe_and_rank(candidates, top_n=50)

    assert len(routes) == 1
    assert routes[0]["source_cve"] == "CVE-HIGH"
    assert routes[0]["score"] == score_path(
        9.8, 0.9, "Crown Jewel",
        kev_flag=False, hop_count=2, internet_facing=False, attack_vector=None,
    )
    assert routes[0]["rank"] == 1
    assert routes[0]["node_ids"] == ["computer-0001", "computer-0018", "group-0033"]


def test_dedupe_and_rank_treats_different_hop_sequences_as_distinct_routes():
    candidates = [
        _candidate("CVE-A", 5.0, 0.5, "computer-0001", "group-0033",
                   ["computer-0001", "computer-0018", "group-0033"], 2),
        _candidate("CVE-B", 5.0, 0.5, "computer-0001", "group-0033",
                   ["computer-0001", "computer-0099", "group-0033"], 2),
    ]

    routes = dedupe_and_rank(candidates, top_n=50)

    assert len(routes) == 2


def test_dedupe_and_rank_caps_to_top_n_by_score_descending():
    candidates = [
        _candidate(f"CVE-{i}", float(i), 1.0, f"asset-{i}", "group-0033",
                   [f"asset-{i}", "group-0033"], 1)
        for i in range(1, 6)
    ]

    routes = dedupe_and_rank(candidates, top_n=3)

    assert [r["source_cve"] for r in routes] == ["CVE-5", "CVE-4", "CVE-3"]
    assert [r["rank"] for r in routes] == [1, 2, 3]


def test_dedupe_and_rank_empty_input_returns_empty_list():
    assert dedupe_and_rank([], top_n=50) == []


def test_dedupe_and_rank_is_deterministic_on_score_ties():
    # Same base_score/epss_score/target_criticality/hop_count (and no
    # kev/exposure/attack-vector multipliers) -> identical score for every
    # candidate here, so ordering must come entirely from the node_ids
    # tiebreak, regardless of input order.
    candidates = [
        _candidate("CVE-A", 7.0, 0.5, "computer-0001", "group-0033",
                   ["computer-0001", "computer-0018", "group-0033"], 2),
        _candidate("CVE-B", 7.0, 0.5, "computer-0002", "group-0033",
                   ["computer-0002", "computer-0019", "group-0033"], 2),
        _candidate("CVE-C", 7.0, 0.5, "computer-0003", "group-0033",
                   ["computer-0003", "computer-0099", "group-0033"], 2),
        _candidate("CVE-D", 7.0, 0.5, "computer-0004", "group-0033",
                   ["computer-0004", "computer-0020", "group-0033"], 2),
    ]

    routes_in_order = dedupe_and_rank(candidates, top_n=50)

    shuffled = list(candidates)
    random.Random(42).shuffle(shuffled)
    routes_shuffled = dedupe_and_rank(shuffled, top_n=50)

    node_ids_in_order = [r["node_ids"] for r in routes_in_order]
    node_ids_shuffled = [r["node_ids"] for r in routes_shuffled]
    assert node_ids_in_order == node_ids_shuffled

    # All candidates score identically, so ordering is purely lexicographic
    # on node_ids.
    assert node_ids_in_order == [
        ["computer-0001", "computer-0018", "group-0033"],
        ["computer-0002", "computer-0019", "group-0033"],
        ["computer-0003", "computer-0099", "group-0033"],
        ["computer-0004", "computer-0020", "group-0033"],
    ]
