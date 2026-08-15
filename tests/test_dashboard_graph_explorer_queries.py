from unittest.mock import MagicMock, call

from dashboard._graph_explorer_queries import (
    AFFECTS_EDGES_QUERY,
    ASSET_NODES_QUERY,
    CVE_NODES_QUERY,
    MAPS_TO_EDGES_QUERY,
    TECHNIQUE_NODES_QUERY,
    TOPOLOGY_EDGES_QUERY,
    read_attack_relevant_subgraph,
)


def test_topology_edges_query_covers_all_five_topology_relationship_types():
    for rel_type in ("RUNS", "CONNECTS_TO", "MEMBER_OF", "HAS_SESSION", "CONTROLS"):
        assert rel_type in TOPOLOGY_EDGES_QUERY


def test_cve_nodes_query_scopes_to_cves_with_an_affects_edge():
    assert "AFFECTS" in CVE_NODES_QUERY
    assert "DISTINCT" in CVE_NODES_QUERY


def test_technique_nodes_query_scopes_via_affects_and_maps_to():
    assert "AFFECTS" in TECHNIQUE_NODES_QUERY
    assert "MAPS_TO" in TECHNIQUE_NODES_QUERY


def test_read_attack_relevant_subgraph_runs_all_six_queries_and_combines_results():
    session = MagicMock()
    assets = [{"node_id": "computer-0001", "display_name": "Host-1", "node_type": "Computer",
               "criticality_tier": "High", "blast_radius": None, "choke_point_count": None}]
    cves = [{"cve_id": "CVE-2023-1234", "vendor": "microsoft", "product": "exchange server",
             "base_score": 8.8, "epss_score": 0.94, "base_severity": "HIGH", "kev_flag": True}]
    techniques = [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
                   "tactic": ["initial-access"]}]
    topology_edges = [{"source_id": "computer-0001", "target_id": "computer-0002", "rel_type": "CONNECTS_TO"}]
    affects_edges = [{"source_id": "CVE-2023-1234", "target_id": "computer-0001", "rel_type": "AFFECTS"}]
    maps_to_edges = [{"source_id": "CVE-2023-1234", "target_id": "T1190", "rel_type": "MAPS_TO"}]
    session.run.side_effect = [assets, cves, techniques, topology_edges, affects_edges, maps_to_edges]

    result = read_attack_relevant_subgraph(session)

    assert result == {
        "assets": assets, "cves": cves, "techniques": techniques,
        "topology_edges": topology_edges, "affects_edges": affects_edges,
        "maps_to_edges": maps_to_edges,
    }
    assert session.run.call_args_list == [
        call(ASSET_NODES_QUERY), call(CVE_NODES_QUERY), call(TECHNIQUE_NODES_QUERY),
        call(TOPOLOGY_EDGES_QUERY), call(AFFECTS_EDGES_QUERY), call(MAPS_TO_EDGES_QUERY),
    ]
