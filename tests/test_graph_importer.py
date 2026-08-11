import pandas as pd

from src.graph.importer import (
    cve_params, technique_params, asset_params,
    topology_edge_params, affects_params, maps_to_params,
)


def test_cve_params_converts_nan_to_none():
    df = pd.DataFrame([
        {"cve_id": "CVE-2026-0001", "vendor": "microsoft", "product": "exchange server",
         "description": "RCE", "cwe_id": None, "base_severity": "HIGH", "base_score": 8.8,
         "attack_vector": "NETWORK", "epss_score": 0.5, "epss_percentile": 0.9,
         "kev_flag": True, "kev_date_added": "2026-01-05", "ransomware_used": "Known",
         "published_date": "2026-01-01"},
    ])
    [params] = cve_params(df)
    assert params["cve_id"] == "CVE-2026-0001"
    assert params["cwe_id"] is None
    assert params["kev_flag"] is True


def test_technique_params_splits_tactic_and_cwe_ids():
    df = pd.DataFrame([
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
         "tactic": "initial-access, execution", "cwe_ids": "CWE-79;CWE-89"},
        {"technique_id": "T1055", "technique_name": "Process Injection",
         "tactic": "privilege-escalation", "cwe_ids": ""},
    ])
    params = technique_params(df)
    assert params[0]["tactic"] == ["initial-access", "execution"]
    assert params[0]["cwe_ids"] == ["CWE-79", "CWE-89"]
    assert params[1]["cwe_ids"] == []


def test_asset_params_splits_installed_software():
    df = pd.DataFrame([
        {"node_id": "computer-0001", "node_type": "Computer", "display_name": "Host",
         "criticality_tier": "High", "installed_software": "exchange server;windows 10",
         "management_group": "Platform/Management"},
        {"node_id": "user-0002", "node_type": "User", "display_name": "User",
         "criticality_tier": "High", "installed_software": "", "management_group": "Platform/Management"},
    ])
    params = asset_params(df)
    assert params[0]["installed_software"] == ["exchange server", "windows 10"]
    assert params[1]["installed_software"] == []


def test_topology_edge_params_groups_by_edge_type():
    df = pd.DataFrame([
        {"source_id": "a", "target_id": "b", "edge_type": "RUNS", "properties": ""},
        {"source_id": "c", "target_id": "d", "edge_type": "MEMBER_OF", "properties": ""},
        {"source_id": "e", "target_id": "f", "edge_type": "RUNS", "properties": "level=admin"},
    ])
    grouped = topology_edge_params(df)
    assert {p["source_id"] for p in grouped["RUNS"]} == {"a", "e"}
    assert grouped["MEMBER_OF"] == [{"source_id": "c", "target_id": "d", "properties": {}}]
    assert {"source_id": "e", "target_id": "f", "properties": {"level": "admin"}} in grouped["RUNS"]


def test_affects_params_matches_installed_software_to_product_case_insensitively():
    cve_df = pd.DataFrame([
        {"cve_id": "CVE-1", "product": "Exchange Server"},
        {"cve_id": "CVE-2", "product": "windows 10"},
        {"cve_id": "CVE-3", "product": "sql server"},
    ])
    nodes_df = pd.DataFrame([
        {"node_id": "computer-0001", "installed_software": "exchange server;windows 10"},
        {"node_id": "user-0002", "installed_software": ""},
    ])
    pairs = affects_params(cve_df, nodes_df)
    assert {"cve_id": "CVE-1", "node_id": "computer-0001"} in pairs
    assert {"cve_id": "CVE-2", "node_id": "computer-0001"} in pairs
    assert not any(p["node_id"] == "user-0002" for p in pairs)
    assert not any(p["cve_id"] == "CVE-3" for p in pairs)


def test_maps_to_params_matches_cwe_id_to_cwe_ids_list():
    cve_df = pd.DataFrame([
        {"cve_id": "CVE-1", "cwe_id": "CWE-79"},
        {"cve_id": "CVE-2", "cwe_id": None},
    ])
    technique_df = pd.DataFrame([
        {"technique_id": "T1190", "cwe_ids": "CWE-79;CWE-89"},
        {"technique_id": "T1055", "cwe_ids": ""},
    ])
    pairs = maps_to_params(cve_df, technique_df)
    assert pairs == [{"cve_id": "CVE-1", "technique_id": "T1190"}]
