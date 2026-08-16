"""Live acceptance tests: verify each contracts/0N_*.yaml's
consumer_must_validate checklist against the real pipeline output (real
CSVs, the real running Neo4j graph) -- not mocks. See
docs/superpowers/specs/2026-08-16-qa-docs-design.md."""
import pandas as pd

VENDOR_ALIASES = [
    "microsoft", "windows", "azure", "office", "exchange", "sql server",
    ".net", "edge", "sharepoint", "active directory",
]

CVE_MASTER_REQUIRED_COLUMNS = [
    "cve_id", "vendor", "product", "description", "base_severity",
    "base_score", "epss_score", "epss_percentile", "kev_flag",
    "published_date",
]
NODES_REQUIRED_COLUMNS = [
    "node_id", "node_type", "display_name", "criticality_tier",
]
EDGES_REQUIRED_COLUMNS = ["source_id", "target_id", "edge_type"]


def test_contract_01_requirements_to_data():
    cve_df = pd.read_csv("data/processed/microsoft_cve_master.csv")
    technique_df = pd.read_csv("data/processed/technique_map.csv")
    nodes_df = pd.read_csv("data/synthetic/nodes_topology.csv")
    edges_df = pd.read_csv("data/synthetic/edges_topology.csv")

    for col in CVE_MASTER_REQUIRED_COLUMNS:
        assert col in cve_df.columns, f"microsoft_cve_master.csv missing required column {col}"
    for col in NODES_REQUIRED_COLUMNS:
        assert col in nodes_df.columns, f"nodes_topology.csv missing required column {col}"
    for col in EDGES_REQUIRED_COLUMNS:
        assert col in edges_df.columns, f"edges_topology.csv missing required column {col}"

    assert cve_df["cve_id"].notna().all(), "cve_id has null values"
    assert cve_df["epss_score"].notna().all(), "epss_score has null values"
    assert cve_df["epss_score"].between(0, 1).all(), "epss_score out of [0,1]"
    assert cve_df["epss_percentile"].between(0, 1).all(), "epss_percentile out of [0,1]"
    assert cve_df["base_score"].between(0, 10).all(), "base_score out of [0,10]"
    assert cve_df["kev_flag"].dtype == bool, "kev_flag is not boolean"

    kev_true = cve_df[cve_df["kev_flag"]]
    kev_false = cve_df[~cve_df["kev_flag"]]
    assert kev_false["kev_date_added"].isna().all(), "kev_date_added set on a non-KEV row"
    assert kev_false["ransomware_used"].isna().all(), "ransomware_used set on a non-KEV row"
    assert kev_true["kev_date_added"].notna().all(), "kev_date_added null on a KEV row"

    out_of_scope = cve_df[~cve_df["vendor"].str.lower().apply(
        lambda v: any(alias in v for alias in VENDOR_ALIASES)
    )]
    assert len(out_of_scope) == 0, (
        f"{len(out_of_scope)} row(s) fail the Microsoft-scope vendor_aliases match: "
        f"{out_of_scope['cve_id'].tolist()[:5]}"
    )

    for name, df in [
        ("microsoft_cve_master.csv", cve_df), ("technique_map.csv", technique_df),
        ("nodes_topology.csv", nodes_df), ("edges_topology.csv", edges_df),
    ]:
        assert len(df) > 0, f"{name} is empty"

    node_ids = set(nodes_df["node_id"])
    missing_source = ~edges_df["source_id"].isin(node_ids)
    missing_target = ~edges_df["target_id"].isin(node_ids)
    assert not missing_source.any(), f"edges reference unknown source_id: {edges_df[missing_source]['source_id'].tolist()[:5]}"
    assert not missing_target.any(), f"edges reference unknown target_id: {edges_df[missing_target]['target_id'].tolist()[:5]}"
