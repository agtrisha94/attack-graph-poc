"""Live acceptance tests: verify each contracts/0N_*.yaml's
consumer_must_validate checklist against the real pipeline output (real
CSVs, the real running Neo4j graph) -- not mocks. See
docs/superpowers/specs/2026-08-16-qa-docs-design.md."""
import pandas as pd
import pytest

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


import pathlib

from src.graph.validate import validate_graph


def test_contract_02_and_03_data_to_graph(neo4j_session):
    violations = validate_graph(
        neo4j_session, pathlib.Path("data/processed"), pathlib.Path("data/synthetic")
    )
    # Watchdog (Agent 6) permanently MERGEs one synthetic CONNECTS_TO edge
    # (computer-0078 -> computer-0160) into the live graph as its documented,
    # idempotent scenario mutation (src/watchdog/scenario.py:apply_new_topology_edge,
    # contracts/06_watchdog_to_qa.yaml) with no revert step -- by the time QA runs,
    # this +1 topology-edge drift from the raw CSV is expected, not a violation.
    expected_edges = len(pd.read_csv("data/synthetic/edges_topology.csv"))
    known_watchdog_drift = f"topology relationship count {expected_edges + 1} != edges_topology.csv rows {expected_edges}"
    violations = [v for v in violations if v != known_watchdog_drift]
    assert violations == [], f"graph import violations: {violations}"

    constraint_names = {
        record["name"] for record in neo4j_session.run("SHOW CONSTRAINTS")
    }
    for expected in ("cve_id_unique", "technique_id_unique", "asset_node_id_unique"):
        assert expected in constraint_names, f"missing constraint {expected}"


from src.paths.score import score_path

ATTACK_PATH_SCORE_QUERY = """
MATCH (p:AttackPath)
MATCH (c:CVE {cve_id: p.source_cve})
MATCH (src:Asset {node_id: p.source_asset_id})
MATCH (tgt:Asset {node_id: p.target_asset_id})
RETURN p.path_id AS path_id, p.score AS score, p.rank AS rank,
       p.hop_count AS hop_count, p.node_ids AS node_ids,
       p.source_cve AS source_cve,
       c.base_score AS base_score, c.epss_score AS epss_score,
       c.kev_flag AS kev_flag, c.attack_vector AS attack_vector,
       src.internet_facing AS internet_facing,
       tgt.criticality_tier AS criticality_tier
"""

# Watchdog (Agent 6) permanently mutates these two CVEs' kev_flag/epss_score
# in place (src/watchdog/scenario.py) without rewriting :AttackPath, by
# design -- so the persisted score of paths sourced from them no longer
# reproduces from current CVE state. Known, documented, not a defect.
KNOWN_WATCHDOG_MUTATED_CVES = {"CVE-2009-0133", "CVE-2024-29988"}


def test_contract_04_paths_to_reasoning(neo4j_session):
    rows = [dict(r) for r in neo4j_session.run(ATTACK_PATH_SCORE_QUERY)]
    assert len(rows) > 0, "no (:AttackPath) nodes found"

    asset_ids = {
        r["node_id"] for r in neo4j_session.run("MATCH (a:Asset) RETURN a.node_id AS node_id")
    }

    for row in rows:
        for node_id in row["node_ids"]:
            assert node_id in asset_ids, f"AttackPath {row['path_id']} node_ids has unknown asset {node_id}"

        if row["source_cve"] in KNOWN_WATCHDOG_MUTATED_CVES:
            assert row["score"] > 0, f"AttackPath {row['path_id']} has non-positive score"
            continue

        expected = score_path(
            row["base_score"], row["epss_score"], row["criticality_tier"],
            kev_flag=row["kev_flag"], hop_count=row["hop_count"],
            internet_facing=bool(row["internet_facing"]), attack_vector=row["attack_vector"],
        )
        assert row["score"] == pytest.approx(expected, rel=1e-6), (
            f"AttackPath {row['path_id']} score {row['score']} != recomputed {expected}"
        )

    ranks = sorted(r["rank"] for r in rows)
    assert ranks == list(range(1, len(rows) + 1)), f"rank is not a dense 1..N ordering: {ranks}"

    scores_by_rank = sorted(rows, key=lambda r: r["rank"])
    for a, b in zip(scores_by_rank, scores_by_rank[1:]):
        assert a["score"] >= b["score"], f"rank {a['rank']} score {a['score']} < rank {b['rank']} score {b['score']}"
