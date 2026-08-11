"""Validates the imported Neo4j graph against contract 02/data_schema.yaml
expectations: node/edge counts match the source CSVs, required CVE fields are
non-null (Community Edition has no existence constraints, see
src/graph/schema.py), and every Asset carrying installed_software is reachable
from at least one CVE via AFFECTS (the FR3 guarantee from requirements.md)."""
import pathlib

import pandas as pd

REQUIRED_CVE_FIELDS = [
    "vendor", "product", "description", "base_severity", "base_score",
    "epss_score", "epss_percentile", "kev_flag", "published_date",
]


def _count(session, query: str, **params) -> int:
    return session.run(query, **params).single()["n"]


def validate_graph(session, processed_dir: pathlib.Path, synthetic_dir: pathlib.Path) -> list[str]:
    violations: list[str] = []

    expected_cve = len(pd.read_csv(processed_dir / "microsoft_cve_master.csv"))
    expected_technique = len(pd.read_csv(processed_dir / "technique_map.csv"))
    expected_asset = len(pd.read_csv(synthetic_dir / "nodes_topology.csv"))
    expected_edges = len(pd.read_csv(synthetic_dir / "edges_topology.csv"))

    actual_cve = _count(session, "MATCH (c:CVE) RETURN count(c) AS n")
    if actual_cve != expected_cve:
        violations.append(f"CVE node count {actual_cve} != microsoft_cve_master.csv rows {expected_cve}")

    actual_technique = _count(session, "MATCH (t:Technique) RETURN count(t) AS n")
    if actual_technique != expected_technique:
        violations.append(f"Technique node count {actual_technique} != technique_map.csv rows {expected_technique}")

    actual_asset = _count(session, "MATCH (a:Asset) RETURN count(a) AS n")
    if actual_asset != expected_asset:
        violations.append(f"Asset node count {actual_asset} != nodes_topology.csv rows {expected_asset}")

    actual_edges = _count(session, "MATCH ()-[r]->() WHERE type(r) IN "
                           "['RUNS','CONNECTS_TO','MEMBER_OF','HAS_SESSION','CONTROLS'] RETURN count(r) AS n")
    if actual_edges != expected_edges:
        violations.append(f"topology relationship count {actual_edges} != edges_topology.csv rows {expected_edges}")

    null_field_clause = " OR ".join(f"c.{f} IS NULL" for f in REQUIRED_CVE_FIELDS)
    missing_required = _count(session, f"MATCH (c:CVE) WHERE {null_field_clause} RETURN count(c) AS n")
    if missing_required:
        violations.append(f"{missing_required} CVE node(s) missing a required field")

    uncovered = _count(session, "MATCH (a:Asset) WHERE size(a.installed_software) > 0 "
                        "AND NOT (a)<-[:AFFECTS]-(:CVE) RETURN count(a) AS n")
    if uncovered:
        violations.append(f"{uncovered} Asset node(s) with installed_software have no AFFECTS relationship")

    return violations


def main() -> None:
    import os

    from neo4j import GraphDatabase

    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        violations = validate_graph(session, pathlib.Path("data/processed"), pathlib.Path("data/synthetic"))
    driver.close()
    if violations:
        print(f"FAILED: {len(violations)} violation(s)")
        for v in violations:
            print(f"  - {v}")
        raise SystemExit(1)
    print("PASSED: all contract 02/03 graph checks satisfied")


if __name__ == "__main__":
    main()
