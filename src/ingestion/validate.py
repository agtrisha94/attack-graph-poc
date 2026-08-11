"""Validates Agent 2 outputs against contracts/01_requirements_to_data.yaml's
consumer_must_validate checklist."""
import pathlib

import pandas as pd
import yaml

from src.ingestion.cve_merge import is_microsoft_scope

DEFAULT_PROCESSED = pathlib.Path("data/processed")
DEFAULT_SYNTHETIC = pathlib.Path("data/synthetic")
SCHEMA_PATH = pathlib.Path("schemas/data_schema.yaml")

# schema name in data_schema.yaml -> output CSV filename
_SCHEMA_FILES = {
    "microsoft_cve_master": "microsoft_cve_master.csv",
    "technique_map": "technique_map.csv",
    "topology_nodes": "nodes_topology.csv",
    "topology_edges": "edges_topology.csv",
}


def _required_columns_violations(dataframes: dict[str, pd.DataFrame]) -> list[str]:
    schemas = yaml.safe_load(SCHEMA_PATH.read_text())["schemas"]
    violations = []
    for schema_name, filename in _SCHEMA_FILES.items():
        required = [f["name"] for f in schemas[schema_name]["fields"] if f.get("required")]
        missing = [c for c in required if c not in dataframes[filename].columns]
        if missing:
            violations.append(f"{filename} missing required columns: {missing}")
    return violations


def _read_csv(path: pathlib.Path) -> pd.DataFrame:
    # ponytail: a headerless/empty CSV (e.g. pd.DataFrame([]).to_csv()) raises
    # EmptyDataError on read; treat it as a 0-row frame so the "is empty" /
    # "row count > 0" contract checks below can report it as a violation
    # instead of crashing the validator.
    try:
        return pd.read_csv(path)
    except pd.errors.EmptyDataError:
        return pd.DataFrame()


def validate_outputs(processed_dir: pathlib.Path, synthetic_dir: pathlib.Path) -> list[str]:
    violations: list[str] = []

    cve_master = _read_csv(processed_dir / "microsoft_cve_master.csv")
    technique_map = _read_csv(processed_dir / "technique_map.csv")
    nodes = _read_csv(synthetic_dir / "nodes_topology.csv")
    edges = _read_csv(synthetic_dir / "edges_topology.csv")
    violations += _required_columns_violations({
        "microsoft_cve_master.csv": cve_master,
        "technique_map.csv": technique_map,
        "nodes_topology.csv": nodes,
        "edges_topology.csv": edges,
    })

    if len(cve_master) == 0:
        violations.append("microsoft_cve_master.csv is empty")
        cve_master = pd.DataFrame(columns=[
            "cve_id", "vendor", "product", "epss_score", "epss_percentile",
            "base_score", "kev_flag", "kev_date_added", "ransomware_used",
        ])
    if cve_master["cve_id"].isna().any():
        violations.append("microsoft_cve_master.csv has null cve_id")
    if cve_master["epss_score"].isna().any() or not cve_master["epss_score"].between(0, 1).all():
        violations.append("microsoft_cve_master.csv has epss_score outside [0, 1] or null")
    if not cve_master["epss_percentile"].between(0, 1).all():
        violations.append("microsoft_cve_master.csv has epss_percentile outside [0, 1]")
    if not cve_master["base_score"].between(0, 10).all():
        violations.append("microsoft_cve_master.csv has base_score outside [0, 10]")
    kev_rows = cve_master[cve_master["kev_flag"] == True]  # noqa: E712
    non_kev_rows = cve_master[cve_master["kev_flag"] == False]  # noqa: E712
    for col in ("kev_date_added", "ransomware_used"):
        if kev_rows[col].isna().any():
            violations.append(f"microsoft_cve_master.csv has kev_flag=True with null {col}")
        if non_kev_rows[col].notna().any():
            violations.append(f"microsoft_cve_master.csv has kev_flag=False with non-null {col}")
    out_of_scope = cve_master[~cve_master.apply(
        lambda r: bool(r["kev_flag"]) or is_microsoft_scope([str(r["vendor"]), str(r["product"])]),
        axis=1,
    )]
    if len(out_of_scope) > 0:
        violations.append(f"microsoft_cve_master.csv has {len(out_of_scope)} row(s) outside the Microsoft-scope filter")

    if len(technique_map) == 0:
        violations.append("technique_map.csv is empty")

    if len(nodes) == 0:
        violations.append("nodes_topology.csv is empty")
    if len(edges) == 0:
        violations.append("edges_topology.csv is empty")
    node_ids = set(nodes["node_id"]) if "node_id" in nodes.columns else set()
    edge_sources = set(edges["source_id"]) if "source_id" in edges.columns else set()
    edge_targets = set(edges["target_id"]) if "target_id" in edges.columns else set()
    dangling = edge_sources - node_ids | edge_targets - node_ids
    if dangling:
        violations.append(f"edges_topology.csv has dangling node references: {sorted(dangling)[:5]}")

    return violations


def main() -> None:
    violations = validate_outputs(DEFAULT_PROCESSED, DEFAULT_SYNTHETIC)
    if violations:
        print(f"FAILED: {len(violations)} violation(s)")
        for v in violations:
            print(f"  - {v}")
        raise SystemExit(1)
    print("PASSED: all contract 01 checks satisfied")


if __name__ == "__main__":
    main()
