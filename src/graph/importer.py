"""CSV -> Cypher parameter builders and the MERGE statements that load
data/processed/*.csv and data/synthetic/*.csv into Neo4j."""
import pathlib

import pandas as pd

CVE_MASTER = pathlib.Path("data/processed/microsoft_cve_master.csv")
TECHNIQUE_MAP = pathlib.Path("data/processed/technique_map.csv")
NODES = pathlib.Path("data/synthetic/nodes_topology.csv")
EDGES = pathlib.Path("data/synthetic/edges_topology.csv")


def _split(value: str, sep: str) -> list[str]:
    if not value or (isinstance(value, float) and pd.isna(value)):
        return []
    return [v for v in value.split(sep) if v]


def _clean(record: dict) -> dict:
    return {k: (None if isinstance(v, float) and pd.isna(v) else v) for k, v in record.items()}


def cve_params(df: pd.DataFrame) -> list[dict]:
    return [_clean(r) for r in df.to_dict(orient="records")]


def technique_params(df: pd.DataFrame) -> list[dict]:
    params = []
    for r in df.to_dict(orient="records"):
        r = _clean(r)
        r["tactic"] = _split(r.get("tactic") or "", ", ")
        r["cwe_ids"] = _split(r.get("cwe_ids") or "", ";")
        params.append(r)
    return params


def asset_params(df: pd.DataFrame) -> list[dict]:
    params = []
    for r in df.to_dict(orient="records"):
        r = _clean(r)
        r["installed_software"] = _split(r.get("installed_software") or "", ";")
        params.append(r)
    return params


def topology_edge_params(df: pd.DataFrame) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for r in df.to_dict(orient="records"):
        props_raw = r.get("properties") or ""
        props = dict(pair.split("=", 1) for pair in props_raw.split(";") if "=" in pair) if props_raw and not pd.isna(props_raw) else {}
        grouped.setdefault(r["edge_type"], []).append({
            "source_id": r["source_id"], "target_id": r["target_id"], "properties": props,
        })
    return grouped


def affects_params(cve_df: pd.DataFrame, nodes_df: pd.DataFrame) -> list[dict]:
    product_to_cves: dict[str, list[str]] = {}
    for r in cve_df.to_dict(orient="records"):
        product_to_cves.setdefault(str(r["product"]).lower(), []).append(r["cve_id"])

    pairs = []
    for r in nodes_df.to_dict(orient="records"):
        for software in _split(r.get("installed_software") or "", ";"):
            for cve_id in product_to_cves.get(software.lower(), []):
                pairs.append({"cve_id": cve_id, "node_id": r["node_id"]})
    return pairs


def maps_to_params(cve_df: pd.DataFrame, technique_df: pd.DataFrame) -> list[dict]:
    cwe_to_techniques: dict[str, list[str]] = {}
    for r in technique_df.to_dict(orient="records"):
        for cwe_id in _split(r.get("cwe_ids") or "", ";"):
            cwe_to_techniques.setdefault(cwe_id, []).append(r["technique_id"])

    pairs = []
    for r in cve_df.to_dict(orient="records"):
        cwe_id = r.get("cwe_id")
        if not cwe_id or (isinstance(cwe_id, float) and pd.isna(cwe_id)):
            continue
        for technique_id in cwe_to_techniques.get(cwe_id, []):
            pairs.append({"cve_id": r["cve_id"], "technique_id": technique_id})
    return pairs
