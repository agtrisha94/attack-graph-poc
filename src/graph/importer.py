"""CSV -> Cypher parameter builders and the MERGE statements that load
data/processed/*.csv and data/synthetic/*.csv into Neo4j."""
import pathlib

import pandas as pd

CVE_MASTER = pathlib.Path("data/processed/microsoft_cve_master.csv")
TECHNIQUE_MAP = pathlib.Path("data/processed/technique_map.csv")
NODES = pathlib.Path("data/synthetic/nodes_topology.csv")
EDGES = pathlib.Path("data/synthetic/edges_topology.csv")

# Cypher label/relationship-type names can't be parameterized, so these enums
# are enforced in Python before being interpolated into query strings below.
TOPOLOGY_EDGE_TYPES = ("RUNS", "CONNECTS_TO", "MEMBER_OF", "HAS_SESSION", "CONTROLS")
ASSET_NODE_TYPES = ("User", "Group", "Computer", "Application", "Device")


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


def _merge_nodes(session, label: str, key: str, params: list[dict]) -> int:
    if not params:
        return 0
    var = label[0].lower()
    session.run(
        f"UNWIND $rows AS row MERGE ({var}:{label} {{{key}: row.{key}}}) SET {var} += row",
        rows=params,
    )
    return len(params)


def import_graph(session, processed_dir: pathlib.Path, synthetic_dir: pathlib.Path) -> dict[str, int]:
    cve_df = pd.read_csv(processed_dir / "microsoft_cve_master.csv")
    technique_df = pd.read_csv(processed_dir / "technique_map.csv")
    nodes_df = pd.read_csv(synthetic_dir / "nodes_topology.csv")
    edges_df = pd.read_csv(synthetic_dir / "edges_topology.csv")

    counts = {
        "CVE": _merge_nodes(session, "CVE", "cve_id", cve_params(cve_df)),
        "Technique": _merge_nodes(session, "Technique", "technique_id", technique_params(technique_df)),
        "Asset": _merge_nodes(session, "Asset", "node_id", asset_params(nodes_df)),
    }
    for a in asset_params(nodes_df):
        node_type = a["node_type"]
        if node_type not in ASSET_NODE_TYPES:
            raise ValueError(f"unknown node_type: {node_type!r}")
        session.run(f"MATCH (a:Asset {{node_id: $node_id}}) SET a:{node_type}", node_id=a["node_id"])

    edge_total = 0
    for edge_type, rows in topology_edge_params(edges_df).items():
        if edge_type not in TOPOLOGY_EDGE_TYPES:
            raise ValueError(f"unknown edge_type: {edge_type!r}")
        session.run(
            f"UNWIND $rows AS row "
            f"MATCH (s:Asset {{node_id: row.source_id}}), (t:Asset {{node_id: row.target_id}}) "
            f"MERGE (s)-[r:{edge_type}]->(t) SET r += row.properties",
            rows=rows,
        )
        edge_total += len(rows)
    counts["topology_edges"] = edge_total

    affects = affects_params(cve_df, nodes_df)
    if affects:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (c:CVE {cve_id: row.cve_id}), (a:Asset {node_id: row.node_id}) "
            "MERGE (c)-[:AFFECTS]->(a)",
            rows=affects,
        )
    counts["AFFECTS"] = len(affects)

    maps_to = maps_to_params(cve_df, technique_df)
    if maps_to:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (c:CVE {cve_id: row.cve_id}), (t:Technique {technique_id: row.technique_id}) "
            "MERGE (c)-[:MAPS_TO]->(t)",
            rows=maps_to,
        )
    counts["MAPS_TO"] = len(maps_to)

    return counts
