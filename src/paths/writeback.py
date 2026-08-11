"""Persists Path Engine results into Neo4j: one (:AttackPath) node per
ranked route, plus blast_radius/choke_point_count properties on :Asset (see
docs/superpowers/specs/2026-08-11-path-engine-design.md, Write-back model).
All writes use MERGE/SET on existing keys -- idempotent, consistent with
Agent 3's import pattern (src/graph/importer.py)."""
import hashlib


def path_id_for(node_ids: list[str]) -> str:
    return hashlib.sha256("|".join(node_ids).encode()).hexdigest()[:16]


def write_attack_paths(session, routes: list[dict]) -> int:
    if not routes:
        return 0
    rows = [{**route, "path_id": path_id_for(route["node_ids"])} for route in routes]
    session.run(
        "UNWIND $rows AS row "
        "MERGE (p:AttackPath {path_id: row.path_id}) "
        "SET p += row",
        rows=rows,
    )
    return len(rows)


def write_asset_metrics(session, blast_radius: dict[str, int], choke_points: dict[str, int]) -> None:
    if blast_radius:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (a:Asset {node_id: row.node_id}) "
            "SET a.blast_radius = row.blast_radius",
            rows=[{"node_id": k, "blast_radius": v} for k, v in blast_radius.items()],
        )
    if choke_points:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (a:Asset {node_id: row.node_id}) "
            "SET a.choke_point_count = row.choke_point_count",
            rows=[{"node_id": k, "choke_point_count": v} for k, v in choke_points.items()],
        )
