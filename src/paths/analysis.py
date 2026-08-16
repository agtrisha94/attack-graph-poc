"""Per-asset blast radius (reachable-asset count) and choke-point frequency
(how many top-N routes an asset sits on as an intermediate hop) -- see
docs/superpowers/specs/2026-08-11-path-engine-design.md, Blast radius &
choke points. No APOC: the local Neo4j Community image doesn't have it
installed, so choke points are a plain frequency count, not betweenness
centrality."""

from src.paths.extract import HOP_CAP

BLAST_RADIUS_QUERY = f"""
MATCH (cve:CVE)-[:AFFECTS]->(start:Asset)
WITH DISTINCT start
MATCH (start)-[:RUNS|CONNECTS_TO|HAS_SESSION|CONTROLS*0..{HOP_CAP}]-(reachable:Asset)
WHERE reachable <> start
RETURN start.node_id AS asset_id, count(DISTINCT reachable) AS blast_radius
""".strip()


def extract_blast_radius(session) -> dict[str, int]:
    return {r["asset_id"]: r["blast_radius"] for r in session.run(BLAST_RADIUS_QUERY)}


def choke_point_counts(routes: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for route in routes:
        intermediate = set(route["node_ids"][1:-1])
        for asset_id in intermediate:
            counts[asset_id] = counts.get(asset_id, 0) + 1
    return {asset_id: count for asset_id, count in counts.items() if count > 1}
