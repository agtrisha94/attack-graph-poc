"""Queries Agent 3's Neo4j graph for routes from CVE-exploitable assets to
Crown Jewel assets, then deduplicates by physical route (start, target, hop
sequence) and ranks by score before capping to the top N (see
docs/superpowers/specs/2026-08-11-path-engine-design.md, Path extraction --
the raw query returns far more (cve, start, target) rows than distinct
routes, since one asset can carry many exploitable CVEs)."""
from src.paths.score import score_path

PATH_QUERY = """
MATCH (cve:CVE)-[:AFFECTS]->(start:Asset)
MATCH p = allShortestPaths(
  (start)-[:RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS*0..6]-(target:Asset {criticality_tier: 'Crown Jewel'})
)
RETURN cve.cve_id AS cve_id, cve.base_score AS base_score, cve.epss_score AS epss_score,
       start.node_id AS start_id, target.node_id AS target_id,
       target.criticality_tier AS target_criticality,
       [n IN nodes(p) | n.node_id] AS node_ids, length(p) AS hop_count
""".strip()


def extract_candidate_paths(session) -> list[dict]:
    return [dict(record) for record in session.run(PATH_QUERY)]


def dedupe_and_rank(candidates: list[dict], top_n: int = 50) -> list[dict]:
    best_by_route: dict[tuple, dict] = {}
    for c in candidates:
        route_key = (c["start_id"], c["target_id"], tuple(c["node_ids"]))
        score = score_path(c["base_score"], c["epss_score"], c["target_criticality"])
        existing = best_by_route.get(route_key)
        if existing is None or score > existing["score"]:
            best_by_route[route_key] = {
                "score": score,
                "hop_count": c["hop_count"],
                "source_cve": c["cve_id"],
                "source_asset_id": c["start_id"],
                "target_asset_id": c["target_id"],
                "node_ids": c["node_ids"],
            }

    ranked = sorted(best_by_route.values(), key=lambda r: r["score"], reverse=True)[:top_n]
    for i, route in enumerate(ranked, start=1):
        route["rank"] = i
    return ranked
