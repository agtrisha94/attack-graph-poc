"""Queries Agent 3's Neo4j graph for routes from CVE-exploitable assets to
Crown Jewel assets, then deduplicates by physical route (start, target, hop
sequence) and ranks by score before capping to the top N (see
docs/superpowers/specs/2026-08-11-path-engine-design.md, Path extraction --
the raw query returns far more (cve, start, target) rows than distinct
routes, since one asset can carry many exploitable CVEs)."""
from src.paths.score import score_path

# Lowered from 6: with the generator's segmentation model (workstations only
# reach their group's local servers, not its gateway -- see
# src/generator/topology.py), 6 hops was generous enough that almost every
# CVE-exploitable asset could reach almost the entire 380-asset inventory,
# making blast radius nearly flat instead of tracking actual network
# position. 5 was picked over 4 by checking both against the live graph:
# capping at 4 hops loses coverage (59/100 exploitable assets can no longer
# reach any Crown Jewel at all, vs 38/100 at cap 5), while cap 6 finds the
# same 38/100 as cap 5 -- the 6th hop only inflates blast radius, it doesn't
# reach any additional Crown Jewel. Shared with src/paths/analysis.py's
# BLAST_RADIUS_QUERY so the two can't drift apart.
HOP_CAP = 5

# MEMBER_OF excluded from traversal: every user in a management group points
# to the same :Group node, so an undirected MEMBER_OF hop turns that node
# into a free bridge between any two co-members (user_A -> group <- user_B)
# even though shared group membership isn't itself a lateral-movement
# primitive -- it collapsed blast radius/path reach to "one whole group" from
# almost any starting asset. MEMBER_OF edges still exist in the graph (for
# display/lookup), just aren't attacker-traversable.
PATH_QUERY = f"""
MATCH (cve:CVE)-[:AFFECTS]->(start:Asset)
MATCH p = allShortestPaths(
  (start)-[:RUNS|CONNECTS_TO|HAS_SESSION|CONTROLS*0..{HOP_CAP}]-(target:Asset {{criticality_tier: 'Crown Jewel'}})
)
RETURN cve.cve_id AS cve_id, cve.base_score AS base_score, cve.epss_score AS epss_score,
       cve.kev_flag AS kev_flag, cve.attack_vector AS attack_vector,
       start.node_id AS start_id, start.internet_facing AS start_internet_facing,
       target.node_id AS target_id,
       target.criticality_tier AS target_criticality,
       [n IN nodes(p) | n.node_id] AS node_ids, length(p) AS hop_count
""".strip()


def extract_candidate_paths(session) -> list[dict]:
    return [dict(record) for record in session.run(PATH_QUERY)]


def dedupe_and_rank(candidates: list[dict], top_n: int = 50) -> list[dict]:
    best_by_route: dict[tuple, dict] = {}
    for c in candidates:
        route_key = (c["start_id"], c["target_id"], tuple(c["node_ids"]))
        score = score_path(
            c["base_score"], c["epss_score"], c["target_criticality"],
            kev_flag=c["kev_flag"], hop_count=c["hop_count"],
            internet_facing=c["start_internet_facing"], attack_vector=c["attack_vector"],
        )
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

    ranked = sorted(
        best_by_route.values(),
        key=lambda r: (-r["score"], r["hop_count"], tuple(r["node_ids"])),
    )[:top_n]
    for i, route in enumerate(ranked, start=1):
        route["rank"] = i
    return ranked
