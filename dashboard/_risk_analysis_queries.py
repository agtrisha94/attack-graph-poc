"""Cypher queries for the Risk Analysis page: choke-point ranking + drill-
down (depends on stage 4's :AttackPath output, so empty until find_paths.py
runs) and blast-radius ranking + reachable-subgraph drill-down (computed
live from CVE/AFFECTS/topology data, independent of stage 4) -- see
docs/superpowers/plans/since-assets-are-synthetic-lexical-gizmo.md, Part 2,
Page 3."""

# Mirrors src/paths/analysis.py's BLAST_RADIUS_QUERY -- duplicated rather
# than imported for the same reason as _attack_paths_queries.py's
# SOURCE_TIER_WEIGHT_DEFAULTS: dashboard pages run under Streamlit's own
# sys.path (only dashboard/ is added, not the repo root), so `from src...`
# doesn't resolve there, and every other dashboard query module is
# self-contained the same way.
BLAST_RADIUS_QUERY = """
MATCH (cve:CVE)-[:AFFECTS]->(start:Asset)
WITH DISTINCT start
MATCH (start)-[:RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS*0..6]-(reachable:Asset)
WHERE reachable <> start
RETURN start.node_id AS asset_id, start.display_name AS display_name,
       count(DISTINCT reachable) AS blast_radius
ORDER BY blast_radius DESC
""".strip()

# Mirrors src/paths/analysis.py's choke_point_counts()' node_ids[1:-1]
# (interior-hop) definition -- an asset counts as a choke point on a route
# only if it's neither that route's start nor its end.
CHOKE_POINT_QUERY = """
MATCH (a:Asset)
WHERE a.choke_point_count IS NOT NULL
RETURN a.node_id AS asset_id, a.display_name AS display_name,
       a.choke_point_count AS choke_point_count
ORDER BY choke_point_count DESC
""".strip()

PATHS_THROUGH_ASSET_QUERY = """
MATCH (p:AttackPath)
WHERE $asset_id IN p.node_ids[1..-1]
RETURN p.path_id AS path_id, p.rank AS rank, p.source_cve AS source_cve,
       p.source_asset_id AS source_asset_id, p.target_asset_id AS target_asset_id
ORDER BY p.rank
""".strip()

# shortestPath with a broadly-matched (not individually bound) second
# endpoint finds the shortest path to every reachable :Asset in one query --
# the same "one bound, one broad" pattern src/paths/extract.py's PATH_QUERY
# already uses with allShortestPaths. hop_distance drives the radial
# blast-radius layout in the Risk Analysis page (nearer rings = fewer hops).
REACHABLE_ASSETS_QUERY = """
MATCH (start:Asset {node_id: $asset_id})
MATCH p = shortestPath((start)-[:RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS*0..6]-(reachable:Asset))
WHERE reachable <> start
RETURN reachable.node_id AS node_id, reachable.display_name AS display_name,
       reachable.node_type AS node_type, reachable.criticality_tier AS criticality_tier,
       length(p) AS hop_distance
""".strip()

# s.node_id < t.node_id keeps each undirected edge to a single row -- an
# unconstrained `-[r]-` match returns the same relationship once per
# traversal direction, which would otherwise double every edge in the
# rendered mini-graph.
REACHABLE_EDGES_QUERY = """
MATCH (start:Asset {node_id: $asset_id})
MATCH (start)-[:RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS*0..6]-(reachable:Asset)
WHERE reachable <> start
WITH start, collect(DISTINCT reachable.node_id) AS reachable_ids
WITH reachable_ids + [start.node_id] AS subgraph_ids
MATCH (s:Asset)-[r:RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS]-(t:Asset)
WHERE s.node_id IN subgraph_ids AND t.node_id IN subgraph_ids AND s.node_id < t.node_id
RETURN s.node_id AS source_id, t.node_id AS target_id, type(r) AS rel_type
""".strip()


def read_blast_radius(session) -> list[dict]:
    return [dict(record) for record in session.run(BLAST_RADIUS_QUERY)]


def read_choke_points(session) -> list[dict]:
    return [dict(record) for record in session.run(CHOKE_POINT_QUERY)]


def read_paths_through_asset(session, asset_id: str) -> list[dict]:
    return [dict(record) for record in session.run(PATHS_THROUGH_ASSET_QUERY, asset_id=asset_id)]


def read_reachable_subgraph(session, asset_id: str) -> dict:
    nodes = [dict(record) for record in session.run(REACHABLE_ASSETS_QUERY, asset_id=asset_id)]
    edges = [dict(record) for record in session.run(REACHABLE_EDGES_QUERY, asset_id=asset_id)]
    return {"nodes": nodes, "edges": edges}
