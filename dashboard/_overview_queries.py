"""Cypher queries for the Overview page's risk-focused stat tiles -- pure
functions over a Neo4j session, no Streamlit dependency (see
docs/superpowers/specs/2026-08-11-dashboard-design.md, Page 1: Overview)."""

COUNT_ATTACK_PATHS_QUERY = "MATCH (p:AttackPath) RETURN count(p) AS n"

COUNT_CROWN_JEWEL_TARGETS_QUERY = """
MATCH (p:AttackPath)
MATCH (a:Asset {node_id: p.target_asset_id})
WHERE a.criticality_tier = "Crown Jewel"
RETURN count(DISTINCT a.node_id) AS n
""".strip()

TOP_CHOKE_POINTS_QUERY = """
MATCH (a:Asset)
WHERE a.choke_point_count IS NOT NULL
RETURN a.node_id AS node_id, a.display_name AS display_name, a.choke_point_count AS choke_point_count
ORDER BY a.choke_point_count DESC
LIMIT $limit
""".strip()

TOP_BLAST_RADIUS_QUERY = """
MATCH (a:Asset)
WHERE a.blast_radius IS NOT NULL
RETURN a.node_id AS node_id, a.display_name AS display_name, a.blast_radius AS blast_radius
ORDER BY a.blast_radius DESC
LIMIT $limit
""".strip()

PATH_COUNTS_BY_CRITICALITY_QUERY = """
MATCH (p:AttackPath)
MATCH (a:Asset {node_id: p.target_asset_id})
RETURN a.criticality_tier AS tier, count(p) AS count
ORDER BY count DESC
""".strip()


def count_attack_paths(session) -> int:
    return session.run(COUNT_ATTACK_PATHS_QUERY).single()["n"]


def count_crown_jewel_targets(session) -> int:
    return session.run(COUNT_CROWN_JEWEL_TARGETS_QUERY).single()["n"]


def top_choke_points(session, limit: int = 5) -> list[dict]:
    return [dict(record) for record in session.run(TOP_CHOKE_POINTS_QUERY, limit=limit)]


def top_blast_radius(session, limit: int = 5) -> list[dict]:
    return [dict(record) for record in session.run(TOP_BLAST_RADIUS_QUERY, limit=limit)]


def path_counts_by_criticality(session) -> list[dict]:
    return [dict(record) for record in session.run(PATH_COUNTS_BY_CRITICALITY_QUERY)]
