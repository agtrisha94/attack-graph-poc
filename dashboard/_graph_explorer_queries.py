"""Cypher queries for the Graph Explorer page: the 80-asset topology
network plus per-asset CVE/technique drill-down -- see
docs/superpowers/specs/2026-08-11-dashboard-design.md, Page 3: Graph
Explorer. Scoped to :Asset nodes only, not the full CVE/Technique graph."""

ASSET_NETWORK_NODES_QUERY = """
MATCH (a:Asset)
RETURN a.node_id AS node_id, a.display_name AS display_name, a.node_type AS node_type,
       a.criticality_tier AS criticality_tier, a.blast_radius AS blast_radius,
       a.choke_point_count AS choke_point_count
""".strip()

ASSET_NETWORK_EDGES_QUERY = """
MATCH (s:Asset)-[r:RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS]->(t:Asset)
RETURN s.node_id AS source_id, t.node_id AS target_id, type(r) AS rel_type
""".strip()

ASSET_DETAIL_QUERY = """
MATCH (c:CVE)-[:AFFECTS]->(a:Asset {node_id: $node_id})
OPTIONAL MATCH (c)-[:MAPS_TO]->(t:Technique)
RETURN c.cve_id AS cve_id, c.base_score AS base_score, c.epss_score AS epss_score,
       collect(DISTINCT t.technique_id) AS technique_ids
ORDER BY c.base_score DESC
""".strip()


def read_asset_network(session) -> dict:
    nodes = [dict(record) for record in session.run(ASSET_NETWORK_NODES_QUERY)]
    edges = [dict(record) for record in session.run(ASSET_NETWORK_EDGES_QUERY)]
    return {"nodes": nodes, "edges": edges}


def read_asset_detail(session, node_id: str) -> list[dict]:
    return [dict(record) for record in session.run(ASSET_DETAIL_QUERY, node_id=node_id)]
