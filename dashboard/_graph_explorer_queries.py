"""Cypher queries for the Graph Explorer page's attack-relevant subgraph --
all :Asset nodes, plus only the :CVE nodes that actually exploit one of them
(via AFFECTS) and the :Technique nodes those CVEs map to (via MAPS_TO). The
literal full graph (26k+ CVE nodes, most unrelated to this environment) is
not renderable by a force-directed graph widget, so this is the node/edge
population that actually matters to the attack surface -- see
docs/superpowers/plans/since-assets-are-synthetic-lexical-gizmo.md,
Part 2, Scale finding that shapes Page 1."""

ASSET_NODES_QUERY = """
MATCH (a:Asset)
RETURN a.node_id AS node_id, a.display_name AS display_name, a.node_type AS node_type,
       a.criticality_tier AS criticality_tier, a.blast_radius AS blast_radius,
       a.choke_point_count AS choke_point_count
""".strip()

CVE_NODES_QUERY = """
MATCH (c:CVE)-[:AFFECTS]->(:Asset)
RETURN DISTINCT c.cve_id AS cve_id, c.vendor AS vendor, c.product AS product,
       c.base_score AS base_score, c.epss_score AS epss_score,
       c.base_severity AS base_severity, c.kev_flag AS kev_flag
""".strip()

TECHNIQUE_NODES_QUERY = """
MATCH (c:CVE)-[:AFFECTS]->(:Asset)
MATCH (c)-[:MAPS_TO]->(t:Technique)
RETURN DISTINCT t.technique_id AS technique_id, t.technique_name AS technique_name,
       t.tactic AS tactic
""".strip()

TOPOLOGY_EDGES_QUERY = """
MATCH (s:Asset)-[r:RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS]->(t:Asset)
RETURN s.node_id AS source_id, t.node_id AS target_id, type(r) AS rel_type
""".strip()

AFFECTS_EDGES_QUERY = """
MATCH (c:CVE)-[:AFFECTS]->(a:Asset)
RETURN c.cve_id AS source_id, a.node_id AS target_id, 'AFFECTS' AS rel_type
""".strip()

MAPS_TO_EDGES_QUERY = """
MATCH (c:CVE)-[:AFFECTS]->(:Asset)
MATCH (c)-[:MAPS_TO]->(t:Technique)
RETURN DISTINCT c.cve_id AS source_id, t.technique_id AS target_id, 'MAPS_TO' AS rel_type
""".strip()


def read_attack_relevant_subgraph(session) -> dict:
    return {
        "assets": [dict(record) for record in session.run(ASSET_NODES_QUERY)],
        "cves": [dict(record) for record in session.run(CVE_NODES_QUERY)],
        "techniques": [dict(record) for record in session.run(TECHNIQUE_NODES_QUERY)],
        "topology_edges": [dict(record) for record in session.run(TOPOLOGY_EDGES_QUERY)],
        "affects_edges": [dict(record) for record in session.run(AFFECTS_EDGES_QUERY)],
        "maps_to_edges": [dict(record) for record in session.run(MAPS_TO_EDGES_QUERY)],
    }
