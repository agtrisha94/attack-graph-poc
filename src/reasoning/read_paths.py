"""Reads AttackPath nodes and their source_cve's MAPS_TO Technique ids from
Neo4j for the Reasoning Agent to ground and explain (see
docs/superpowers/specs/2026-08-11-reasoning-agent-design.md)."""

READ_PATHS_QUERY = """
MATCH (p:AttackPath)
MATCH (c:CVE {cve_id: p.source_cve})
MATCH (target:Asset {node_id: p.target_asset_id})
OPTIONAL MATCH (c)-[:MAPS_TO]->(t:Technique)
RETURN p.path_id AS path_id, p.source_cve AS source_cve,
       p.source_asset_id AS source_asset_id, p.target_asset_id AS target_asset_id,
       p.hop_count AS hop_count, c.base_score AS base_score, c.epss_score AS epss_score,
       target.criticality_tier AS target_criticality_tier,
       collect(DISTINCT t.technique_id) AS technique_ids
""".strip()


def read_attack_paths(session) -> list[dict]:
    return [dict(record) for record in session.run(READ_PATHS_QUERY)]
