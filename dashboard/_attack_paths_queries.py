"""Cypher query for the Attack Paths page: every AttackPath left-joined
with its CVE/target-asset facts and (if resolved) its Reasoning
explanation -- see docs/superpowers/specs/2026-08-11-dashboard-design.md,
Page 2: Attack Paths."""

READ_ATTACK_PATHS_WITH_REASONING_QUERY = """
MATCH (p:AttackPath)
MATCH (c:CVE {cve_id: p.source_cve})
MATCH (target:Asset {node_id: p.target_asset_id})
OPTIONAL MATCH (p)-[:EXPLAINED_BY]->(r:Reasoning)
RETURN p.path_id AS path_id, p.rank AS rank, p.source_cve AS source_cve,
       p.source_asset_id AS source_asset_id, p.target_asset_id AS target_asset_id,
       p.hop_count AS hop_count, c.base_score AS base_score, c.epss_score AS epss_score,
       target.criticality_tier AS target_criticality_tier,
       r.explanation AS explanation, r.technique_ids AS technique_ids,
       r.threat_actors AS threat_actors, r.mitigations AS mitigations
ORDER BY p.rank
""".strip()


def read_attack_paths_with_reasoning(session) -> list[dict]:
    return [dict(record) for record in session.run(READ_ATTACK_PATHS_WITH_REASONING_QUERY)]
