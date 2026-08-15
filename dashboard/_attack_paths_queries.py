"""Cypher queries for the Attack Paths page: every AttackPath left-joined
with its CVE/source-asset/target-asset facts and (if resolved) its
Reasoning explanation, plus per-hop topology edge-type resolution for
rendering a selected path as a chain -- see
docs/superpowers/plans/since-assets-are-synthetic-lexical-gizmo.md, Part 2,
Page 2."""

READ_ATTACK_PATHS_WITH_REASONING_QUERY = """
MATCH (p:AttackPath)
MATCH (c:CVE {cve_id: p.source_cve})
MATCH (source:Asset {node_id: p.source_asset_id})
MATCH (target:Asset {node_id: p.target_asset_id})
OPTIONAL MATCH (p)-[:EXPLAINED_BY]->(r:Reasoning)
RETURN p.path_id AS path_id, p.rank AS rank, p.score AS pipeline_score,
       p.source_cve AS source_cve,
       p.source_asset_id AS source_asset_id, p.target_asset_id AS target_asset_id,
       p.node_ids AS node_ids, p.hop_count AS hop_count,
       c.base_score AS base_score, c.epss_score AS epss_score,
       source.criticality_tier AS source_criticality_tier,
       target.criticality_tier AS target_criticality_tier,
       r.explanation AS explanation, r.technique_ids AS technique_ids,
       r.threat_actors AS threat_actors, r.mitigations AS mitigations
ORDER BY p.rank
""".strip()

# Resolves the topology relationship type between each consecutive pair in a
# path's node_ids, batched into one query rather than one round-trip per hop.
PATH_CHAIN_EDGE_TYPES_QUERY = """
UNWIND range(0, size($node_ids) - 2) AS i
MATCH (a:Asset {node_id: $node_ids[i]})-[r:RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS]-(b:Asset {node_id: $node_ids[i + 1]})
RETURN i, type(r) AS rel_type
""".strip()

# Mirrors src/paths/score.py's CRITICALITY_WEIGHT -- duplicated rather than
# imported because dashboard pages run under Streamlit's own sys.path
# (only dashboard/ is added, not the repo root), so `from src...` doesn't
# resolve there; every other dashboard query module is self-contained the
# same way, so this keeps the same convention rather than fighting it.
SOURCE_TIER_WEIGHT_DEFAULTS = {"Crown Jewel": 4, "High": 3, "Medium": 2, "Low": 1}


def read_attack_paths_with_reasoning(session) -> list[dict]:
    return [dict(record) for record in session.run(READ_ATTACK_PATHS_WITH_REASONING_QUERY)]


def read_path_chain_edge_types(session, node_ids: list[str]) -> dict[int, str]:
    if len(node_ids) < 2:
        return {}
    rows = session.run(PATH_CHAIN_EDGE_TYPES_QUERY, node_ids=node_ids)
    return {record["i"]: record["rel_type"] for record in rows}
