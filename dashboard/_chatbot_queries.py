"""Graph-fact lookups for the chatbot page. Filters/selects in Python rather
than writing a parameterized Cypher query -- the ranked-path set is small
(top 50), so fetching everything and filtering is the lazy option, not a
performance shortcut. The read query is a trimmed duplicate of
_attack_paths_queries.READ_ATTACK_PATHS_WITH_REASONING_QUERY rather than a
cross-module import: dashboard pages run under Streamlit's own sys.path
(only dashboard/ is added, not the repo root), so query modules don't
import each other -- see _attack_paths_queries.py's own comment on the same
convention. CVE/technique-ID extraction is a simple regex heuristic (exact
source-CVE match, technique-ID overlap); good enough to demo grounding, not
full entity resolution."""
import re

# CVE join + score components (pipeline_score, base_score, epss_score,
# kev_flag, attack_vector, source_internet_facing, hop_count, node_ids)
# mirror _attack_paths_queries.READ_ATTACK_PATHS_WITH_REASONING_QUERY's
# joins -- same data, now also exposed to the chatbot so "why is this path
# risky" has real numbers instead of just the free-text explanation.
READ_ATTACK_PATHS_FOR_CHAT_QUERY = """
MATCH (p:AttackPath)
MATCH (c:CVE {cve_id: p.source_cve})
MATCH (source:Asset {node_id: p.source_asset_id})
MATCH (target:Asset {node_id: p.target_asset_id})
OPTIONAL MATCH (p)-[:EXPLAINED_BY]->(r:Reasoning)
RETURN p.path_id AS path_id, p.rank AS rank, p.score AS pipeline_score,
       p.source_cve AS source_cve, p.source_asset_id AS source_asset_id,
       p.target_asset_id AS target_asset_id, p.node_ids AS node_ids,
       p.hop_count AS hop_count, c.base_score AS base_score,
       c.epss_score AS epss_score, c.kev_flag AS kev_flag,
       c.attack_vector AS attack_vector,
       source.internet_facing AS source_internet_facing,
       target.criticality_tier AS target_criticality_tier,
       r.explanation AS explanation, r.technique_ids AS technique_ids
ORDER BY p.rank
""".strip()

# Trimmed duplicate of _attack_paths_queries.PATH_CHAIN_EDGE_TYPES_QUERY --
# same no-cross-import convention as the rest of this module.
PATH_CHAIN_EDGE_TYPES_QUERY = """
UNWIND range(0, size($node_ids) - 2) AS i
MATCH (a:Asset {node_id: $node_ids[i]})-[r:RUNS|CONNECTS_TO|HAS_SESSION|CONTROLS]-(b:Asset {node_id: $node_ids[i + 1]})
RETURN i, type(r) AS rel_type
""".strip()

# All assets with their precomputed risk metrics (see _risk_analysis_queries.py's
# BLAST_RADIUS_QUERY/CHOKE_POINT_QUERY, which read the same properties but
# filter to non-null only, for the Risk Analysis page's ranked charts). Here
# we want every asset, including nulls, so a plain-text mention of any asset
# can be matched regardless of whether it has risk data.
ALL_ASSETS_QUERY = """
MATCH (a:Asset)
RETURN a.node_id AS asset_id, a.display_name AS display_name,
       a.choke_point_count AS choke_point_count, a.blast_radius AS blast_radius
""".strip()

# Trimmed duplicate of _risk_analysis_queries.PATHS_THROUGH_ASSET_QUERY --
# same no-cross-import convention as READ_ATTACK_PATHS_FOR_CHAT_QUERY above.
# Returns the same fields as the Risk Analysis page's version (not just
# path_id) so the chatbot can explain *why* an asset is a choke point with
# concrete path details, not just a bare count.
PATHS_THROUGH_ASSET_QUERY = """
MATCH (p:AttackPath)
WHERE $asset_id IN p.node_ids[1..-1]
RETURN p.path_id AS path_id, p.rank AS rank, p.source_cve AS source_cve,
       p.source_asset_id AS source_asset_id, p.target_asset_id AS target_asset_id
ORDER BY p.rank
""".strip()

CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
TECHNIQUE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def read_attack_paths_for_chat(session) -> list[dict]:
    return [dict(record) for record in session.run(READ_ATTACK_PATHS_FOR_CHAT_QUERY)]


def read_all_assets(session) -> list[dict]:
    return [dict(record) for record in session.run(ALL_ASSETS_QUERY)]


def read_paths_through_asset(session, asset_id: str) -> list[dict]:
    return [dict(record) for record in session.run(PATHS_THROUGH_ASSET_QUERY, asset_id=asset_id)]


def read_path_chain_edge_types(session, node_ids: list[str]) -> dict[int, str]:
    if len(node_ids) < 2:
        return {}
    rows = session.run(PATH_CHAIN_EDGE_TYPES_QUERY, node_ids=node_ids)
    return {record["i"]: record["rel_type"] for record in rows}


def extract_cve_ids(text: str) -> list[str]:
    return sorted({m.upper() for m in CVE_ID_PATTERN.findall(text)})


def extract_technique_ids(text: str) -> list[str]:
    return sorted({m.upper() for m in TECHNIQUE_ID_PATTERN.findall(text)})


def relevant_paths_for_question(session, question: str, top_n: int = 3) -> list[dict]:
    """Paths whose source CVE or resolved technique_ids are named in the
    question; falls back to the top-N ranked paths if nothing matches."""
    paths = read_attack_paths_for_chat(session)
    cve_ids = extract_cve_ids(question)
    technique_ids = extract_technique_ids(question)

    if cve_ids or technique_ids:
        matched = [
            p for p in paths
            if p["source_cve"] in cve_ids
            or set(p.get("technique_ids") or []) & set(technique_ids)
        ]
        if matched:
            return matched

    return paths[:top_n]


def relevant_assets_for_question(session, question: str) -> list[dict]:
    """Assets whose ID or display name is named in the question (case-
    insensitive substring match -- 380 assets, so brute-force is fine, same
    reasoning as relevant_paths_for_question above), enriched with their
    choke-point/blast-radius risk metrics and which ranked paths they sit
    on as an interior hop."""
    lowered = question.lower()
    matched = [
        a for a in read_all_assets(session)
        if (a["asset_id"] and a["asset_id"].lower() in lowered)
        or (a["display_name"] and a["display_name"].lower() in lowered)
    ]
    for asset in matched:
        asset["through_paths"] = read_paths_through_asset(session, asset["asset_id"])
    return matched
