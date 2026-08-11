"""Persists Reasoning Agent results into Neo4j: one (:Reasoning) node per
AttackPath, linked via :EXPLAINED_BY (see
docs/superpowers/specs/2026-08-11-reasoning-agent-design.md, Write-back
model). MERGE-based, idempotent, consistent with Agents 3-4's import
pattern."""


def clear_previous_results(session) -> None:
    session.run("MATCH (r:Reasoning) DETACH DELETE r")


def write_reasoning(session, rows: list[dict]) -> int:
    if not rows:
        return 0
    session.run(
        "UNWIND $rows AS row "
        "MATCH (p:AttackPath {path_id: row.path_id}) "
        "MERGE (r:Reasoning {path_id: row.path_id}) "
        "SET r += row "
        "MERGE (p)-[:EXPLAINED_BY]->(r)",
        rows=rows,
    )
    return len(rows)
