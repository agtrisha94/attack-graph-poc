"""Persists Watchdog diff results into Neo4j: one (:Alert) node per
detected change (see docs/superpowers/specs/2026-08-16-watchdog-design.md,
Alert node shape and write-back). MERGE-based, idempotent, consistent with
Agents 3-5's import pattern. No relationship to :AttackPath -- a
dropped_from_top50 alert's path may no longer have a node at all."""


def clear_previous_alerts(session) -> None:
    session.run("MATCH (a:Alert) DETACH DELETE a")


def write_alerts(session, alerts: list[dict]) -> int:
    if not alerts:
        return 0
    session.run(
        "UNWIND $rows AS row "
        "MERGE (a:Alert {alert_id: row.alert_id}) "
        "SET a += row",
        rows=alerts,
    )
    return len(alerts)
