"""Runs the full Agent 6 (Watchdog) pipeline: apply the synthetic scenario
injector's 3 mutations -> re-extract/re-rank candidate paths (reusing Agent
4's src.paths.extract unmodified) -> diff against the persisted :AttackPath
baseline -> write results back into Neo4j as (:Alert) nodes. Does not
rewrite :AttackPath/:Reasoning -- see
docs/superpowers/specs/2026-08-16-watchdog-design.md, Scope."""
import os
import sys

sys.path.insert(0, ".")

from neo4j import GraphDatabase  # noqa: E402

from src.paths.extract import dedupe_and_rank, extract_candidate_paths  # noqa: E402
from src.watchdog.rescore import diff_paths, read_baseline_paths  # noqa: E402
from src.watchdog.scenario import (  # noqa: E402
    apply_epss_spike,
    apply_kev_disclosure,
    apply_new_topology_edge,
)
from src.watchdog.writeback import clear_previous_alerts, write_alerts  # noqa: E402

TOP_N = 50


def main() -> None:
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]

    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        baseline = read_baseline_paths(session)

        kev = apply_kev_disclosure(session)
        print(f"kev_disclosure({kev['cve_id']}: {kev['before']} -> {kev['after']})")
        epss = apply_epss_spike(session)
        print(f"epss_spike({epss['cve_id']}: {epss['before']} -> {epss['after']})")
        edge = apply_new_topology_edge(session)
        print(f"new_topology_edge({edge['source_asset_id']} -> {edge['target_asset_id']})")

        candidates = extract_candidate_paths(session)
        routes = dedupe_and_rank(candidates, top_n=TOP_N)
        alerts = diff_paths(baseline, routes)

        clear_previous_alerts(session)
        written = write_alerts(session, alerts)
    driver.close()

    by_type: dict[str, int] = {}
    for alert in alerts:
        by_type[alert["alert_type"]] = by_type.get(alert["alert_type"], 0) + 1
    breakdown = ", ".join(f"{count} {alert_type}" for alert_type, count in sorted(by_type.items()))
    print(f"Re-scored {len(routes)} route(s) against {len(baseline)} baseline path(s)")
    print(f"Alerts: {breakdown or 'none'} ({len(alerts)} total) -- wrote {written} Alert node(s)")


if __name__ == "__main__":
    main()
