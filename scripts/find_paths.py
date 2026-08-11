"""Runs the full Agent 4 (Path Engine) pipeline: extract candidate paths ->
dedupe/rank into routes -> compute blast radius/choke points -> write
results back into Neo4j as (:AttackPath) nodes and :Asset properties."""
import os
import sys

sys.path.insert(0, ".")

from neo4j import GraphDatabase  # noqa: E402

from src.paths.analysis import choke_point_counts, extract_blast_radius  # noqa: E402
from src.paths.extract import dedupe_and_rank, extract_candidate_paths  # noqa: E402
from src.paths.writeback import (  # noqa: E402
    clear_previous_results,
    write_asset_metrics,
    write_attack_paths,
)

TOP_N = 50


def main() -> None:
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]

    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        clear_previous_results(session)
        candidates = extract_candidate_paths(session)
        routes = dedupe_and_rank(candidates, top_n=TOP_N)
        blast_radius = extract_blast_radius(session)
        choke_points = choke_point_counts(routes)
        written = write_attack_paths(session, routes)
        write_asset_metrics(session, blast_radius, choke_points)
    driver.close()

    print(f"Extracted {len(candidates)} candidate paths, deduplicated to {len(routes)} distinct route(s), wrote {written} AttackPath node(s)")
    print(f"Blast radius computed for {len(blast_radius)} asset(s); {len(choke_points)} choke point(s) found")


if __name__ == "__main__":
    main()
