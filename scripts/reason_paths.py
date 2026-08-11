"""Runs the full Agent 5 (Reasoning Agent) pipeline: read AttackPaths ->
resolve MITRE-grounded threat-actor/mitigation facts -> build a deterministic
explanation -> write results back into Neo4j as (:Reasoning) nodes linked
via :EXPLAINED_BY."""
import os
import sys

sys.path.insert(0, ".")

from neo4j import GraphDatabase  # noqa: E402

from src.reasoning.explain import build_explanation  # noqa: E402
from src.reasoning.mitre_lookup import (  # noqa: E402
    build_technique_facts,
    resolve_facts_for_techniques,
)
from src.reasoning.read_paths import read_attack_paths  # noqa: E402
from src.reasoning.writeback import clear_previous_results, write_reasoning  # noqa: E402


def main() -> None:
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]

    technique_facts = build_technique_facts()

    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        clear_previous_results(session)
        paths = read_attack_paths(session)

        rows = []
        for path in paths:
            resolved = resolve_facts_for_techniques(path["technique_ids"], technique_facts)
            rows.append({
                "path_id": path["path_id"],
                "explanation": build_explanation(path, resolved),
                "technique_ids": path["technique_ids"],
                "threat_actors": resolved["threat_actors"],
                "mitigations": resolved["mitigations"],
            })

        written = write_reasoning(session, rows)
    driver.close()

    print(f"Read {len(paths)} AttackPath node(s), wrote {written} Reasoning node(s)")


if __name__ == "__main__":
    main()
