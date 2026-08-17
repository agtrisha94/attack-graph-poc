"""Runs the full Agent 3 (Graph Architect) pipeline: apply schema -> import
CSVs -> validate the loaded graph. Exits non-zero if validation fails."""
import os
import pathlib
import sys

sys.path.insert(0, ".")

from neo4j import GraphDatabase  # noqa: E402

from src.graph.importer import import_graph  # noqa: E402
from src.graph.schema import apply_schema  # noqa: E402
from src.graph.validate import validate_graph  # noqa: E402

PROCESSED_DIR = pathlib.Path("data/processed")
SYNTHETIC_DIR = pathlib.Path("data/synthetic")


def main() -> None:
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USERNAME") or os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]

    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        apply_schema(session)
        counts = import_graph(session, PROCESSED_DIR, SYNTHETIC_DIR)
        print(f"Imported: {counts}")
        violations = validate_graph(session, PROCESSED_DIR, SYNTHETIC_DIR)
    driver.close()

    if violations:
        print(f"FAILED: {len(violations)} violation(s)")
        for v in violations:
            print(f"  - {v}")
        raise SystemExit(1)
    print("PASSED: graph import satisfies contract 02/03")


if __name__ == "__main__":
    main()
