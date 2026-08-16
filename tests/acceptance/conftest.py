"""Live Neo4j connection fixture for tests/acceptance/. Connects using the
same NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD pattern as every scripts/*.py (see
src/graph/validate.py:main()) -- fails loudly if the DB isn't reachable,
since these tests exist to prove the real data holds up."""
import os

import pytest
from neo4j import GraphDatabase


@pytest.fixture(scope="module")
def neo4j_session():
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    try:
        password = os.environ["NEO4J_PASSWORD"]
    except KeyError:
        pytest.fail(
            "NEO4J_PASSWORD is not set. Run `set -a && source .env && set +a` "
            "(see README.md) before running the acceptance suite."
        )

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        driver.verify_connectivity()
    except Exception as exc:
        pytest.fail(
            f"Could not connect to Neo4j at {uri}: {exc}. "
            "Run `docker compose up -d` first (see README.md)."
        )

    with driver.session() as session:
        yield session
    driver.close()
