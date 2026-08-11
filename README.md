## Running the graph import (Agent 3)

1. `pip install -r requirements.txt`
2. `docker compose up -d` (requires Docker; starts Neo4j on bolt://localhost:7687)
3. `cp .env.example .env` and fill in a real `NEO4J_PASSWORD` (8+ chars)
4. Load the env vars into your shell: `set -a && source .env && set +a` (bash/zsh)
5. `python3 scripts/build_graph.py`

Note: `requirements.txt` pins `neo4j==5.28.4` to match `docker-compose.yml`'s
`neo4j:5-community` image — the `neo4j` driver's 6.x line speaks a newer Bolt
protocol version that this server doesn't support, and the failure mode is a
misleading `AuthError` rather than a clear version-mismatch error.

If ports 7474/7687 are already in use on your machine (e.g. a native Neo4j
install), add a git-ignored `docker-compose.override.yml` remapping them
(e.g. to 17474/17687) and point `NEO4J_URI` in `.env` at the same port.
