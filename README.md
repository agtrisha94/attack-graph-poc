## Running the graph import (Agent 3)

1. `pip install -r requirements.txt`
2. `docker compose up -d` (requires Docker; starts Neo4j on bolt://localhost:7687)
3. `cp .env.example .env` and fill in a real `NEO4J_PASSWORD` (8+ chars)
4. Load the env vars into your shell: `set -a && source .env && set +a` (bash/zsh)
5. `python3 scripts/build_graph.py`
