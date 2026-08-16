# Demo Walkthrough

Runs the full 7-agent pipeline end to end and shows where to look at each
step. Assumes Docker is installed.

## 1. Setup

```bash
pip install -r requirements.txt
cp .env.example .env          # then fill in a real NEO4J_PASSWORD (8+ chars)
set -a && source .env && set +a
docker compose up -d          # starts Neo4j on bolt://localhost:7687
```

## 2. Build and import the graph (Agents 2-3)

```bash
python3 scripts/build_dataset.py   # writes data/processed/*.csv, data/synthetic/*.csv
python3 scripts/build_graph.py     # imports into Neo4j, runs src/graph/validate.py
```

Check: open Neo4j Browser at http://localhost:7474 and run
`MATCH (c:CVE) RETURN count(c)` -- should return the same row count as
`data/processed/microsoft_cve_master.csv`.

## 3. Extract and score attack paths (Agent 4)

```bash
python3 scripts/find_paths.py
```

Check: `MATCH (p:AttackPath) RETURN count(p)` in Neo4j Browser should return
50. `MATCH (p:AttackPath) RETURN p ORDER BY p.rank LIMIT 1` shows the
highest-scoring path.

## 4. Generate grounded explanations (Agent 5)

```bash
python3 scripts/reason_paths.py
```

Check: `MATCH (p:AttackPath)-[:EXPLAINED_BY]->(r:Reasoning) RETURN p.path_id, r.explanation LIMIT 1`.

## 5. Simulate a change and watch it alert (Agent 6)

```bash
python3 scripts/watch_paths.py
```

Check: the script prints each scenario mutation's before/after value and an
alert-type breakdown. `MATCH (a:Alert) RETURN a.alert_type, count(*)` in
Neo4j Browser should show all three alert types.

## 6. Verify the whole pipeline (Agent 7)

```bash
python3 -m pytest tests/acceptance/test_contracts.py -v
```

Every contract's `consumer_must_validate` checklist is checked against the
live data you just built. All 6 contracts, verified across 5 test functions,
should pass.

## 7. Explore visually

```bash
streamlit run dashboard/app.py
```

Opens the dashboard: Graph Explorer (the attack-relevant subgraph, default
landing page), Attack Paths, Risk Analysis, and Data Sources pages -- browse
the same top-50 paths you just verified.
