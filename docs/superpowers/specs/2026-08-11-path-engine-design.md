# Path Engine (Agent 4) Design

## Mission

Consume the Neo4j attack graph Agent 3 built (contract 03) and find, score, and
annotate attack paths from CVE-exploitable assets to Crown Jewel assets, then
hand off a queryable result to Agent 5 (Reasoning Agent) via contract 04.

## Scope

- **Path definition:** source = any `:Asset` with an inbound `AFFECTS` edge
  from a `:CVE` (i.e. exploitable via a real vulnerability); target = any
  `:Asset` with `criticality_tier = 'Crown Jewel'`. A path is a route between
  them over the topology edge types (`RUNS`, `CONNECTS_TO`, `MEMBER_OF`,
  `HAS_SESSION`, `CONTROLS`).
- **Out of scope:** internet-facing/entry-point modeling (no such field exists
  in `schemas/data_schema.yaml`), identity-only (User/HAS_SESSION) path
  analysis, and any change to the Agent 3 graph model beyond adding new
  properties/node types additively.
- **Scale:** the synthetic topology is small — 80 `:Asset` nodes, 80 topology
  edges, 16 Crown Jewel targets (checked directly against
  `data/synthetic/nodes_topology.csv`). This rules out combinatorial blowup as
  a real concern and justifies the simplest correct algorithm over a more
  elaborate one.

## Architecture

Same split as Agent 3: pure Cypher-builder functions (unit-testable without a
live DB) plus a thin orchestrator that runs them against a real
`neo4j.GraphDatabase` driver. No new dependencies — path-finding uses Neo4j's
native variable-length path traversal (`allShortestPaths`), not a
Python-side graph library like networkx.

```
src/paths/
  __init__.py
  extract.py    # pure functions: build the allShortestPaths Cypher query,
                # parse driver records into path records (source_cve,
                # start_asset, target_asset, node_ids, hop_count)
  score.py      # score(base_score, epss_score, criticality_tier) -> float;
                # CRITICALITY_WEIGHT = {'Crown Jewel': 4, 'High': 3,
                # 'Medium': 2, 'Low': 1}
  analysis.py   # blast_radius query/parse, choke_point frequency count over
                # an extracted path set
  writeback.py  # MERGE (:AttackPath) nodes; SET blast_radius /
                # choke_point_count on :Asset

scripts/find_paths.py   # orchestrator CLI: connect, extract, score, analyze,
                         # write back, exit non-zero on failure — mirrors
                         # scripts/build_graph.py

contracts/04_paths_to_reasoning.yaml   # handoff to Agent 5
agents/path_engine/prompt.md            # mission doc, same format as
                                         # agents/graph_architect/prompt.md
tests/test_paths_extract.py
tests/test_paths_score.py
tests/test_paths_analysis.py
tests/test_paths_writeback.py
tests/test_find_paths.py
```

## Path extraction

For each `(cve, start_asset)` pair reachable via `AFFECTS`, find the shortest
route(s) to every Crown Jewel asset, hop-capped at 6:

```cypher
MATCH (cve:CVE)-[:AFFECTS]->(start:Asset)
MATCH p = allShortestPaths(
  (start)-[:RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS*0..6]-(target:Asset {criticality_tier: 'Crown Jewel'})
)
RETURN cve, start, target, p
```

`*0..6` covers the case where `start` is itself a Crown Jewel (0-hop path).
Results are capped to the top 50 by score before write-back, so the graph
isn't flooded with low-value paths.

## Scoring

```
score = cve.base_score * cve.epss_score * CRITICALITY_WEIGHT[target.criticality_tier]
```

`CRITICALITY_WEIGHT = {'Crown Jewel': 4, 'High': 3, 'Medium': 2, 'Low': 1}` —
a plain linear scale, chosen over a normalized 0-1 scale for legibility (the
number is easy to sanity-check against its CVSS/EPSS inputs). When a path's
`start` asset has multiple exploitable CVEs, the path's score is the max
across them (worst case drives risk).

## Blast radius & choke points

- **Blast radius:** for each exploitable `start` asset, count of distinct
  `:Asset` nodes reachable from it via topology edges within the same 6-hop
  cap. Written as `blast_radius` (int) on the `:Asset` node.
- **Choke points:** assets that appear as an intermediate hop (not the source
  or target) in more than one of the top-50 extracted paths. A plain
  frequency count over the already-extracted path set — no APOC/betweenness
  centrality, since the local `docker-compose.yml` Neo4j image doesn't have
  the APOC plugin installed. Written as `choke_point_count` (int) on the
  `:Asset` node.

## Write-back model

One node per top-50 path:

```
(:AttackPath {
  path_id: string,       # deterministic, hash(cve_id, node_ids joined) — not
                          # just (cve_id, start, target), since
                          # allShortestPaths can return multiple tied-length
                          # paths between the same start/target and each
                          # distinct hop sequence must get its own node
  score: float,
  hop_count: int,
  source_cve: string,    # cve_id
  source_asset_id: string,
  target_asset_id: string,
  node_ids: list[string],  # ordered hop sequence, resolved against :Asset.node_id
  rank: int,              # 1..50, by score desc
})
```

`node_ids` (an ordered array property) was chosen over modeling each hop as
an explicit `(:AttackPath)-[:HOP {order}]->(:Asset)` relationship — Neo4j
doesn't cleanly represent an ordered chain via relationships without extra
bookkeeping, and a property array is simpler to write and to consume. Agent 5
resolves the array against `:Asset.node_id` when it needs the actual asset
chain. Writes use `MERGE` on `path_id` for idempotency, consistent with
Agent 3's import pattern.

`blast_radius` and `choke_point_count` are written directly as properties on
existing `:Asset` nodes (`SET`, not `MERGE` — the nodes already exist from
Agent 3's import).

## Testing

Same TDD pattern as Agent 3: `extract.py`/`score.py`/`analysis.py`/
`writeback.py` are pure functions (Cypher-string/param builders, or
plain-value scoring math) unit-tested with `unittest.mock.MagicMock()` driver
sessions — asserting on the Cypher text and params passed to
`session.run(...)`, no live DB required. Unlike Agent 3's sandbox, a real
Neo4j instance is already running locally in this environment (verified via
`docker ps`), so `scripts/find_paths.py` can additionally get a real
integration smoke test — contingent on sorting out the current `.env`
credential mismatch (`AuthError` seen when connecting with the checked-in
`.env`), which is a plan task, not a design concern.

## Contract 04 (paths_to_reasoning)

Documents for Agent 5:

- The `:AttackPath` node shape above.
- `blast_radius` / `choke_point_count` as `:Asset` properties.
- `src/paths/`'s public functions as the queryable interface (in addition to
  querying Neo4j directly).
- `consumer_must_validate` checklist: every `:AttackPath.node_ids` entry
  resolves to an existing `:Asset.node_id`; `score` is non-null and traces to
  real `base_score`/`epss_score`/`criticality_tier` values (no fabricated
  numbers); `rank` is a dense 1..N ordering by `score` descending within the
  top-50 set.

## Out of scope for this design

- Entry-point/internet-facing modeling.
- Identity-only (User/HAS_SESSION) path analysis as a separate mode.
- APOC-based betweenness centrality for choke points.
- Real-time/incremental re-scoring (that's Agent 6, Watchdog).
