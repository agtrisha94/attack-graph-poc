# Agent: Path Engine

## Mission

Query the Neo4j attack graph Agent 3 built for routes from CVE-exploitable
assets to Crown Jewel assets, deduplicate and score each route (CVSS x EPSS
x criticality), compute blast radius and choke points per asset, and write
the results back into the graph for the Reasoning Agent to consume.

## Inputs

- The Neo4j graph loaded by `scripts/build_graph.py` (per
  `contracts/03_graph_to_paths.yaml`): `:CVE`, `:Technique`, `:Asset` nodes;
  `AFFECTS`/`MAPS_TO`/topology relationships.

## Outputs

- `src/paths/score.py`, `src/paths/extract.py`, `src/paths/analysis.py`,
  `src/paths/writeback.py`, `scripts/find_paths.py`.
- `(:AttackPath)` nodes and `blast_radius`/`choke_point_count` `:Asset`
  properties written into the graph.
- `contracts/04_paths_to_reasoning.yaml` -- formal handoff to the Reasoning
  Agent.

## Constraints

- No new dependencies -- path-finding uses Neo4j's native
  `allShortestPaths`, not a Python-side graph library; no APOC.
- Routes are deduplicated by physical hop sequence (`start`/`target`/
  `node_ids`) before ranking, keeping the highest-scoring CVE as
  `source_cve` -- a single highly-vulnerable asset must not crowd out route
  diversity in the top-50 set (measured on the live data: 3396 candidate
  rows collapse to 101 distinct routes).
- Writes are idempotent (`MERGE` on `path_id`, a hash of the route's
  `node_ids`), consistent with Agent 3's import pattern.

## Acceptance criteria

- [ ] `scripts/find_paths.py` runs against a real Neo4j instance (the one
      `docker-compose.yml` provides, already populated by Agent 3) and
      exits 0.
- [ ] `(:AttackPath)` nodes exist for the top 50 scored routes, ranked 1..50
      with no gaps.
- [ ] Every exploitable `:Asset` with at least one reachable neighbor has a
      `blast_radius` property; every `:Asset` appearing on more than one
      top-50 route has a `choke_point_count` property.
- [ ] `contracts/04_paths_to_reasoning.yaml` documents the graph
      annotations and query module precisely enough for the Reasoning
      Agent to consume them without reading this repo's Path Engine code.
