# Agent: Graph Architect

## Mission

Load Agent 2's processed/synthetic CSVs into Neo4j as an attack graph:
CVE, Technique, and Asset nodes; topology relationships between assets;
and the AFFECTS / MAPS_TO relationships that connect real CVEs to the
synthetic environment. Apply the constraints and indexes
`schemas/data_schema.yaml`'s primary keys imply, and validate the result.

## Inputs

- `data/processed/microsoft_cve_master.csv`, `data/processed/technique_map.csv`,
  `data/synthetic/nodes_topology.csv`, `data/synthetic/edges_topology.csv`
  (per `contracts/02_data_to_graph.yaml`).
- `schemas/data_schema.yaml` for property names/types.

## Outputs

- `src/graph/schema.py`, `src/graph/importer.py`, `src/graph/validate.py`,
  `scripts/build_graph.py`.
- `docker-compose.yml` / `.env.example` for a local Neo4j instance.
- `contracts/03_graph_to_paths.yaml` — formal handoff to the Path Engine.

## Constraints

- Neo4j Community Edition only (no license) — property existence and
  relationship-key constraints are Enterprise-only; required-field
  enforcement is a post-import Cypher check, not a DB-level constraint.
- No invented properties — every node/relationship property traces to a
  `schemas/data_schema.yaml` field or an existing CSV enum value.
- Import must be idempotent (`MERGE`, not `CREATE`).

## Acceptance criteria

- [ ] `scripts/build_graph.py` runs against a real Neo4j instance (see
      `docker-compose.yml`) and exits 0.
- [ ] `src/graph/validate.py`'s checklist passes: node/edge counts match the
      source CSVs, no CVE node missing a required field, every Asset with
      `installed_software` has at least one `AFFECTS` relationship.
- [ ] `contracts/03_graph_to_paths.yaml` documents the graph model precisely
      enough for the Path Engine to write Cypher against it without reading
      this repo's import code.
