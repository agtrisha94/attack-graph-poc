# Architecture -- Attack Graph POC

A 7-agent pipeline. Each agent consumes the previous agent's Neo4j graph
state (plus any files it produced) and hands off to the next via a written
contract in `contracts/`. Each numbered contract below is listed under the
agent that CONSUMES it (i.e. `contracts/01_requirements_to_data.yaml` is
what Agent 2 reads, not what Agent 1 produced it as). See `requirements.md`
for the full mission and `docs/superpowers/specs/` for each phase's design
rationale.

## Pipeline

1. **Requirements Architect** -- `schemas/data_schema.yaml`, `requirements.md`.
   No upstream input, root of the pipeline.
2. **Data Engineer** -- ingests CISA KEV, EPSS, the Kaggle CVE corpus, and
   MITRE ATT&CK; produces `data/processed/microsoft_cve_master.csv`,
   `data/processed/technique_map.csv`, and the synthetic enterprise topology
   (`data/synthetic/nodes_topology.csv`, `data/synthetic/edges_topology.csv`).
   Consumes: `contracts/01_requirements_to_data.yaml`.
3. **Graph Architect** -- imports those CSVs into Neo4j
   (`scripts/build_graph.py`), with uniqueness constraints on
   `(:CVE.cve_id)`, `(:Technique.technique_id)`, `(:Asset.node_id)`.
   Consumes: `contracts/02_data_to_graph.yaml`.
4. **Path Engine** -- extracts attack paths from CVE-exploitable assets to
   Crown Jewel assets, scores and ranks the top 50
   (`scripts/find_paths.py`), computes blast radius and choke points.
   Consumes: `contracts/03_graph_to_paths.yaml`.
5. **Reasoning Agent** -- explains each of the top-50 paths, grounded in
   MITRE ATT&CK threat-actor/mitigation data (`scripts/reason_paths.py`).
   Consumes: `contracts/04_paths_to_reasoning.yaml`.
6. **Watchdog Agent** -- applies deterministic synthetic scenario mutations,
   re-scores affected paths, diffs against the baseline, writes `:Alert`
   nodes (`scripts/watch_paths.py`).
   Consumes: `contracts/05_baseline_to_watchdog.yaml`.
7. **QA & Docs** (this phase) -- live acceptance tests
   (`tests/acceptance/`) proving every contract's checklist holds against
   the real data, plus this document and `docs/demo_walkthrough.md`.
   Consumes: `contracts/06_watchdog_to_qa.yaml`.

## Neo4j graph model

Node labels:

- `(:CVE {cve_id, vendor, product, base_score, epss_score, kev_flag, attack_vector, ...})`
- `(:Technique {technique_id, technique_name, tactic})`
- `(:Asset {node_id, node_type, criticality_tier, internet_facing, blast_radius, choke_point_count, ...})` --
  also carries a secondary label matching its `node_type` (e.g.
  `(:Asset:Computer)`, `(:Asset:User)`, `(:Asset:Group)`,
  `(:Asset:Application)`, `(:Asset:Device)`); see
  `contracts/03_graph_to_paths.yaml`.
- `(:AttackPath {path_id, score, rank, hop_count, source_cve, source_asset_id, target_asset_id, node_ids})`
- `(:Reasoning {path_id, explanation, threat_actors, mitigations, technique_ids})`
- `(:Alert {alert_id, alert_type, path_id, old_score, new_score, old_rank, new_rank, source_cve, source_asset_id, target_asset_id})`

Relationship types: `AFFECTS` (CVE->Asset), `MAPS_TO` (CVE->Technique),
topology edges (`RUNS`/`CONNECTS_TO`/`MEMBER_OF`/`HAS_SESSION`/`CONTROLS`
between Assets), `EXPLAINED_BY` (AttackPath->Reasoning). `Alert` nodes carry
no graph relationship -- see `contracts/06_watchdog_to_qa.yaml` for why.

## Scoring formula

`(:AttackPath).score` = `(base_score * epss_score * criticality_weight *
kev_multiplier * exposure_multiplier * attack_vector_weight) / (hop_count + 1)`,
implemented in `src/paths/score.py`. See
`contracts/04_paths_to_reasoning.yaml` for the exact multiplier table.

## Where each phase's logic lives

| Phase | Code |
|---|---|
| Data Engineer | `src/ingestion/`, `src/generator/`, `scripts/build_dataset.py` |
| Graph Architect | `src/graph/`, `scripts/build_graph.py` |
| Path Engine | `src/paths/`, `scripts/find_paths.py` |
| Reasoning Agent | `src/reasoning/`, `scripts/reason_paths.py` |
| Watchdog Agent | `src/watchdog/`, `scripts/watch_paths.py` |
| QA & Docs | `tests/acceptance/` |
| Dashboard (cross-cutting UI) | `dashboard/` |
