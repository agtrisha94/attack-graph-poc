# QA & Docs (Agent 7) Design

## Mission

Verify, against the live pipeline output (not mocks), that every contract's
`consumer_must_validate` checklist actually holds -- and write the docs that
let a new reader run the whole 7-agent pipeline and see it work. Terminal
phase: no downstream contract, no new src/ business-logic package.

## Scope

- **Live verification, not re-tested logic.** The existing 139 tests already
  cover each module's internal logic with mocked sessions. Agent 7's suite
  answers a different question: does the *actual* data currently sitting in
  `data/processed/`, `data/synthetic/`, and the running Neo4j instance
  satisfy every contract's `consumer_must_validate` bullet, end to end. It
  connects to the real DB (`NEO4J_URI`/`NEO4J_USER`/`NEO4J_PASSWORD` from
  `.env`, same pattern as every `scripts/*.py`) and fails loudly if it can't
  connect -- no skip-if-down, since a live-verification suite that silently
  skips proves nothing.
- **Reuse over reimplementation.** `src/graph/validate.py`'s
  `validate_graph()` already implements contract 02/03's checklist; Agent 7
  calls it rather than re-deriving the same Cypher. `src/paths/score.py`'s
  `score_path()` is reused to recompute and compare, not reimplemented.
- **Docs are synthesis, not new design.** `docs/architecture.md` and
  `docs/demo_walkthrough.md` are written from the contracts and specs that
  already exist (both files currently empty placeholders) -- no new
  architectural decisions get made in this phase.
- **Out of scope:** re-testing internal module logic (already covered),
  performance/load testing, a CI workflow file (no CI system in this repo
  currently), fixing any violation the suite finds (that's a bug in the
  phase that produced it, not Agent 7's job -- Agent 7 reports, doesn't
  repair).

## Architecture

```
tests/acceptance/
  __init__.py
  conftest.py           # neo4j_session fixture: connects via .env vars
                         # (mirrors src/graph/validate.py's connection
                         # pattern), raises with a clear "start
                         # docker-compose up" message if connection fails
  test_contracts.py     # one test function per contract (01-06), each
                         # asserting every consumer_must_validate bullet

docs/
  architecture.md        # 7-agent pipeline overview, contract chain,
                          # Neo4j graph model
  demo_walkthrough.md    # runnable steps: docker-compose up -> ingest ->
                          # build_graph -> find_paths -> reason_paths ->
                          # watch_paths -> dashboard

agents/qa_docs/prompt.md # mission/inputs/outputs/acceptance-criteria,
                          # same format as agents/watchdog/prompt.md
```

No new dependencies (pandas, neo4j driver, pytest already present). No new
src/ package -- this phase has no reusable business logic of its own, only
verification and documentation.

## Acceptance test suite

`tests/acceptance/conftest.py`:

- `neo4j_session` fixture (module-scoped): builds a driver from
  `NEO4J_URI`/`NEO4J_USER`/`NEO4J_PASSWORD` exactly like
  `src/graph/validate.py:main()`, yields a session, closes the driver after.
  `NEO4J_PASSWORD` missing or connection refused -> the fixture raises
  immediately with a message telling the user to start the DB, rather than
  producing a confusing downstream failure.

`tests/acceptance/test_contracts.py`, one test per contract:

- **`test_contract_01_requirements_to_data`** -- no Neo4j needed, reads
  `data/processed/microsoft_cve_master.csv`, `data/processed/technique_map.csv`,
  `data/synthetic/nodes_topology.csv`, `data/synthetic/edges_topology.csv`
  with pandas directly: required columns present, `cve_id`/`epss_score`
  non-null, `epss_score`/`epss_percentile` in [0,1], `base_score` in [0,10],
  `kev_flag` boolean with `kev_date_added`/`ransomware_used` null iff
  `kev_flag` is false, Microsoft-scope filter (0 rows failing
  `vendor_aliases` from `schemas/data_schema.yaml`), row counts > 0, every
  edge's endpoints exist in nodes.
- **`test_contract_02_data_to_graph`** and **`test_contract_03_graph_to_paths`**
  -- call `src.graph.validate.validate_graph(session, ...)`, assert the
  returned violations list is empty; separately assert the three uniqueness
  constraints exist via `SHOW CONSTRAINTS`.
- **`test_contract_04_paths_to_reasoning`** -- query all `(:AttackPath)`
  nodes with their sourcing `(:CVE)`/`(:Asset)` properties, recompute
  `score_path()` per row, assert it matches the persisted `score` (float
  tolerance), assert every `node_ids` entry resolves to an existing
  `(:Asset)`, assert `rank` is a dense 1..N ordering by score descending.
- **`test_contract_05_reasoning_to_watchdog`** -- query `(:Reasoning)`
  nodes: every `path_id` matches an existing `(:AttackPath {path_id})`,
  `threat_actors`/`mitigations`/`technique_ids` are lists (possibly empty,
  per contract 05's documented known_limitations -- the 50 baseline paths'
  source CVEs predate the MAPS_TO-mapped CVE set, so empty lists here are
  expected, not a failure), never null, and `explanation` is non-empty.
- **`test_contract_06_watchdog_to_qa`** -- query `(:Alert)` nodes: every
  `alert_type` in the fixed 3-value set, null-pairing per type
  (`new_top50_entry`: old_* null, new_* non-null; `dropped_from_top50`:
  reverse; `score_change`: all four non-null), `alert_id` uniqueness,
  minimum alert counts per the known_limitations note in contract 06 (>=5
  `score_change` alerts from the KEV disclosure) rather than exact totals,
  and that `(:AttackPath)`/`(:Reasoning)` node counts and `:EXPLAINED_BY`
  edge count are unchanged from Agent 5's handoff (Watchdog does not
  rewrite them).

## Docs

`docs/architecture.md`: the 7-agent pipeline end to end -- what each agent
consumes/produces, how the 6 contracts chain them (01->02->...->06), the
Neo4j graph model (node labels: CVE, Technique, Asset, AttackPath,
Reasoning, Alert; relationship types: AFFECTS, MAPS_TO, topology edges,
EXPLAINED_BY), and a pointer to where each phase's logic lives in `src/`.
Synthesized from `requirements.md`, `contracts/*.yaml`, and
`docs/superpowers/specs/*.md` -- no new facts, just organized for a reader
who hasn't seen those six files.

`docs/demo_walkthrough.md`: concrete commands in order --
`docker-compose up -d`, then each `scripts/*.py` in pipeline order, then
`streamlit run dashboard/app.py` (or actual entrypoint), noting what to look
for at each step (row counts, Neo4j Browser queries, dashboard pages) so
someone can confirm it worked without reading source.

## agents/qa_docs/prompt.md

Filled in from the empty placeholder, same structure as
`agents/watchdog/prompt.md`: mission, inputs (contract 06), outputs
(`tests/acceptance/`, `docs/architecture.md`, `docs/demo_walkthrough.md`),
acceptance criteria (every contract's checklist passes against live data;
both docs exist and are non-empty; a fresh reader can follow
demo_walkthrough.md end to end).

## Testing

The acceptance suite *is* the test deliverable for this phase -- there's no
separate "tests for the tests." `tests/acceptance/conftest.py`'s fixture
itself gets no unit test (it's a thin driver-construction wrapper mirroring
existing code); its correctness is proven by the acceptance tests passing
against the real DB.

## Out of scope for this design

- Fixing any contract violation the suite discovers (reported, not repaired,
  in this phase).
- A CI workflow to run the suite automatically.
- Performance/load testing.
- Re-deriving graph-model facts already fully specified in
  `contracts/*.yaml` -- `docs/architecture.md` points to them rather than
  duplicating them.
