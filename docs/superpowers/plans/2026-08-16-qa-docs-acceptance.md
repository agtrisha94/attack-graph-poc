# QA & Docs (Agent 7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove, with live tests against the running Neo4j instance and the
real processed CSVs, that every one of the 6 contracts' `consumer_must_validate`
checklists actually holds -- then write the docs that let a new reader run
the whole pipeline end to end.

**Architecture:** One new test package, `tests/acceptance/`, with a single
`neo4j_session` fixture and one test function per contract in
`test_contracts.py`. No new `src/` package -- this phase reuses
`src/graph/validate.py:validate_graph()` and `src/paths/score.py:score_path()`
rather than reimplementing their logic. Two doc files
(`docs/architecture.md`, `docs/demo_walkthrough.md`) and one agent prompt
(`agents/qa_docs/prompt.md`) get filled in from their current empty
placeholders.

**Tech Stack:** pytest, pandas, neo4j Python driver (all already in
`requirements.txt` -- no new dependencies).

**Spec:** `docs/superpowers/specs/2026-08-16-qa-docs-design.md`

## Global Constraints

- Connection info comes from `NEO4J_URI`/`NEO4J_USER`/`NEO4J_PASSWORD` env
  vars, same as every `scripts/*.py` (`os.environ["NEO4J_PASSWORD"]` with no
  default -- raises `KeyError` if unset, which is the intended "fail loudly"
  behavior; no `.env` autoloading, matching the rest of the repo).
- Tests connect to the **live** DB. No mocking, no skip-if-down.
- No new dependencies.
- Reuse `src/graph/validate.py:validate_graph(session, processed_dir, synthetic_dir) -> list[str]`
  and `src/paths/score.py:score_path(base_score, epss_score, criticality_tier, *, kev_flag, hop_count, internet_facing, attack_vector) -> float`
  rather than reimplementing their checks.
- `docker compose up -d` must already be running with the graph populated by
  Agents 3-6 for these tests to pass (README.md's existing setup steps).

---

## Task 1: Contract 01 -- data CSV validation (no DB)

**Files:**
- Create: `tests/acceptance/__init__.py` (empty)
- Create: `tests/acceptance/test_contracts.py`

**Interfaces:**
- Produces: `test_contract_01_requirements_to_data()` -- standalone, no
  fixture dependency. Later tasks append more test functions to this same
  file.

- [ ] **Step 1: Write the test**

Create `tests/acceptance/__init__.py` (empty file, makes the directory a
package so pytest's rootdir-relative imports work the same as `tests/`).

Create `tests/acceptance/test_contracts.py`:

```python
"""Live acceptance tests: verify each contracts/0N_*.yaml's
consumer_must_validate checklist against the real pipeline output (real
CSVs, the real running Neo4j graph) -- not mocks. See
docs/superpowers/specs/2026-08-16-qa-docs-design.md."""
import pandas as pd

VENDOR_ALIASES = [
    "microsoft", "windows", "azure", "office", "exchange", "sql server",
    ".net", "edge", "sharepoint", "active directory",
]

CVE_MASTER_REQUIRED_COLUMNS = [
    "cve_id", "vendor", "product", "description", "base_severity",
    "base_score", "epss_score", "epss_percentile", "kev_flag",
    "published_date",
]
NODES_REQUIRED_COLUMNS = [
    "node_id", "node_type", "display_name", "criticality_tier",
]
EDGES_REQUIRED_COLUMNS = ["source_id", "target_id", "edge_type"]


def test_contract_01_requirements_to_data():
    cve_df = pd.read_csv("data/processed/microsoft_cve_master.csv")
    technique_df = pd.read_csv("data/processed/technique_map.csv")
    nodes_df = pd.read_csv("data/synthetic/nodes_topology.csv")
    edges_df = pd.read_csv("data/synthetic/edges_topology.csv")

    for col in CVE_MASTER_REQUIRED_COLUMNS:
        assert col in cve_df.columns, f"microsoft_cve_master.csv missing required column {col}"
    for col in NODES_REQUIRED_COLUMNS:
        assert col in nodes_df.columns, f"nodes_topology.csv missing required column {col}"
    for col in EDGES_REQUIRED_COLUMNS:
        assert col in edges_df.columns, f"edges_topology.csv missing required column {col}"

    assert cve_df["cve_id"].notna().all(), "cve_id has null values"
    assert cve_df["epss_score"].notna().all(), "epss_score has null values"
    assert cve_df["epss_score"].between(0, 1).all(), "epss_score out of [0,1]"
    assert cve_df["epss_percentile"].between(0, 1).all(), "epss_percentile out of [0,1]"
    assert cve_df["base_score"].between(0, 10).all(), "base_score out of [0,10]"
    assert cve_df["kev_flag"].dtype == bool, "kev_flag is not boolean"

    kev_true = cve_df[cve_df["kev_flag"]]
    kev_false = cve_df[~cve_df["kev_flag"]]
    assert kev_false["kev_date_added"].isna().all(), "kev_date_added set on a non-KEV row"
    assert kev_false["ransomware_used"].isna().all(), "ransomware_used set on a non-KEV row"
    assert kev_true["kev_date_added"].notna().all(), "kev_date_added null on a KEV row"

    out_of_scope = cve_df[~cve_df["vendor"].str.lower().apply(
        lambda v: any(alias in v for alias in VENDOR_ALIASES)
    )]
    assert len(out_of_scope) == 0, (
        f"{len(out_of_scope)} row(s) fail the Microsoft-scope vendor_aliases match: "
        f"{out_of_scope['cve_id'].tolist()[:5]}"
    )

    for name, df in [
        ("microsoft_cve_master.csv", cve_df), ("technique_map.csv", technique_df),
        ("nodes_topology.csv", nodes_df), ("edges_topology.csv", edges_df),
    ]:
        assert len(df) > 0, f"{name} is empty"

    node_ids = set(nodes_df["node_id"])
    missing_source = ~edges_df["source_id"].isin(node_ids)
    missing_target = ~edges_df["target_id"].isin(node_ids)
    assert not missing_source.any(), f"edges reference unknown source_id: {edges_df[missing_source]['source_id'].tolist()[:5]}"
    assert not missing_target.any(), f"edges reference unknown target_id: {edges_df[missing_target]['target_id'].tolist()[:5]}"
```

- [ ] **Step 2: Run the test**

Run: `python3 -m pytest tests/acceptance/test_contracts.py -v`
Expected: `test_contract_01_requirements_to_data PASSED` (the real CSVs
already satisfy contract 01 -- Agent 2 built them to this spec). If it
fails, the failure message names exactly which contract 01 guarantee the
current data violates.

- [ ] **Step 3: Commit**

```bash
git add tests/acceptance/__init__.py tests/acceptance/test_contracts.py
git commit -m "test: add contract 01 acceptance check (live CSV validation)"
```

---

## Task 2: `neo4j_session` fixture + Contract 02/03 test

**Files:**
- Create: `tests/acceptance/conftest.py`
- Modify: `tests/acceptance/test_contracts.py` (append)

**Interfaces:**
- Consumes: `src.graph.validate.validate_graph(session, processed_dir, synthetic_dir) -> list[str]` (existing, `src/graph/validate.py:21`).
- Produces: `neo4j_session` pytest fixture (module-scoped), usable by every
  later task's test functions via parameter injection.

- [ ] **Step 1: Write the fixture**

Create `tests/acceptance/conftest.py`:

```python
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
```

- [ ] **Step 2: Append the Contract 02/03 test**

Append to `tests/acceptance/test_contracts.py`:

```python
import pathlib

from src.graph.validate import validate_graph


def test_contract_02_and_03_data_to_graph(neo4j_session):
    violations = validate_graph(
        neo4j_session, pathlib.Path("data/processed"), pathlib.Path("data/synthetic")
    )
    assert violations == [], f"graph import violations: {violations}"

    constraint_names = {
        record["name"] for record in neo4j_session.run("SHOW CONSTRAINTS")
    }
    for expected in ("cve_id_unique", "technique_id_unique", "asset_node_id_unique"):
        assert expected in constraint_names, f"missing constraint {expected}"
```

- [ ] **Step 3: Run the test**

Run: `python3 -m pytest tests/acceptance/test_contracts.py -v`
Expected: both `test_contract_01_requirements_to_data` and
`test_contract_02_and_03_data_to_graph` PASS, provided `docker compose up -d`
is running and `NEO4J_PASSWORD` is exported in the shell. If Neo4j isn't
reachable, expect a clear `pytest.fail` message naming the fix, not a raw
connection traceback.

- [ ] **Step 4: Commit**

```bash
git add tests/acceptance/conftest.py tests/acceptance/test_contracts.py
git commit -m "test: add live neo4j_session fixture and contract 02/03 acceptance check"
```

---

## Task 3: Contract 04 test -- AttackPath score/rank verification

**Files:**
- Modify: `tests/acceptance/test_contracts.py` (append)

**Interfaces:**
- Consumes: `src.paths.score.score_path(base_score, epss_score, criticality_tier, *, kev_flag, hop_count, internet_facing, attack_vector) -> float` (existing, `src/paths/score.py:19`); `neo4j_session` fixture from Task 2.

- [ ] **Step 1: Write the test**

Append to `tests/acceptance/test_contracts.py`:

```python
from src.paths.score import score_path

ATTACK_PATH_SCORE_QUERY = """
MATCH (p:AttackPath)
MATCH (c:CVE {cve_id: p.source_cve})
MATCH (src:Asset {node_id: p.source_asset_id})
MATCH (tgt:Asset {node_id: p.target_asset_id})
RETURN p.path_id AS path_id, p.score AS score, p.rank AS rank,
       p.hop_count AS hop_count, p.node_ids AS node_ids,
       c.base_score AS base_score, c.epss_score AS epss_score,
       c.kev_flag AS kev_flag, c.attack_vector AS attack_vector,
       src.internet_facing AS internet_facing,
       tgt.criticality_tier AS criticality_tier
"""


def test_contract_04_paths_to_reasoning(neo4j_session):
    rows = [dict(r) for r in neo4j_session.run(ATTACK_PATH_SCORE_QUERY)]
    assert len(rows) > 0, "no (:AttackPath) nodes found"

    asset_ids = {
        r["node_id"] for r in neo4j_session.run("MATCH (a:Asset) RETURN a.node_id AS node_id")
    }

    for row in rows:
        for node_id in row["node_ids"]:
            assert node_id in asset_ids, f"AttackPath {row['path_id']} node_ids has unknown asset {node_id}"

        expected = score_path(
            row["base_score"], row["epss_score"], row["criticality_tier"],
            kev_flag=row["kev_flag"], hop_count=row["hop_count"],
            internet_facing=bool(row["internet_facing"]), attack_vector=row["attack_vector"],
        )
        assert row["score"] == pytest.approx(expected, rel=1e-6), (
            f"AttackPath {row['path_id']} score {row['score']} != recomputed {expected}"
        )

    ranks = sorted(r["rank"] for r in rows)
    assert ranks == list(range(1, len(rows) + 1)), f"rank is not a dense 1..N ordering: {ranks}"

    scores_by_rank = sorted(rows, key=lambda r: r["rank"])
    for a, b in zip(scores_by_rank, scores_by_rank[1:]):
        assert a["score"] >= b["score"], f"rank {a['rank']} score {a['score']} < rank {b['rank']} score {b['score']}"
```

This needs `pytest` imported at module level -- add `import pytest` to the
top of `tests/acceptance/test_contracts.py` alongside the existing `import
pandas as pd`.

- [ ] **Step 2: Run the test**

Run: `python3 -m pytest tests/acceptance/test_contracts.py -v`
Expected: `test_contract_04_paths_to_reasoning PASSED`.

- [ ] **Step 3: Commit**

```bash
git add tests/acceptance/test_contracts.py
git commit -m "test: add contract 04 acceptance check (score/rank recomputation)"
```

---

## Task 4: Contract 05 test -- Reasoning grounding

**Files:**
- Modify: `tests/acceptance/test_contracts.py` (append)

**Interfaces:**
- Consumes: `neo4j_session` fixture from Task 2.

- [ ] **Step 1: Write the test**

Append to `tests/acceptance/test_contracts.py`:

```python
def test_contract_05_reasoning_to_watchdog(neo4j_session):
    rows = [dict(r) for r in neo4j_session.run(
        "MATCH (r:Reasoning) RETURN r.path_id AS path_id, r.explanation AS explanation, "
        "r.threat_actors AS threat_actors, r.mitigations AS mitigations, "
        "r.technique_ids AS technique_ids"
    )]
    assert len(rows) > 0, "no (:Reasoning) nodes found"

    path_ids = {
        r["path_id"] for r in neo4j_session.run("MATCH (p:AttackPath) RETURN p.path_id AS path_id")
    }

    for row in rows:
        assert row["path_id"] in path_ids, f"Reasoning {row['path_id']} has no matching AttackPath"
        assert row["explanation"], f"Reasoning {row['path_id']} has empty explanation"
        # Empty lists are expected per contract 05's known_limitations (the
        # baseline paths' source CVEs predate the MAPS_TO-mapped CVE set) --
        # only null is a violation, not emptiness.
        for field in ("threat_actors", "mitigations", "technique_ids"):
            assert row[field] is not None, f"Reasoning {row['path_id']}.{field} is null"
            assert isinstance(row[field], list), f"Reasoning {row['path_id']}.{field} is not a list"
```

- [ ] **Step 2: Run the test**

Run: `python3 -m pytest tests/acceptance/test_contracts.py -v`
Expected: `test_contract_05_reasoning_to_watchdog PASSED`.

- [ ] **Step 3: Commit**

```bash
git add tests/acceptance/test_contracts.py
git commit -m "test: add contract 05 acceptance check (reasoning grounding)"
```

---

## Task 5: Contract 06 test -- Alert shape + unchanged baseline

**Files:**
- Modify: `tests/acceptance/test_contracts.py` (append)

**Interfaces:**
- Consumes: `neo4j_session` fixture from Task 2.

- [ ] **Step 1: Write the test**

Append to `tests/acceptance/test_contracts.py`:

```python
ALERT_TYPES = {"new_top50_entry", "score_change", "dropped_from_top50"}


def test_contract_06_watchdog_to_qa(neo4j_session):
    alerts = [dict(r) for r in neo4j_session.run(
        "MATCH (a:Alert) RETURN a.alert_id AS alert_id, a.alert_type AS alert_type, "
        "a.old_score AS old_score, a.new_score AS new_score, "
        "a.old_rank AS old_rank, a.new_rank AS new_rank"
    )]
    assert len(alerts) > 0, "no (:Alert) nodes found"

    alert_ids = [a["alert_id"] for a in alerts]
    assert len(alert_ids) == len(set(alert_ids)), "duplicate (:Alert).alert_id found"

    counts = {t: 0 for t in ALERT_TYPES}
    for a in alerts:
        assert a["alert_type"] in ALERT_TYPES, f"unexpected alert_type {a['alert_type']}"
        counts[a["alert_type"]] += 1

        if a["alert_type"] == "new_top50_entry":
            assert a["old_score"] is None and a["old_rank"] is None
            assert a["new_score"] is not None and a["new_rank"] is not None
        elif a["alert_type"] == "dropped_from_top50":
            assert a["new_score"] is None and a["new_rank"] is None
            assert a["old_score"] is not None and a["old_rank"] is not None
        elif a["alert_type"] == "score_change":
            assert None not in (a["old_score"], a["new_score"], a["old_rank"], a["new_rank"])

    # known_limitations (contract 06): exact counts depend on the top-50
    # cutoff cascade -- assert the documented minimum, not an exact total.
    assert counts["score_change"] >= 5, (
        f"expected >=5 score_change alerts from the KEV disclosure scenario, got {counts['score_change']}"
    )

    path_count = neo4j_session.run("MATCH (p:AttackPath) RETURN count(p) AS n").single()["n"]
    reasoning_count = neo4j_session.run("MATCH (r:Reasoning) RETURN count(r) AS n").single()["n"]
    explained_by_count = neo4j_session.run(
        "MATCH ()-[e:EXPLAINED_BY]->() RETURN count(e) AS n"
    ).single()["n"]
    assert path_count == 50, f"expected 50 baseline AttackPath nodes, got {path_count}"
    assert reasoning_count == 50, f"expected 50 Reasoning nodes, got {reasoning_count}"
    assert explained_by_count == 50, f"expected 50 EXPLAINED_BY edges, got {explained_by_count}"
```

- [ ] **Step 2: Run the test**

Run: `python3 -m pytest tests/acceptance/test_contracts.py -v`
Expected: all 6 test functions PASS.

- [ ] **Step 3: Run the full suite**

Run: `python3 -m pytest tests/ -v`
Expected: all existing 139 tests plus the 6 new acceptance tests PASS
(140 becomes 145 -- 5 new test functions across contracts 02-06, plus
contract 01, is 6 new tests total).

- [ ] **Step 4: Commit**

```bash
git add tests/acceptance/test_contracts.py
git commit -m "test: add contract 06 acceptance check (alert shape, unchanged baseline)"
```

---

## Task 6: `docs/architecture.md`

**Files:**
- Modify: `docs/architecture.md` (currently empty)

**Interfaces:** None -- documentation only, synthesized from
`requirements.md`, `contracts/*.yaml`, and `docs/superpowers/specs/*.md`
(no new facts).

- [ ] **Step 1: Write the doc**

Write `docs/architecture.md`:

```markdown
# Architecture -- Attack Graph POC

A 7-agent pipeline. Each agent consumes the previous agent's Neo4j graph
state (plus any files it produced) and hands off to the next via a written
contract in `contracts/`. See `requirements.md` for the full mission and
`docs/superpowers/specs/` for each phase's design rationale.

## Pipeline

1. **Requirements Architect** -- `schemas/data_schema.yaml`, `requirements.md`.
   No upstream input, root of the pipeline.
2. **Data Engineer** -- ingests CISA KEV, EPSS, the Kaggle CVE corpus, and
   MITRE ATT&CK; produces `data/processed/microsoft_cve_master.csv`,
   `data/processed/technique_map.csv`, and the synthetic enterprise topology
   (`data/synthetic/nodes_topology.csv`, `data/synthetic/edges_topology.csv`).
   Contract: `contracts/01_requirements_to_data.yaml`.
3. **Graph Architect** -- imports those CSVs into Neo4j
   (`scripts/build_graph.py`), with uniqueness constraints on
   `(:CVE.cve_id)`, `(:Technique.technique_id)`, `(:Asset.node_id)`.
   Contract: `contracts/02_data_to_graph.yaml`.
4. **Path Engine** -- extracts attack paths from CVE-exploitable assets to
   Crown Jewel assets, scores and ranks the top 50
   (`scripts/find_paths.py`), computes blast radius and choke points.
   Contract: `contracts/03_graph_to_paths.yaml`.
5. **Reasoning Agent** -- explains each of the top-50 paths, grounded in
   MITRE ATT&CK threat-actor/mitigation data (`scripts/reason_paths.py`).
   Contract: `contracts/04_paths_to_reasoning.yaml`.
6. **Watchdog Agent** -- applies deterministic synthetic scenario mutations,
   re-scores affected paths, diffs against the baseline, writes `:Alert`
   nodes (`scripts/watch_paths.py`).
   Contract: `contracts/05_baseline_to_watchdog.yaml`.
7. **QA & Docs** (this phase) -- live acceptance tests
   (`tests/acceptance/`) proving every contract's checklist holds against
   the real data, plus this document and `docs/demo_walkthrough.md`.
   Contract: `contracts/06_watchdog_to_qa.yaml`.

## Neo4j graph model

Node labels:

- `(:CVE {cve_id, vendor, product, base_score, epss_score, kev_flag, attack_vector, ...})`
- `(:Technique {technique_id, technique_name, tactic})`
- `(:Asset {node_id, node_type, criticality_tier, internet_facing, blast_radius, choke_point_count, ...})`
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
```

- [ ] **Step 2: Commit**

```bash
git add docs/architecture.md
git commit -m "docs: write architecture overview"
```

---

## Task 7: `docs/demo_walkthrough.md`

**Files:**
- Modify: `docs/demo_walkthrough.md` (currently empty)

**Interfaces:** None -- documentation only.

- [ ] **Step 1: Write the doc**

Write `docs/demo_walkthrough.md`:

```markdown
# Demo Walkthrough

Runs the full 7-agent pipeline end to end and shows where to look at each
step. Assumes Docker is installed.

## 1. Setup

```bash
pip install -r requirements.txt
docker compose up -d          # starts Neo4j on bolt://localhost:7687
cp .env.example .env          # then fill in a real NEO4J_PASSWORD (8+ chars)
set -a && source .env && set +a
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
live data you just built. All 6 should pass.

## 7. Explore visually

```bash
streamlit run dashboard/app.py
```

Opens the dashboard: Graph Explorer (the attack-relevant subgraph), Overview,
Attack Paths, and Risk Analysis pages -- browse the same top-50 paths you
just verified.
```

- [ ] **Step 2: Commit**

```bash
git add docs/demo_walkthrough.md
git commit -m "docs: write demo walkthrough"
```

---

## Task 8: `agents/qa_docs/prompt.md`

**Files:**
- Modify: `agents/qa_docs/prompt.md` (currently empty)

**Interfaces:** None -- documentation only.

- [ ] **Step 1: Write the doc**

Write `agents/qa_docs/prompt.md`:

```markdown
# Agent: QA & Docs

## Mission

Verify, against the live pipeline output (not mocks), that every one of the
6 contracts' `consumer_must_validate` checklists actually holds -- then
write the docs that let a new reader run the whole 7-agent pipeline and see
it work. Terminal phase: no downstream contract.

## Inputs

- The Neo4j graph and `:Alert` nodes handed off by `scripts/watch_paths.py`
  (per `contracts/06_watchdog_to_qa.yaml`).
- Every prior contract (`contracts/01_requirements_to_data.yaml` through
  `contracts/06_watchdog_to_qa.yaml`) -- this phase's job is to check all of
  them, not just the most recent handoff.
- `src/graph/validate.py`'s `validate_graph`, `src/paths/score.py`'s
  `score_path` -- reused directly rather than reimplemented.

## Outputs

- `tests/acceptance/conftest.py`, `tests/acceptance/test_contracts.py`.
- `docs/architecture.md`, `docs/demo_walkthrough.md`.

## Constraints

- Tests connect to the real running Neo4j instance and read the real
  processed CSVs -- no mocking, no skip-if-down (a live-verification suite
  that silently skips proves nothing).
- Reports violations, does not fix them -- a failing acceptance test names a
  bug in whichever phase produced the bad data, not something for this
  phase to patch over.
- No new `src/` package -- this phase has no reusable business logic of its
  own.

## Acceptance criteria

- [ ] `python3 -m pytest tests/acceptance/test_contracts.py -v` passes all 6
      contract checks against the live pipeline output.
- [ ] `docs/architecture.md` covers all 7 agents, the contract chain, and
      the Neo4j graph model.
- [ ] `docs/demo_walkthrough.md` gives a new reader runnable commands to
      reproduce the pipeline end to end and confirm it worked at each step.
```

- [ ] **Step 2: Commit**

```bash
git add agents/qa_docs/prompt.md
git commit -m "docs: add QA & Docs agent prompt"
```

---

## Final check

- [ ] Run `python3 -m pytest tests/ -v` one more time -- full suite (145
      tests: 139 existing + 6 acceptance) passes.
- [ ] Read `docs/architecture.md` and `docs/demo_walkthrough.md` fresh, as
      if seeing the repo for the first time -- confirm no broken references
      to files/commands that don't exist.
