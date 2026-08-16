# Watchdog Agent (Agent 6) Alerting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Agent 6 (Watchdog) layer: a deterministic synthetic scenario injector that mutates the live graph (KEV disclosure, EPSS spike, new topology edge), a re-score/diff pass reusing Agent 4's scoring logic, and `(:Alert)` node write-back — then hand off contract 06 and the agent's own prompt doc.

**Architecture:** Three small pure-function modules (`src/watchdog/scenario.py` for the mutations, `src/watchdog/rescore.py` for baseline-read + diff logic, `src/watchdog/writeback.py` for the `MERGE`/`SET` alert statements) and a thin orchestrator (`scripts/watch_paths.py`) that wires them together with `src/paths/{extract,writeback}.py` reused unmodified, mirroring `scripts/reason_paths.py`. A live local Neo4j is running in this environment, already populated with 50 `:AttackPath` nodes and 50 linked `:Reasoning` nodes by Agents 4-5, so the last task runs the real pipeline end-to-end against it.

**Tech Stack:** Python 3.11, `neo4j` 5.28.4 driver, pytest 9.1.1 (all already installed — no new dependency).

## Global Constraints

- **No new dependencies.**
- **No fabricated CVEs, assets, or topology facts (NFR2/NFR3).** Every scenario mutation targets a real, already-existing `:CVE`/`:Asset` node id in the live graph — verified live: `CVE-2009-0133` (sources 5 baseline top-50 paths), `CVE-2024-29988` (sources the rank-50 path), `computer-0078`/`computer-0160` (an existing 4-hop route with no direct edge yet).
- **Watchdog does not rewrite `:AttackPath`/`:Reasoning`.** Do not call `src.paths.writeback.clear_previous_results`/`write_attack_paths` — that would sever Agent 5's `:EXPLAINED_BY` edges (see design spec, Scope).
- **Fixed alert thresholds, not configurable.** `SCORE_CHANGE_THRESHOLD = 0.20`, three alert types only (`new_top50_entry`, `score_change`, `dropped_from_top50`). No env var, no CLI flag.
- **Idempotent writes.** Scenario mutations use `SET`/`MERGE` (safe to re-run); `:Alert` writes use `MERGE` on `alert_id`, same pattern as Agents 3-5.
- **No invented properties.** Every `:Alert` field traces to the design spec (`docs/superpowers/specs/2026-08-16-watchdog-design.md`).
- Follow TDD: write the failing test, confirm it fails, implement, confirm it passes, commit.
- A live local Neo4j (`neo4j:5-community`, via `docker-compose.yml`) is running in this environment (container `attack-graph-poc-neo4j-1`), already populated by Agents 3-5: 50 `:AttackPath` nodes, 50 `:Reasoning` nodes linked via `:EXPLAINED_BY`. The checked-in `.env` password already matches the running container — no sync step needed.

---

## File Structure

- `src/watchdog/__init__.py` — empty, package marker.
- `src/watchdog/scenario.py` — `KEV_DISCLOSURE_CVE`, `EPSS_SPIKE_CVE`, `EPSS_SPIKE_NEW_VALUE`, `NEW_EDGE_SOURCE_ASSET`, `NEW_EDGE_TARGET_ASSET`, `apply_kev_disclosure(session, cve_id=KEV_DISCLOSURE_CVE) -> dict`, `apply_epss_spike(session, cve_id=EPSS_SPIKE_CVE, new_epss=EPSS_SPIKE_NEW_VALUE) -> dict`, `apply_new_topology_edge(session, source_asset_id=NEW_EDGE_SOURCE_ASSET, target_asset_id=NEW_EDGE_TARGET_ASSET) -> dict`.
- `src/watchdog/rescore.py` — `SCORE_CHANGE_THRESHOLD = 0.20`, `READ_BASELINE_QUERY`, `read_baseline_paths(session) -> dict[str, dict]`, `diff_paths(baseline: dict[str, dict], rescored_routes: list[dict]) -> list[dict]`.
- `src/watchdog/writeback.py` — `clear_previous_alerts(session) -> None`, `write_alerts(session, alerts: list[dict]) -> int`.
- `scripts/watch_paths.py` — orchestrator CLI: connect, read baseline, apply the 3 scenario mutations, re-extract/re-rank, diff, clear + write alerts, print summary.
- `contracts/06_watchdog_to_qa.yaml` — Agent 6's handoff to QA & Docs.
- `agents/watchdog/prompt.md` — Agent 6's mission doc.
- `tests/test_watchdog_scenario.py`, `tests/test_watchdog_rescore.py`, `tests/test_watchdog_writeback.py`, `tests/test_watch_paths.py`.

---

### Task 1: Scenario injector (`src/watchdog/scenario.py`)

**Files:**
- Create: `src/watchdog/__init__.py` (empty)
- Create: `src/watchdog/scenario.py`
- Test: `tests/test_watchdog_scenario.py`

**Interfaces:**
- Produces: `apply_kev_disclosure(session, cve_id: str = KEV_DISCLOSURE_CVE) -> dict`, `apply_epss_spike(session, cve_id: str = EPSS_SPIKE_CVE, new_epss: float = EPSS_SPIKE_NEW_VALUE) -> dict`, `apply_new_topology_edge(session, source_asset_id: str = NEW_EDGE_SOURCE_ASSET, target_asset_id: str = NEW_EDGE_TARGET_ASSET) -> dict`. Consumed by Task 4 (`scripts/watch_paths.py`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_watchdog_scenario.py
from unittest.mock import MagicMock

from src.watchdog.scenario import (
    apply_epss_spike,
    apply_kev_disclosure,
    apply_new_topology_edge,
)


def _fake_session(record):
    session = MagicMock()
    result = MagicMock()
    result.single.return_value = record
    session.run.return_value = result
    return session


def test_apply_kev_disclosure_sets_kev_flag_true_and_returns_before_after():
    session = _fake_session({"cve_id": "CVE-2009-0133", "before": False, "after": True})

    result = apply_kev_disclosure(session, cve_id="CVE-2009-0133")

    assert result == {"cve_id": "CVE-2009-0133", "before": False, "after": True}
    query, kwargs = session.run.call_args
    assert "MATCH (c:CVE {cve_id: $cve_id})" in query[0]
    assert "SET c.kev_flag = true" in query[0]
    assert kwargs["cve_id"] == "CVE-2009-0133"


def test_apply_epss_spike_sets_epss_score_and_returns_before_after():
    session = _fake_session({"cve_id": "CVE-2024-29988", "before": 0.45151, "after": 0.95})

    result = apply_epss_spike(session, cve_id="CVE-2024-29988", new_epss=0.95)

    assert result == {"cve_id": "CVE-2024-29988", "before": 0.45151, "after": 0.95}
    query, kwargs = session.run.call_args
    assert "SET c.epss_score = $new_epss" in query[0]
    assert kwargs == {"cve_id": "CVE-2024-29988", "new_epss": 0.95}


def test_apply_new_topology_edge_merges_connects_to():
    session = _fake_session({"source_asset_id": "computer-0078", "target_asset_id": "computer-0160"})

    result = apply_new_topology_edge(session, source_asset_id="computer-0078", target_asset_id="computer-0160")

    assert result == {"source_asset_id": "computer-0078", "target_asset_id": "computer-0160"}
    query, kwargs = session.run.call_args
    assert "MERGE (a)-[:CONNECTS_TO]->(b)" in query[0]
    assert kwargs == {"source_asset_id": "computer-0078", "target_asset_id": "computer-0160"}


def test_scenario_defaults_target_real_baseline_ids():
    from src.watchdog.scenario import (
        EPSS_SPIKE_CVE,
        KEV_DISCLOSURE_CVE,
        NEW_EDGE_SOURCE_ASSET,
        NEW_EDGE_TARGET_ASSET,
    )

    assert KEV_DISCLOSURE_CVE == "CVE-2009-0133"
    assert EPSS_SPIKE_CVE == "CVE-2024-29988"
    assert NEW_EDGE_SOURCE_ASSET == "computer-0078"
    assert NEW_EDGE_TARGET_ASSET == "computer-0160"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_watchdog_scenario.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.watchdog'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/watchdog/scenario.py
"""Deterministic synthetic scenario injector standing in for a live
threat-intel/topology feed -- this is a static synthetic dataset with no
live feed to watch (see docs/superpowers/specs/2026-08-16-watchdog-design.md,
Scope). Every mutation targets a real, already-existing CVE/Asset node id in
the live graph -- no fabricated entities (NFR2/NFR3). Idempotent: re-running
any of these is a no-op past the first call."""

KEV_DISCLOSURE_CVE = "CVE-2009-0133"
EPSS_SPIKE_CVE = "CVE-2024-29988"
EPSS_SPIKE_NEW_VALUE = 0.95
NEW_EDGE_SOURCE_ASSET = "computer-0078"
NEW_EDGE_TARGET_ASSET = "computer-0160"


def apply_kev_disclosure(session, cve_id: str = KEV_DISCLOSURE_CVE) -> dict:
    return dict(session.run(
        "MATCH (c:CVE {cve_id: $cve_id}) "
        "WITH c, c.kev_flag AS before "
        "SET c.kev_flag = true "
        "RETURN c.cve_id AS cve_id, before, c.kev_flag AS after",
        cve_id=cve_id,
    ).single())


def apply_epss_spike(session, cve_id: str = EPSS_SPIKE_CVE, new_epss: float = EPSS_SPIKE_NEW_VALUE) -> dict:
    return dict(session.run(
        "MATCH (c:CVE {cve_id: $cve_id}) "
        "WITH c, c.epss_score AS before "
        "SET c.epss_score = $new_epss "
        "RETURN c.cve_id AS cve_id, before, c.epss_score AS after",
        cve_id=cve_id, new_epss=new_epss,
    ).single())


def apply_new_topology_edge(
    session, source_asset_id: str = NEW_EDGE_SOURCE_ASSET, target_asset_id: str = NEW_EDGE_TARGET_ASSET
) -> dict:
    return dict(session.run(
        "MATCH (a:Asset {node_id: $source_asset_id}), (b:Asset {node_id: $target_asset_id}) "
        "MERGE (a)-[:CONNECTS_TO]->(b) "
        "RETURN a.node_id AS source_asset_id, b.node_id AS target_asset_id",
        source_asset_id=source_asset_id, target_asset_id=target_asset_id,
    ).single())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_watchdog_scenario.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/watchdog/__init__.py src/watchdog/scenario.py tests/test_watchdog_scenario.py
git commit -m "feat: add synthetic scenario injector for Watchdog (Agent 6)"
```

---

### Task 2: Re-score + diff logic (`src/watchdog/rescore.py`)

**Files:**
- Create: `src/watchdog/rescore.py`
- Test: `tests/test_watchdog_rescore.py`

**Interfaces:**
- Consumes: `src.paths.writeback.path_id_for` (existing, Agent 4).
- Produces: `SCORE_CHANGE_THRESHOLD: float`, `READ_BASELINE_QUERY: str`, `read_baseline_paths(session) -> dict[str, dict]`, `diff_paths(baseline: dict[str, dict], rescored_routes: list[dict]) -> list[dict]`. Consumed by Task 4.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_watchdog_rescore.py
from unittest.mock import MagicMock

from src.paths.writeback import path_id_for
from src.watchdog.rescore import READ_BASELINE_QUERY, diff_paths, read_baseline_paths


def test_read_baseline_query_reads_attack_path_fields():
    assert "MATCH (p:AttackPath)" in READ_BASELINE_QUERY
    assert "p.path_id" in READ_BASELINE_QUERY
    assert "p.score" in READ_BASELINE_QUERY
    assert "p.rank" in READ_BASELINE_QUERY


def test_read_baseline_paths_keys_rows_by_path_id():
    session = MagicMock()
    session.run.return_value = [{
        "path_id": "abc123", "score": 10.0, "rank": 5, "source_cve": "CVE-X",
        "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }]

    result = read_baseline_paths(session)

    assert result == {"abc123": {
        "path_id": "abc123", "score": 10.0, "rank": 5, "source_cve": "CVE-X",
        "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }}
    session.run.assert_called_once_with(READ_BASELINE_QUERY)


def _route(node_ids, **overrides):
    base = {
        "node_ids": node_ids, "score": 10.0, "rank": 1,
        "source_cve": "CVE-X", "source_asset_id": "computer-0001",
        "target_asset_id": "computer-0002", "hop_count": 1,
    }
    base.update(overrides)
    return base


def test_diff_paths_flags_new_top50_entry():
    route = _route(["computer-0078", "computer-0160"])
    pid = path_id_for(route["node_ids"])

    alerts = diff_paths({}, [route])

    assert alerts == [{
        "alert_id": f"new_top50_entry:{pid}", "alert_type": "new_top50_entry", "path_id": pid,
        "old_score": None, "new_score": 10.0, "old_rank": None, "new_rank": 1,
        "source_cve": "CVE-X", "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }]


def test_diff_paths_flags_score_change_above_threshold():
    route = _route(["a", "b"], score=20.0, rank=3)
    pid = path_id_for(route["node_ids"])
    baseline = {pid: {
        "path_id": pid, "score": 10.0, "rank": 10, "source_cve": "CVE-X",
        "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }}

    alerts = diff_paths(baseline, [route])

    assert alerts == [{
        "alert_id": f"score_change:{pid}", "alert_type": "score_change", "path_id": pid,
        "old_score": 10.0, "new_score": 20.0, "old_rank": 10, "new_rank": 3,
        "source_cve": "CVE-X", "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }]


def test_diff_paths_ignores_score_change_below_threshold():
    route = _route(["a", "b"], score=10.5, rank=10)
    pid = path_id_for(route["node_ids"])
    baseline = {pid: {
        "path_id": pid, "score": 10.0, "rank": 10, "source_cve": "CVE-X",
        "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }}

    assert diff_paths(baseline, [route]) == []


def test_diff_paths_flags_dropped_from_top50():
    baseline = {"gone123": {
        "path_id": "gone123", "score": 32.76, "rank": 6, "source_cve": "CVE-2021-26855",
        "source_asset_id": "computer-0078", "target_asset_id": "computer-0160",
    }}

    alerts = diff_paths(baseline, [])

    assert alerts == [{
        "alert_id": "dropped_from_top50:gone123", "alert_type": "dropped_from_top50", "path_id": "gone123",
        "old_score": 32.76, "new_score": None, "old_rank": 6, "new_rank": None,
        "source_cve": "CVE-2021-26855", "source_asset_id": "computer-0078", "target_asset_id": "computer-0160",
    }]


def test_diff_paths_no_alerts_when_unchanged():
    route = _route(["a", "b"], score=10.0, rank=1)
    pid = path_id_for(route["node_ids"])
    baseline = {pid: {
        "path_id": pid, "score": 10.0, "rank": 1, "source_cve": "CVE-X",
        "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }}

    assert diff_paths(baseline, [route]) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_watchdog_rescore.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.watchdog.rescore'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/watchdog/rescore.py
"""Diffs a freshly re-scored candidate route set against the persisted
:AttackPath baseline Agent 5 left, classifying exactly three fixed alert
types -- new_top50_entry, score_change, dropped_from_top50 (see
docs/superpowers/specs/2026-08-16-watchdog-design.md, Re-score + diff
logic). Reuses src.paths.writeback.path_id_for so rescored routes match
baseline path_ids the same way Agent 4 assigned them."""
from src.paths.writeback import path_id_for

# 20%: clearly above float noise, comfortably below the ~2x/~2.1x swings the
# scenario injector's own mutations produce. Fixed, not configurable (YAGNI).
SCORE_CHANGE_THRESHOLD = 0.20

READ_BASELINE_QUERY = """
MATCH (p:AttackPath)
RETURN p.path_id AS path_id, p.score AS score, p.rank AS rank,
       p.source_cve AS source_cve, p.source_asset_id AS source_asset_id,
       p.target_asset_id AS target_asset_id
""".strip()


def read_baseline_paths(session) -> dict[str, dict]:
    return {row["path_id"]: dict(row) for row in session.run(READ_BASELINE_QUERY)}


def _alert(alert_type: str, path_id: str, *, old, new, source_cve, source_asset_id, target_asset_id) -> dict:
    return {
        "alert_id": f"{alert_type}:{path_id}",
        "alert_type": alert_type,
        "path_id": path_id,
        "old_score": old["score"] if old else None,
        "new_score": new["score"] if new else None,
        "old_rank": old["rank"] if old else None,
        "new_rank": new["rank"] if new else None,
        "source_cve": source_cve,
        "source_asset_id": source_asset_id,
        "target_asset_id": target_asset_id,
    }


def diff_paths(baseline: dict[str, dict], rescored_routes: list[dict]) -> list[dict]:
    rescored_by_id = {path_id_for(r["node_ids"]): r for r in rescored_routes}
    alerts = []

    for path_id, new in rescored_by_id.items():
        old = baseline.get(path_id)
        if old is None:
            alerts.append(_alert(
                "new_top50_entry", path_id, old=None, new=new,
                source_cve=new["source_cve"], source_asset_id=new["source_asset_id"],
                target_asset_id=new["target_asset_id"],
            ))
            continue
        old_score = old["score"]
        pct_change = abs(new["score"] - old_score) / old_score if old_score else float("inf")
        if pct_change > SCORE_CHANGE_THRESHOLD:
            alerts.append(_alert(
                "score_change", path_id, old=old, new=new,
                source_cve=new["source_cve"], source_asset_id=new["source_asset_id"],
                target_asset_id=new["target_asset_id"],
            ))

    for path_id, old in baseline.items():
        if path_id not in rescored_by_id:
            alerts.append(_alert(
                "dropped_from_top50", path_id, old=old, new=None,
                source_cve=old["source_cve"], source_asset_id=old["source_asset_id"],
                target_asset_id=old["target_asset_id"],
            ))

    return alerts
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_watchdog_rescore.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/watchdog/rescore.py tests/test_watchdog_rescore.py
git commit -m "feat: add Watchdog re-score/diff logic against AttackPath baseline (Agent 6)"
```

---

### Task 3: Write-back (`src/watchdog/writeback.py`)

**Files:**
- Create: `src/watchdog/writeback.py`
- Test: `tests/test_watchdog_writeback.py`

**Interfaces:**
- Consumes: nothing directly (takes `diff_paths`' output, Task 2, by shape convention).
- Produces: `clear_previous_alerts(session) -> None`, `write_alerts(session, alerts: list[dict]) -> int`. Consumed by Task 4.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_watchdog_writeback.py
from unittest.mock import MagicMock

from src.watchdog.writeback import clear_previous_alerts, write_alerts


def test_clear_previous_alerts_detach_deletes_alert_nodes():
    session = MagicMock()

    clear_previous_alerts(session)

    query = session.run.call_args[0][0]
    assert "MATCH (a:Alert)" in query
    assert "DETACH DELETE a" in query


def test_write_alerts_merges_on_alert_id():
    session = MagicMock()
    alerts = [{
        "alert_id": "score_change:abc123", "alert_type": "score_change", "path_id": "abc123",
        "old_score": 10.0, "new_score": 20.0, "old_rank": 10, "new_rank": 3,
        "source_cve": "CVE-X", "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }]

    written = write_alerts(session, alerts)

    assert written == 1
    query, kwargs = session.run.call_args
    assert "MERGE (a:Alert {alert_id: row.alert_id})" in query[0]
    assert "SET a += row" in query[0]
    [row] = kwargs["rows"]
    assert row["alert_id"] == "score_change:abc123"


def test_write_alerts_noop_on_empty_alerts():
    session = MagicMock()

    assert write_alerts(session, []) == 0
    session.run.assert_not_called()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_watchdog_writeback.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.watchdog.writeback'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/watchdog/writeback.py
"""Persists Watchdog diff results into Neo4j: one (:Alert) node per
detected change (see docs/superpowers/specs/2026-08-16-watchdog-design.md,
Alert node shape and write-back). MERGE-based, idempotent, consistent with
Agents 3-5's import pattern. No relationship to :AttackPath -- a
dropped_from_top50 alert's path may no longer have a node at all."""


def clear_previous_alerts(session) -> None:
    session.run("MATCH (a:Alert) DETACH DELETE a")


def write_alerts(session, alerts: list[dict]) -> int:
    if not alerts:
        return 0
    session.run(
        "UNWIND $rows AS row "
        "MERGE (a:Alert {alert_id: row.alert_id}) "
        "SET a += row",
        rows=alerts,
    )
    return len(alerts)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_watchdog_writeback.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/watchdog/writeback.py tests/test_watchdog_writeback.py
git commit -m "feat: add Alert node write-back to Neo4j (Agent 6)"
```

---

### Task 4: Orchestrator CLI (`scripts/watch_paths.py`)

**Files:**
- Create: `scripts/watch_paths.py`
- Test: `tests/test_watch_paths.py`

**Interfaces:**
- Consumes: `apply_kev_disclosure`, `apply_epss_spike`, `apply_new_topology_edge` (Task 1); `read_baseline_paths`, `diff_paths` (Task 2); `clear_previous_alerts`, `write_alerts` (Task 3); `extract_candidate_paths`, `dedupe_and_rank` (existing, `src/paths/extract.py`).
- Produces: `main() -> None`. Manual/CI entry point, mirroring `scripts/reason_paths.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_watch_paths.py
from unittest.mock import MagicMock, patch


def test_main_applies_scenarios_rescores_diffs_and_writes_alerts(monkeypatch, capsys):
    monkeypatch.setenv("NEO4J_PASSWORD", "test-password")
    fake_session = MagicMock()
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = fake_session

    baseline = {"old123": {
        "path_id": "old123", "score": 32.76, "rank": 6, "source_cve": "CVE-2021-26855",
        "source_asset_id": "computer-0078", "target_asset_id": "computer-0160",
    }}
    candidates = [{"cve_id": "CVE-2021-26855"}]
    routes = [{
        "node_ids": ["computer-0078", "computer-0160"], "score": 81.9, "rank": 1,
        "hop_count": 1, "source_cve": "CVE-2021-26855",
        "source_asset_id": "computer-0078", "target_asset_id": "computer-0160",
    }]
    alerts = [{"alert_id": "new_top50_entry:new456", "alert_type": "new_top50_entry", "path_id": "new456"}]

    with patch("scripts.watch_paths.GraphDatabase") as fake_gdb, \
         patch("scripts.watch_paths.apply_kev_disclosure", return_value={"cve_id": "CVE-2009-0133", "before": False, "after": True}) as fake_kev, \
         patch("scripts.watch_paths.apply_epss_spike", return_value={"cve_id": "CVE-2024-29988", "before": 0.45151, "after": 0.95}) as fake_epss, \
         patch("scripts.watch_paths.apply_new_topology_edge", return_value={"source_asset_id": "computer-0078", "target_asset_id": "computer-0160"}) as fake_edge, \
         patch("scripts.watch_paths.read_baseline_paths", return_value=baseline) as fake_read_baseline, \
         patch("scripts.watch_paths.extract_candidate_paths", return_value=candidates) as fake_extract, \
         patch("scripts.watch_paths.dedupe_and_rank", return_value=routes) as fake_rank, \
         patch("scripts.watch_paths.diff_paths", return_value=alerts) as fake_diff, \
         patch("scripts.watch_paths.clear_previous_alerts") as fake_clear, \
         patch("scripts.watch_paths.write_alerts", return_value=1) as fake_write:
        fake_gdb.driver.return_value = fake_driver

        from scripts.watch_paths import main
        main()

        fake_read_baseline.assert_called_once_with(fake_session)
        fake_kev.assert_called_once_with(fake_session)
        fake_epss.assert_called_once_with(fake_session)
        fake_edge.assert_called_once_with(fake_session)
        fake_extract.assert_called_once_with(fake_session)
        fake_rank.assert_called_once_with(candidates, top_n=50)
        fake_diff.assert_called_once_with(baseline, routes)
        fake_clear.assert_called_once_with(fake_session)
        fake_write.assert_called_once_with(fake_session, alerts)

    captured = capsys.readouterr()
    assert "kev_disclosure(CVE-2009-0133: False -> True)" in captured.out
    assert "epss_spike(CVE-2024-29988: 0.45151 -> 0.95)" in captured.out
    assert "new_topology_edge(computer-0078 -> computer-0160)" in captured.out
    assert "wrote 1 Alert node(s)" in captured.out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_watch_paths.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.watch_paths'`

- [ ] **Step 3: Write minimal implementation**

```python
# scripts/watch_paths.py
"""Runs the full Agent 6 (Watchdog) pipeline: apply the synthetic scenario
injector's 3 mutations -> re-extract/re-rank candidate paths (reusing Agent
4's src.paths.extract unmodified) -> diff against the persisted :AttackPath
baseline -> write results back into Neo4j as (:Alert) nodes. Does not
rewrite :AttackPath/:Reasoning -- see
docs/superpowers/specs/2026-08-16-watchdog-design.md, Scope."""
import os
import sys

sys.path.insert(0, ".")

from neo4j import GraphDatabase  # noqa: E402

from src.paths.extract import dedupe_and_rank, extract_candidate_paths  # noqa: E402
from src.watchdog.rescore import diff_paths, read_baseline_paths  # noqa: E402
from src.watchdog.scenario import (  # noqa: E402
    apply_epss_spike,
    apply_kev_disclosure,
    apply_new_topology_edge,
)
from src.watchdog.writeback import clear_previous_alerts, write_alerts  # noqa: E402

TOP_N = 50


def main() -> None:
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]

    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        baseline = read_baseline_paths(session)

        kev = apply_kev_disclosure(session)
        print(f"kev_disclosure({kev['cve_id']}: {kev['before']} -> {kev['after']})")
        epss = apply_epss_spike(session)
        print(f"epss_spike({epss['cve_id']}: {epss['before']} -> {epss['after']})")
        edge = apply_new_topology_edge(session)
        print(f"new_topology_edge({edge['source_asset_id']} -> {edge['target_asset_id']})")

        candidates = extract_candidate_paths(session)
        routes = dedupe_and_rank(candidates, top_n=TOP_N)
        alerts = diff_paths(baseline, routes)

        clear_previous_alerts(session)
        written = write_alerts(session, alerts)
    driver.close()

    by_type: dict[str, int] = {}
    for alert in alerts:
        by_type[alert["alert_type"]] = by_type.get(alert["alert_type"], 0) + 1
    breakdown = ", ".join(f"{count} {alert_type}" for alert_type, count in sorted(by_type.items()))
    print(f"Re-scored {len(routes)} route(s) against {len(baseline)} baseline path(s)")
    print(f"Alerts: {breakdown or 'none'} ({len(alerts)} total) -- wrote {written} Alert node(s)")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_watch_paths.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/watch_paths.py tests/test_watch_paths.py
git commit -m "feat: add Watchdog pipeline orchestrator (Agent 6)"
```

---

### Task 5: Contract 06 and agent doc (no new logic — handoff docs)

**Files:**
- Modify: `contracts/06_watchdog_to_qa.yaml` (currently empty placeholder)
- Modify: `agents/watchdog/prompt.md` (currently empty placeholder)

**Interfaces:** None (docs only).

- [ ] **Step 1: Write `contracts/06_watchdog_to_qa.yaml`**

```yaml
contract: 06_watchdog_to_qa
producer: watchdog
consumer: qa_docs

inputs:
  - path: contracts/05_baseline_to_watchdog.yaml
    description: The Neo4j graph, AttackPath/Reasoning baseline this phase reads and diffs against.

outputs:
  - path: Neo4j graph database (bolt://$NEO4J_URI, credentials in .env, see .env.example)
    description: >
      Annotated in place by scripts/watch_paths.py. New node label:
      (:Alert {alert_id, alert_type, path_id, old_score, new_score, old_rank,
      new_rank, source_cve, source_asset_id, target_asset_id}) -- one node
      per detected change, alert_type is one of "new_top50_entry",
      "score_change", "dropped_from_top50" (fixed set, see
      docs/superpowers/specs/2026-08-16-watchdog-design.md, Re-score + diff
      logic). alert_id = f"{alert_type}:{path_id}", the MERGE key. No
      relationship to :AttackPath -- a dropped_from_top50 alert's path may
      no longer have a corresponding node. Before writing alerts,
      scripts/watch_paths.py applies 3 deterministic synthetic scenario
      mutations (a KEV disclosure on CVE-2009-0133, an EPSS update on
      CVE-2024-29988, a new CONNECTS_TO edge computer-0078->computer-0160)
      standing in for a live feed -- this is a static synthetic dataset with
      no live feed (see design spec, Scope, for why and the upgrade path).
      :AttackPath and :Reasoning nodes are NOT rewritten by this phase --
      only the scenario mutation's own CVE/Asset/edge properties change; the
      persisted top-50 :AttackPath set and its :Reasoning annotations remain
      exactly as Agent 5 left them.
  - path: src/watchdog/{scenario,rescore,writeback}.py
    description: >
      Query module QA & Docs can import directly instead of writing its own
      Cypher: apply_kev_disclosure, apply_epss_spike, apply_new_topology_edge,
      read_baseline_paths, diff_paths, SCORE_CHANGE_THRESHOLD (0.20, fixed).

consumer_must_validate:
  - "Every (:Alert).alert_type is one of \"new_top50_entry\", \"score_change\", \"dropped_from_top50\"."
  - "new_top50_entry alerts have old_score/old_rank null and non-null new_score/new_rank; dropped_from_top50 alerts have the reverse; score_change alerts have all four non-null."
  - "Every (:Alert).alert_id is unique (the MERGE key)."
  - "(:AttackPath)/(:Reasoning) node counts and :EXPLAINED_BY edges are unchanged from Agent 5's handoff -- Watchdog does not rewrite them."

known_limitations:
  - >
    Exact alert counts depend on the top-50 cutoff cascade: a new
    high-scoring path entering the top 50 can push an unrelated, unmutated
    path out purely because the cap is 50, not because that path's own
    CVE/asset facts changed. QA should assert minimum expected alert counts
    per scenario mutation (e.g. at least 5 score_change alerts from the KEV
    disclosure, since CVE-2009-0133 sources 5 baseline top-50 paths), not
    exact totals.

handoff_status: ready
```

- [ ] **Step 2: Write `agents/watchdog/prompt.md`**

```markdown
# Agent: Watchdog

## Mission

Simulate a real-world graph change via a deterministic synthetic scenario
injector, re-score affected attack paths using Agent 4's scoring logic,
diff the result against the `:AttackPath` baseline Agent 5 left, and write
the changes back into the graph as `:Alert` nodes for QA & Docs to verify.

## Inputs

- The Neo4j graph handed off by `scripts/reason_paths.py` (per
  `contracts/05_baseline_to_watchdog.yaml`): 50 `:AttackPath` nodes, their
  linked `:Reasoning` nodes.
- `src/paths/extract.py`'s `extract_candidate_paths`/`dedupe_and_rank` --
  reused unmodified for re-scoring, not reimplemented.

## Outputs

- `src/watchdog/scenario.py`, `src/watchdog/rescore.py`,
  `src/watchdog/writeback.py`, `scripts/watch_paths.py`.
- `(:Alert)` nodes, one per detected change.
- `contracts/06_watchdog_to_qa.yaml` -- formal handoff to QA & Docs.

## Constraints

- No live feed -- `requirements.md` calls for "real-time edge monitoring",
  but this is a static synthetic dataset with no live feed. A deterministic
  synthetic scenario injector (3 fixed, parameterized Cypher mutations
  against real, already-existing CVE/Asset ids) stands in instead; no
  fabricated CVEs, assets, or topology facts (NFR2/NFR3).
- Does not rewrite `:AttackPath`/`:Reasoning` -- re-running Agent 4's
  writeback would sever Agent 5's `:EXPLAINED_BY` edges even for unchanged
  paths. Watchdog's rescoring is read-only analysis for diffing/alerting.
- Three fixed alert types only (`new_top50_entry`, `score_change` at a fixed
  20% threshold, `dropped_from_top50`) -- not configurable.
- Writes are idempotent (`MERGE` on `alert_id`; scenario mutations are
  `SET`/`MERGE`, safe to re-run), consistent with Agents 3-5's import
  pattern.

## Acceptance criteria

- [ ] `scripts/watch_paths.py` runs against a real Neo4j instance (the one
      `docker-compose.yml` provides, already populated by Agents 3-5) and
      exits 0.
- [ ] All 3 scenario mutations are applied and printed with before/after
      values.
- [ ] `:AttackPath`/`:Reasoning` node counts and `:EXPLAINED_BY` edges are
      unchanged after the run.
- [ ] At least one `:Alert` node of each of the 3 types exists after the
      run (the fixed scenario mutations are designed to trigger all three).
- [ ] `contracts/06_watchdog_to_qa.yaml` documents the `:Alert` shape and
      query module precisely enough for QA & Docs to consume them without
      reading this repo's Watchdog code.
```

- [ ] **Step 3: Verify the contract YAML still parses**

Run: `python3 -c "import yaml; yaml.safe_load(open('contracts/06_watchdog_to_qa.yaml')); print('ok')"`
Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add contracts/06_watchdog_to_qa.yaml agents/watchdog/prompt.md
git commit -m "docs: add Watchdog contract and agent prompt (Agent 6)"
```

---

### Task 6: Live run against the local Neo4j

**Files:** None tracked in git (`.env` is gitignored — this task only exercises already-committed code against a live database). **No commit for this task.**

**Interfaces:** None (verification task).

- [ ] **Step 1: Run the pipeline**

```bash
set -a; source .env; set +a
python3 scripts/watch_paths.py
```

Expected: prints the 3 mutation lines with before/after values matching the ones verified live during design (`kev_disclosure(CVE-2009-0133: False -> True)`, `epss_spike(CVE-2024-29988: 0.45151 -> 0.95)`, `new_topology_edge(computer-0078 -> computer-0160)`), then `Re-scored N route(s) against 50 baseline path(s)` and an `Alerts: ... -- wrote M Alert node(s)` line with `M > 0`.

- [ ] **Step 2: Verify results directly against the graph**

```bash
docker compose exec neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
  "MATCH (a:Alert) RETURN a.alert_type, count(*) ORDER BY a.alert_type;"
docker compose exec neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
  "MATCH (p:AttackPath) RETURN count(p) AS attack_path_count;"
docker compose exec neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
  "MATCH (p:AttackPath)-[:EXPLAINED_BY]->(r:Reasoning) RETURN count(r) AS still_linked;"
```

Expected: at least 5 `score_change` alerts (the 5 baseline paths sourced by `CVE-2009-0133`), at least 1 `new_top50_entry` and 1 `dropped_from_top50` (the `computer-0078`->`computer-0160` route pair). `attack_path_count` = 50 and `still_linked` = 50, unchanged from Agent 5's handoff -- confirming Watchdog did not touch `:AttackPath`/`:Reasoning`. Confirm idempotency by running the script a second time and checking the total `:Alert` count in Neo4j is unchanged (idempotent mutations, same diff).

No commit for this task — it verifies already-committed code against a live database; no tracked file changes.

---

## Out of scope for this plan

- Live threat-intel/topology feed integration (see design spec, Scope).
- A Watchdog dashboard page.
- Configurable/tunable alert thresholds.
- Re-running Reasoning Agent explanations for newly-entered paths.
- Rewriting the persisted `:AttackPath`/`:Reasoning` set to reflect post-mutation state.
