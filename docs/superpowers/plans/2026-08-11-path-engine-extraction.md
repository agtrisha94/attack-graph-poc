# Path Engine (Agent 4) Path Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Agent 4 (Path Engine) layer that queries Agent 3's Neo4j graph for routes from CVE-exploitable assets to Crown Jewel assets, deduplicates and scores them (CVSS x EPSS x criticality), computes blast radius and choke points per asset, writes the results back into the graph as `(:AttackPath)` nodes and `:Asset` properties — then hands off contract 04 and the agent's own prompt doc.

**Architecture:** Four small pure-function modules split by responsibility (`src/paths/score.py` for the scoring formula, `src/paths/extract.py` for the Cypher path query plus dedup/ranking, `src/paths/analysis.py` for blast radius and choke-point counting, `src/paths/writeback.py` for the `MERGE`/`SET` statements that persist results) and a thin orchestrator (`scripts/find_paths.py`) that wires them together against a real `neo4j.GraphDatabase` driver, mirroring `scripts/build_graph.py`. Unlike Agent 3's plan, a live local Neo4j is actually running in this environment, so the last task runs the real pipeline end-to-end against it.

**Tech Stack:** Python 3.11, `neo4j` 5.28.4 driver, pandas 3.0.3, pytest 9.1.1 (all already installed — no new dependency; no networkx, no APOC).

## Global Constraints

- **No new dependencies.** Path-finding uses Neo4j's native `allShortestPaths` variable-length traversal, not a Python-side graph library. Choke points are a plain frequency count, not APOC betweenness centrality (the local `neo4j:5-community` image doesn't have APOC installed).
- **Hop cap: 6.** Used identically in the path-extraction query and the blast-radius query (`*0..6`), verified directly against the live local Neo4j to accept a zero lower bound (covers an asset that is itself a Crown Jewel).
- **Deduplicate by physical route before ranking.** Group candidate `(cve, start, target)` rows by `(start_id, target_id, node_ids)` and collapse each group to one record, keeping the highest-scoring CVE as `source_cve`. Verified against the live synthetic data: the raw query returns 3396 candidate rows but only 143 distinct routes — 101 distinct start/target pairs, since some pairs have multiple tied-length shortest routes (one asset alone carries 140 exploitable CVEs) — without this, the top-50 set would be dominated by repeats of a couple of routes instead of showing route diversity.
- **Scoring:** `score = base_score * epss_score * CRITICALITY_WEIGHT[criticality_tier]`, where `CRITICALITY_WEIGHT = {"Crown Jewel": 4, "High": 3, "Medium": 2, "Low": 1}`.
- **Top 50.** Rank deduplicated routes by score descending and cap write-back to the top 50 (`rank` 1..50, dense, no gaps).
- **Idempotent writes.** Every write uses `MERGE`, never `CREATE` — `path_id` is a deterministic hash of a route's `node_ids` (not `cve_id`, since dedup already happened; not just `start_id`/`target_id`, since `allShortestPaths` can return multiple tied-length routes between the same pair).
- **No invented properties.** Every `:AttackPath` field and every new `:Asset` property (`blast_radius`, `choke_point_count`) traces to the design spec (`docs/superpowers/specs/2026-08-11-path-engine-design.md`) — no field beyond what's documented there.
- Follow TDD: write the failing test, confirm it fails, implement, confirm it passes, commit.
- A live local Neo4j (`neo4j:5-community`, via `docker-compose.yml`) is running in this environment (container `attack-graph-poc-neo4j-1`), already populated by Agent 3. Its actual password may not match the checked-in-format `.env` file — Task 7 syncs them before running the real pipeline.

---

## File Structure

- `src/paths/__init__.py` — empty, package marker.
- `src/paths/score.py` — `CRITICALITY_WEIGHT`, `score_path(base_score, epss_score, criticality_tier) -> float`.
- `src/paths/extract.py` — `PATH_QUERY`, `extract_candidate_paths(session) -> list[dict]`, `dedupe_and_rank(candidates, top_n=50) -> list[dict]`.
- `src/paths/analysis.py` — `BLAST_RADIUS_QUERY`, `extract_blast_radius(session) -> dict[str, int]`, `choke_point_counts(routes) -> dict[str, int]`.
- `src/paths/writeback.py` — `path_id_for(node_ids) -> str`, `write_attack_paths(session, routes) -> int`, `write_asset_metrics(session, blast_radius, choke_points) -> None`.
- `scripts/find_paths.py` — orchestrator CLI: connect, extract, dedupe/rank, analyze, write back, print summary.
- `contracts/04_paths_to_reasoning.yaml` — Agent 4's handoff to the Reasoning Agent.
- `agents/path_engine/prompt.md` — Agent 4's mission doc, same format as `agents/graph_architect/prompt.md`.
- `tests/test_paths_score.py`, `tests/test_paths_extract.py`, `tests/test_paths_analysis.py`, `tests/test_paths_writeback.py`, `tests/test_find_paths.py`.

---

### Task 1: Scoring formula (`src/paths/score.py`)

**Files:**
- Create: `src/paths/__init__.py` (empty)
- Create: `src/paths/score.py`
- Test: `tests/test_paths_score.py`

**Interfaces:**
- Produces: `CRITICALITY_WEIGHT: dict[str, int]`, `score_path(base_score: float, epss_score: float, criticality_tier: str) -> float`. Consumed by Task 2 (`extract.py`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_paths_score.py
import pytest

from src.paths.score import CRITICALITY_WEIGHT, score_path


def test_criticality_weight_covers_all_four_tiers():
    assert CRITICALITY_WEIGHT == {"Crown Jewel": 4, "High": 3, "Medium": 2, "Low": 1}


def test_score_path_multiplies_cvss_epss_and_criticality_weight():
    assert score_path(9.8, 0.94, "Crown Jewel") == pytest.approx(9.8 * 0.94 * 4)
    assert score_path(9.8, 0.94, "High") == pytest.approx(9.8 * 0.94 * 3)
    assert score_path(9.8, 0.94, "Medium") == pytest.approx(9.8 * 0.94 * 2)
    assert score_path(9.8, 0.94, "Low") == pytest.approx(9.8 * 0.94 * 1)


def test_score_path_zero_cvss_yields_zero_score():
    assert score_path(0.0, 0.94, "Crown Jewel") == 0.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_paths_score.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.paths'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/paths/score.py
"""CVSS x EPSS x criticality scoring formula for attack-path ranking (see
docs/superpowers/specs/2026-08-11-path-engine-design.md, Scoring)."""

CRITICALITY_WEIGHT: dict[str, int] = {
    "Crown Jewel": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}


def score_path(base_score: float, epss_score: float, criticality_tier: str) -> float:
    return base_score * epss_score * CRITICALITY_WEIGHT[criticality_tier]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_paths_score.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/paths/__init__.py src/paths/score.py tests/test_paths_score.py
git commit -m "feat: add attack-path scoring formula (Agent 4)"
```

---

### Task 2: Path extraction and route dedup (`src/paths/extract.py`)

**Files:**
- Create: `src/paths/extract.py`
- Test: `tests/test_paths_extract.py`

**Interfaces:**
- Consumes: `score_path` from Task 1 (`src.paths.score`).
- Produces: `PATH_QUERY: str`, `extract_candidate_paths(session) -> list[dict]` (each dict has keys `cve_id`, `base_score`, `epss_score`, `start_id`, `target_id`, `target_criticality`, `node_ids`, `hop_count`), `dedupe_and_rank(candidates: list[dict], top_n: int = 50) -> list[dict]` (each returned dict has keys `score`, `hop_count`, `source_cve`, `source_asset_id`, `target_asset_id`, `node_ids`, `rank`). Consumed by Task 5 (`scripts/find_paths.py`) and by Task 3's `choke_point_counts` (which takes this shape as input).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_paths_extract.py
from unittest.mock import MagicMock

from src.paths.extract import PATH_QUERY, dedupe_and_rank, extract_candidate_paths
from src.paths.score import score_path


def _candidate(cve_id, base_score, epss_score, start_id, target_id, node_ids, hop_count):
    return {
        "cve_id": cve_id, "base_score": base_score, "epss_score": epss_score,
        "start_id": start_id, "target_id": target_id, "target_criticality": "Crown Jewel",
        "node_ids": node_ids, "hop_count": hop_count,
    }


def test_path_query_uses_hop_cap_edge_types_and_crown_jewel_target():
    assert "allShortestPaths" in PATH_QUERY
    assert "AFFECTS" in PATH_QUERY
    assert "*0..6" in PATH_QUERY
    assert "RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS" in PATH_QUERY
    assert "Crown Jewel" in PATH_QUERY


def test_extract_candidate_paths_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [_candidate("CVE-1", 8.8, 0.5, "computer-0001", "group-0033",
                        ["computer-0001", "computer-0018", "group-0033"], 2)]
    session.run.return_value = rows

    result = extract_candidate_paths(session)

    assert result == rows
    session.run.assert_called_once_with(PATH_QUERY)


def test_dedupe_and_rank_keeps_max_scoring_cve_per_physical_route():
    candidates = [
        _candidate("CVE-LOW", 2.0, 0.1, "computer-0001", "group-0033",
                   ["computer-0001", "computer-0018", "group-0033"], 2),
        _candidate("CVE-HIGH", 9.8, 0.9, "computer-0001", "group-0033",
                   ["computer-0001", "computer-0018", "group-0033"], 2),
    ]

    routes = dedupe_and_rank(candidates, top_n=50)

    assert len(routes) == 1
    assert routes[0]["source_cve"] == "CVE-HIGH"
    assert routes[0]["score"] == score_path(9.8, 0.9, "Crown Jewel")
    assert routes[0]["rank"] == 1
    assert routes[0]["node_ids"] == ["computer-0001", "computer-0018", "group-0033"]


def test_dedupe_and_rank_treats_different_hop_sequences_as_distinct_routes():
    candidates = [
        _candidate("CVE-A", 5.0, 0.5, "computer-0001", "group-0033",
                   ["computer-0001", "computer-0018", "group-0033"], 2),
        _candidate("CVE-B", 5.0, 0.5, "computer-0001", "group-0033",
                   ["computer-0001", "computer-0099", "group-0033"], 2),
    ]

    routes = dedupe_and_rank(candidates, top_n=50)

    assert len(routes) == 2


def test_dedupe_and_rank_caps_to_top_n_by_score_descending():
    candidates = [
        _candidate(f"CVE-{i}", float(i), 1.0, f"asset-{i}", "group-0033",
                   [f"asset-{i}", "group-0033"], 1)
        for i in range(1, 6)
    ]

    routes = dedupe_and_rank(candidates, top_n=3)

    assert [r["source_cve"] for r in routes] == ["CVE-5", "CVE-4", "CVE-3"]
    assert [r["rank"] for r in routes] == [1, 2, 3]


def test_dedupe_and_rank_empty_input_returns_empty_list():
    assert dedupe_and_rank([], top_n=50) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_paths_extract.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.paths.extract'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/paths/extract.py
"""Queries Agent 3's Neo4j graph for routes from CVE-exploitable assets to
Crown Jewel assets, then deduplicates by physical route (start, target, hop
sequence) and ranks by score before capping to the top N (see
docs/superpowers/specs/2026-08-11-path-engine-design.md, Path extraction --
the raw query returns far more (cve, start, target) rows than distinct
routes, since one asset can carry many exploitable CVEs)."""
from src.paths.score import score_path

PATH_QUERY = """
MATCH (cve:CVE)-[:AFFECTS]->(start:Asset)
MATCH p = allShortestPaths(
  (start)-[:RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS*0..6]-(target:Asset {criticality_tier: 'Crown Jewel'})
)
RETURN cve.cve_id AS cve_id, cve.base_score AS base_score, cve.epss_score AS epss_score,
       start.node_id AS start_id, target.node_id AS target_id,
       target.criticality_tier AS target_criticality,
       [n IN nodes(p) | n.node_id] AS node_ids, length(p) AS hop_count
""".strip()


def extract_candidate_paths(session) -> list[dict]:
    return [dict(record) for record in session.run(PATH_QUERY)]


def dedupe_and_rank(candidates: list[dict], top_n: int = 50) -> list[dict]:
    best_by_route: dict[tuple, dict] = {}
    for c in candidates:
        route_key = (c["start_id"], c["target_id"], tuple(c["node_ids"]))
        score = score_path(c["base_score"], c["epss_score"], c["target_criticality"])
        existing = best_by_route.get(route_key)
        if existing is None or score > existing["score"]:
            best_by_route[route_key] = {
                "score": score,
                "hop_count": c["hop_count"],
                "source_cve": c["cve_id"],
                "source_asset_id": c["start_id"],
                "target_asset_id": c["target_id"],
                "node_ids": c["node_ids"],
            }

    ranked = sorted(best_by_route.values(), key=lambda r: r["score"], reverse=True)[:top_n]
    for i, route in enumerate(ranked, start=1):
        route["rank"] = i
    return ranked
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_paths_extract.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/paths/extract.py tests/test_paths_extract.py
git commit -m "feat: add attack-path extraction and route dedup (Agent 4)"
```

---

### Task 3: Blast radius and choke points (`src/paths/analysis.py`)

**Files:**
- Create: `src/paths/analysis.py`
- Test: `tests/test_paths_analysis.py`

**Interfaces:**
- Consumes: nothing directly from Tasks 1-2 (`extract_blast_radius` queries the graph independently; `choke_point_counts` takes the `node_ids`-bearing route dicts `dedupe_and_rank` produces, by shape convention, not by import).
- Produces: `BLAST_RADIUS_QUERY: str`, `extract_blast_radius(session) -> dict[str, int]` (asset_id -> reachable count), `choke_point_counts(routes: list[dict]) -> dict[str, int]` (asset_id -> count of top-N routes it's an intermediate hop on, only entries with count > 1). Consumed by Task 5.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_paths_analysis.py
from unittest.mock import MagicMock

from src.paths.analysis import BLAST_RADIUS_QUERY, choke_point_counts, extract_blast_radius


def test_blast_radius_query_excludes_self_and_uses_hop_cap():
    assert "*0..6" in BLAST_RADIUS_QUERY
    assert "reachable <> start" in BLAST_RADIUS_QUERY
    assert "AFFECTS" in BLAST_RADIUS_QUERY


def test_extract_blast_radius_returns_asset_id_to_count_mapping():
    session = MagicMock()
    session.run.return_value = [
        {"asset_id": "computer-0002", "blast_radius": 14},
        {"asset_id": "computer-0005", "blast_radius": 3},
    ]

    result = extract_blast_radius(session)

    assert result == {"computer-0002": 14, "computer-0005": 3}
    session.run.assert_called_once_with(BLAST_RADIUS_QUERY)


def test_choke_point_counts_flags_assets_on_more_than_one_route():
    routes = [
        {"node_ids": ["computer-0001", "hub", "group-0033"]},
        {"node_ids": ["computer-0002", "hub", "group-0034"]},
        {"node_ids": ["computer-0003", "other", "group-0035"]},
    ]

    counts = choke_point_counts(routes)

    assert counts == {"hub": 2}


def test_choke_point_counts_excludes_source_and_target_endpoints():
    routes = [
        {"node_ids": ["computer-0001", "group-0033"]},
        {"node_ids": ["computer-0001", "group-0033"]},
    ]

    assert choke_point_counts(routes) == {}


def test_choke_point_counts_counts_each_route_at_most_once_per_asset():
    # A route whose hop sequence happens to repeat a node should not let that
    # single route count twice toward the >1-route threshold.
    routes = [{"node_ids": ["a", "hub", "hub", "b"]}]

    assert choke_point_counts(routes) == {}


def test_choke_point_counts_empty_routes_returns_empty_dict():
    assert choke_point_counts([]) == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_paths_analysis.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.paths.analysis'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/paths/analysis.py
"""Per-asset blast radius (reachable-asset count) and choke-point frequency
(how many top-N routes an asset sits on as an intermediate hop) -- see
docs/superpowers/specs/2026-08-11-path-engine-design.md, Blast radius &
choke points. No APOC: the local Neo4j Community image doesn't have it
installed, so choke points are a plain frequency count, not betweenness
centrality."""

BLAST_RADIUS_QUERY = """
MATCH (cve:CVE)-[:AFFECTS]->(start:Asset)
WITH DISTINCT start
MATCH (start)-[:RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS*0..6]-(reachable:Asset)
WHERE reachable <> start
RETURN start.node_id AS asset_id, count(DISTINCT reachable) AS blast_radius
""".strip()


def extract_blast_radius(session) -> dict[str, int]:
    return {r["asset_id"]: r["blast_radius"] for r in session.run(BLAST_RADIUS_QUERY)}


def choke_point_counts(routes: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for route in routes:
        intermediate = set(route["node_ids"][1:-1])
        for asset_id in intermediate:
            counts[asset_id] = counts.get(asset_id, 0) + 1
    return {asset_id: count for asset_id, count in counts.items() if count > 1}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_paths_analysis.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/paths/analysis.py tests/test_paths_analysis.py
git commit -m "feat: add blast radius and choke point analysis (Agent 4)"
```

---

### Task 4: Write-back (`src/paths/writeback.py`)

**Files:**
- Create: `src/paths/writeback.py`
- Test: `tests/test_paths_writeback.py`

**Interfaces:**
- Consumes: nothing directly (takes the route dicts `dedupe_and_rank` produces and the mappings `extract_blast_radius`/`choke_point_counts` produce, by shape convention).
- Produces: `path_id_for(node_ids: list[str]) -> str`, `write_attack_paths(session, routes: list[dict]) -> int`, `write_asset_metrics(session, blast_radius: dict[str, int], choke_points: dict[str, int]) -> None`. Consumed by Task 5.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_paths_writeback.py
from unittest.mock import MagicMock

from src.paths.writeback import path_id_for, write_asset_metrics, write_attack_paths


def test_path_id_for_is_deterministic_and_order_sensitive():
    forward = path_id_for(["x", "y", "z"])
    forward_again = path_id_for(["x", "y", "z"])
    reversed_ = path_id_for(["z", "y", "x"])

    assert forward == forward_again
    assert forward != reversed_


def test_write_attack_paths_merges_on_path_id_with_route_fields():
    session = MagicMock()
    routes = [{
        "score": 36.85, "hop_count": 2, "source_cve": "CVE-1",
        "source_asset_id": "computer-0001", "target_asset_id": "group-0033",
        "node_ids": ["computer-0001", "computer-0018", "group-0033"], "rank": 1,
    }]

    written = write_attack_paths(session, routes)

    assert written == 1
    query, kwargs = session.run.call_args
    assert "MERGE (p:AttackPath {path_id: row.path_id})" in query[0]
    [row] = kwargs["rows"]
    assert row["path_id"] == path_id_for(routes[0]["node_ids"])
    assert row["source_cve"] == "CVE-1"
    assert row["rank"] == 1


def test_write_attack_paths_noop_on_empty_routes():
    session = MagicMock()

    assert write_attack_paths(session, []) == 0
    session.run.assert_not_called()


def test_write_asset_metrics_sets_blast_radius_and_choke_point_count():
    session = MagicMock()

    write_asset_metrics(session, {"computer-0002": 14}, {"computer-0018": 2})

    queries = [call.args[0] for call in session.run.call_args_list]
    assert any("a.blast_radius = row.blast_radius" in q for q in queries)
    assert any("a.choke_point_count = row.choke_point_count" in q for q in queries)


def test_write_asset_metrics_skips_run_when_both_mappings_empty():
    session = MagicMock()

    write_asset_metrics(session, {}, {})

    session.run.assert_not_called()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_paths_writeback.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.paths.writeback'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/paths/writeback.py
"""Persists Path Engine results into Neo4j: one (:AttackPath) node per
ranked route, plus blast_radius/choke_point_count properties on :Asset (see
docs/superpowers/specs/2026-08-11-path-engine-design.md, Write-back model).
All writes use MERGE/SET on existing keys -- idempotent, consistent with
Agent 3's import pattern (src/graph/importer.py)."""
import hashlib


def path_id_for(node_ids: list[str]) -> str:
    return hashlib.sha256("|".join(node_ids).encode()).hexdigest()[:16]


def write_attack_paths(session, routes: list[dict]) -> int:
    if not routes:
        return 0
    rows = [{**route, "path_id": path_id_for(route["node_ids"])} for route in routes]
    session.run(
        "UNWIND $rows AS row "
        "MERGE (p:AttackPath {path_id: row.path_id}) "
        "SET p += row",
        rows=rows,
    )
    return len(rows)


def write_asset_metrics(session, blast_radius: dict[str, int], choke_points: dict[str, int]) -> None:
    if blast_radius:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (a:Asset {node_id: row.node_id}) "
            "SET a.blast_radius = row.blast_radius",
            rows=[{"node_id": k, "blast_radius": v} for k, v in blast_radius.items()],
        )
    if choke_points:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (a:Asset {node_id: row.node_id}) "
            "SET a.choke_point_count = row.choke_point_count",
            rows=[{"node_id": k, "choke_point_count": v} for k, v in choke_points.items()],
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_paths_writeback.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/paths/writeback.py tests/test_paths_writeback.py
git commit -m "feat: add attack-path write-back to Neo4j (Agent 4)"
```

---

### Task 5: Orchestrator CLI (`scripts/find_paths.py`)

**Files:**
- Create: `scripts/find_paths.py`
- Test: `tests/test_find_paths.py`

**Interfaces:**
- Consumes: `extract_candidate_paths`, `dedupe_and_rank` (Task 2); `extract_blast_radius`, `choke_point_counts` (Task 3); `write_attack_paths`, `write_asset_metrics` (Task 4).
- Produces: `main() -> None`. Nothing downstream in this plan consumes it directly — it's the manual/CI entry point, mirroring `scripts/build_graph.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_find_paths.py
from unittest.mock import MagicMock, patch


def test_main_extracts_dedupes_analyzes_and_writes_back(monkeypatch, capsys):
    monkeypatch.setenv("NEO4J_PASSWORD", "test-password")
    fake_session = MagicMock()
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = fake_session

    candidates = [{"cve_id": "CVE-1"}]
    routes = [{"node_ids": ["a", "b"], "score": 10.0, "rank": 1}]

    with patch("scripts.find_paths.GraphDatabase") as fake_gdb, \
         patch("scripts.find_paths.extract_candidate_paths", return_value=candidates) as fake_extract, \
         patch("scripts.find_paths.dedupe_and_rank", return_value=routes) as fake_dedupe, \
         patch("scripts.find_paths.extract_blast_radius", return_value={"a": 5}) as fake_blast, \
         patch("scripts.find_paths.choke_point_counts", return_value={}) as fake_choke, \
         patch("scripts.find_paths.write_attack_paths", return_value=1) as fake_write_paths, \
         patch("scripts.find_paths.write_asset_metrics") as fake_write_metrics:
        fake_gdb.driver.return_value = fake_driver

        from scripts.find_paths import main
        main()

        fake_extract.assert_called_once_with(fake_session)
        fake_dedupe.assert_called_once_with(candidates, top_n=50)
        fake_blast.assert_called_once_with(fake_session)
        fake_choke.assert_called_once_with(routes)
        fake_write_paths.assert_called_once_with(fake_session, routes)
        fake_write_metrics.assert_called_once_with(fake_session, {"a": 5}, {})

    captured = capsys.readouterr()
    assert "1 candidate" in captured.out
    assert "1 distinct route" in captured.out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_find_paths.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.find_paths'`

- [ ] **Step 3: Write minimal implementation**

```python
# scripts/find_paths.py
"""Runs the full Agent 4 (Path Engine) pipeline: extract candidate paths ->
dedupe/rank into routes -> compute blast radius/choke points -> write
results back into Neo4j as (:AttackPath) nodes and :Asset properties."""
import os
import sys

sys.path.insert(0, ".")

from neo4j import GraphDatabase  # noqa: E402

from src.paths.analysis import choke_point_counts, extract_blast_radius  # noqa: E402
from src.paths.extract import dedupe_and_rank, extract_candidate_paths  # noqa: E402
from src.paths.writeback import write_asset_metrics, write_attack_paths  # noqa: E402

TOP_N = 50


def main() -> None:
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]

    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        candidates = extract_candidate_paths(session)
        routes = dedupe_and_rank(candidates, top_n=TOP_N)
        blast_radius = extract_blast_radius(session)
        choke_points = choke_point_counts(routes)
        written = write_attack_paths(session, routes)
        write_asset_metrics(session, blast_radius, choke_points)
    driver.close()

    print(f"Extracted {len(candidates)} candidate paths, deduplicated to {len(routes)} distinct route(s), wrote {written} AttackPath node(s)")
    print(f"Blast radius computed for {len(blast_radius)} asset(s); {len(choke_points)} choke point(s) found")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_find_paths.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/find_paths.py tests/test_find_paths.py
git commit -m "feat: add Path Engine pipeline orchestrator (Agent 4)"
```

---

### Task 6: Contract 04 and agent doc (no new logic — handoff docs)

**Files:**
- Modify: `contracts/04_paths_to_reasoning.yaml` (currently empty placeholder)
- Modify: `agents/path_engine/prompt.md` (currently empty placeholder)

**Interfaces:** None (docs only — no function signatures produced or consumed).

- [ ] **Step 1: Write `contracts/04_paths_to_reasoning.yaml`**

```yaml
contract: 04_paths_to_reasoning
producer: path_engine
consumer: reasoning_agent

inputs:
  - path: contracts/03_graph_to_paths.yaml
    description: The Neo4j graph this phase queries and annotates.

outputs:
  - path: Neo4j graph database (bolt://$NEO4J_URI, credentials in .env, see .env.example)
    description: >
      Annotated in place by scripts/find_paths.py. New node label:
      (:AttackPath {path_id, score, hop_count, source_cve, source_asset_id,
      target_asset_id, node_ids: list[string], rank}) -- one node per
      deduplicated route from a CVE-exploitable :Asset to a Crown Jewel
      :Asset, top 50 by score, rank 1..50 (dense, no gaps). node_ids is the
      ordered hop sequence; resolve each entry against :Asset.node_id to get
      the actual asset chain (modeled as a property array rather than
      relationships -- see docs/superpowers/specs/2026-08-11-path-engine-design.md,
      Write-back model, for why). New :Asset properties: blast_radius (int,
      count of distinct assets reachable from this asset via topology edges,
      hop-capped at 6; present only on assets with >=1 exploitable CVE and
      >=1 reachable neighbor) and choke_point_count (int, number of top-50
      routes this asset appears on as an intermediate hop; present only when
      greater than 1).
  - path: src/paths/{score,extract,analysis,writeback}.py
    description: >
      Query module the Reasoning Agent can import directly instead of
      writing its own Cypher: score_path, extract_candidate_paths,
      dedupe_and_rank, extract_blast_radius, choke_point_counts.

consumer_must_validate:
  - Every (:AttackPath).node_ids entry resolves to an existing (:Asset {node_id}).
  - (:AttackPath).score is non-null and reproducible as base_score * epss_score * criticality_weight (Crown Jewel=4, High=3, Medium=2, Low=1), reading base_score/epss_score from the (:CVE {cve_id: source_cve}) and criticality_tier from the (:Asset {node_id: target_asset_id}).
  - (:AttackPath).rank is a dense 1..N ordering by score descending within the top-50 set.
  - (:Asset).blast_radius and (:Asset).choke_point_count, where present, are non-negative integers.

handoff_status: ready
```

- [ ] **Step 2: Write `agents/path_engine/prompt.md`**

```markdown
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
  rows collapse to 143 distinct routes -- 101 distinct start/target pairs,
  since some pairs have multiple tied-length shortest routes).
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
```

- [ ] **Step 3: Verify the contract YAML still parses**

Run: `python3 -c "import yaml; yaml.safe_load(open('contracts/04_paths_to_reasoning.yaml')); print('ok')"`
Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add contracts/04_paths_to_reasoning.yaml agents/path_engine/prompt.md
git commit -m "docs: add Path Engine contract and agent prompt (Agent 4)"
```

---

### Task 7: Live run against the local Neo4j

**Files:** None tracked in git (`.env` is gitignored — this task syncs local dev state, not repo content).

**Interfaces:** None (verification task).

- [ ] **Step 1: Sync `.env` to the running container's actual password**

```bash
CONTAINER=$(docker compose ps -q neo4j)
if [ -n "$CONTAINER" ]; then
  REAL_PW=$(docker inspect "$CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep ^NEO4J_AUTH= | cut -d/ -f2)
  [ -f .env ] || cp .env.example .env
  sed -i.bak "s/^NEO4J_PASSWORD=.*/NEO4J_PASSWORD=${REAL_PW}/" .env && rm .env.bak
else
  [ -f .env ] || cp .env.example .env
  docker compose up -d
fi
```

Expected: `.env`'s `NEO4J_PASSWORD` now matches the running container (or a fresh container just started using `.env`'s password).

- [ ] **Step 2: Run the full pipeline (idempotent re-import, then path extraction)**

```bash
set -a; source .env; set +a
python3 scripts/build_graph.py
python3 scripts/find_paths.py
```

Expected: `build_graph.py` prints `PASSED: graph import satisfies contract 02/03`; `find_paths.py` prints two summary lines ending `... wrote N AttackPath node(s)` (N <= 50) and `... M choke point(s) found`.

- [ ] **Step 3: Verify results directly against the graph**

```bash
docker compose exec neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
  "MATCH (p:AttackPath) RETURN count(p) AS attack_paths, min(p.rank) AS min_rank, max(p.rank) AS max_rank;"
docker compose exec neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
  "MATCH (a:Asset) WHERE a.blast_radius IS NOT NULL RETURN count(a) AS assets_with_blast_radius;"
```

Expected: `attack_paths` <= 50 with `min_rank` = 1 and `max_rank` = `attack_paths` (dense ranking); `assets_with_blast_radius` > 0.

No commit for this task — it verifies already-committed code against a live database; no tracked file changes.

---

## Out of scope for this plan

- Entry-point/internet-facing modeling, or an identity-only (User/HAS_SESSION) path-analysis mode (see design spec, Out of scope).
- APOC-based betweenness centrality for choke points.
- Real-time/incremental re-scoring on graph change -- that's Agent 6 (Watchdog).
- LLM-powered explanation of the extracted paths -- that's Agent 5 (Reasoning Agent), scoped by `contracts/04_paths_to_reasoning.yaml`.
