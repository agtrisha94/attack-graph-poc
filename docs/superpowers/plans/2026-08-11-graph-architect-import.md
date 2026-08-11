# Graph Architect (Agent 3) Neo4j Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Agent 3 (Graph Architect) Neo4j import layer that loads Agent 2's four processed/synthetic CSVs into a graph (CVE, Technique, Asset nodes; topology, AFFECTS, and MAPS_TO relationships), applies uniqueness constraints derived from `schemas/data_schema.yaml`, and validates the loaded graph — then hand off contracts 02/03 and the agent's own prompt doc.

**Architecture:** Two small modules split by responsibility (`src/graph/schema.py` for constraints/indexes, `src/graph/importer.py` for CSV→Cypher param-building plus the MERGE statements that load them) and a validator (`src/graph/validate.py`) that mirrors the existing `src/ingestion/validate.py` pattern (pure function returning a list of violation strings, plus a `main()` that exits non-zero). A thin orchestrator (`scripts/build_graph.py`) wires them together against a real `neo4j.GraphDatabase` driver, mirroring `scripts/build_dataset.py`. A `docker-compose.yml` provides the local Neo4j instance to run it against.

**Tech Stack:** Python 3.11, `neo4j` 6.2.0 Python driver (already installed, verified via `pip3 show neo4j`), pandas 3.0.3, pytest 9.1.1 (all already installed — no new dependency). Docker/Neo4j itself is NOT available in this sandbox (`docker` command not found) — see Global Constraints.

## Global Constraints

- **No live Neo4j in this sandbox.** `docker` is not installed here, so `scripts/build_graph.py` cannot be executed end-to-end during this plan. All unit tests use `unittest.mock.MagicMock()` as a fake driver session and assert on the Cypher text/params passed to `session.run(...)` — no test in this plan requires a real database. `docker-compose.yml` is provided so the user can run the real import locally.
- **Neo4j Community Edition, not Enterprise.** Property existence constraints (`REQUIRE ... IS NOT NULL`) and relationship key/uniqueness constraints are Enterprise-only. Only node uniqueness constraints and indexes are used at the DB level; "every required field is present" is enforced instead as a post-import Cypher check in `src/graph/validate.py` — this is the constraint-validation FR5 in `requirements.md` asks for, not a DB-level existence constraint.
- Every node label, relationship type, and property name must trace to a field already defined in `schemas/data_schema.yaml` or to the enum values already present in the CSVs on disk (`node_type`, `edge_type`) — no invented properties (NFR2/NFR3 carry through from `requirements.md`).
- Import is idempotent: every write uses `MERGE`, never `CREATE`, so `scripts/build_graph.py` can be re-run safely against the same database.
- `installed_software` → CVE `product` matching is **exact, case-insensitive, split on `;`** — this matches how `src/generator/topology.py` populates `installed_software` directly from `microsoft_cve_master.product`'s unique values (see `topology.py:60-73`), so no fuzzy matching is needed or wanted.
- `technique_map.tactic` is comma-space-delimited (`"stealth, privilege-escalation"`, per `technique_map.py:24-27`) and must be split into a list on import. `technique_map.cwe_ids` is **always empty** in the current dataset (documented `ponytail:` gap in `technique_map.py:31-33` — no CWE↔ATT&CK bridge exists yet in `data/raw/`); the `MAPS_TO` relationship-building code must still exist and be correct, it will just produce zero relationships until that gap is closed upstream. Use `;` as the list delimiter for `cwe_ids` (consistent with `installed_software`'s convention) if/when it is populated.
- Relationship types cannot be parameterized in Cypher — `edge_type` (topology) is a closed enum already validated by Agent 2 (`RUNS, CONNECTS_TO, MEMBER_OF, HAS_SESSION, CONTROLS`), so it is safe to interpolate directly into the query string (grouped by type, one query per type, never per-row string building from unvalidated input).
- Follow TDD: write the failing test, confirm it fails, implement, confirm it passes, commit.

---

## File Structure

- `src/graph/__init__.py` — empty, package marker.
- `src/graph/schema.py` — Cypher constraint/index statements + `apply_schema(session)`.
- `src/graph/importer.py` — pure CSV→param builder functions plus `import_graph(session, processed_dir, synthetic_dir)`.
- `src/graph/validate.py` — post-import validation, mirrors `src/ingestion/validate.py`.
- `scripts/build_graph.py` — orchestrator CLI: connect, apply schema, import, validate, exit non-zero on failure.
- `docker-compose.yml` — local Neo4j 5 Community for manual/dev use.
- `.env.example` — documents `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD`.
- `contracts/02_data_to_graph.yaml` — backfilled (Agent 2 never wrote its handoff; Agent 3 documents the CSVs it actually consumes).
- `contracts/03_graph_to_paths.yaml` — Agent 3's own handoff to Agent 4 (Path Engine).
- `agents/graph_architect/prompt.md` — Agent 3's mission doc, same format as `agents/requirements_architect/prompt.md`.
- `tests/test_graph_schema.py`, `tests/test_graph_importer.py`, `tests/test_graph_validate.py`, `tests/test_build_graph.py`.

---

### Task 1: Constraints and indexes (`src/graph/schema.py`)

**Files:**
- Create: `src/graph/__init__.py` (empty)
- Create: `src/graph/schema.py`
- Test: `tests/test_graph_schema.py`

**Interfaces:**
- Produces: `SCHEMA_STATEMENTS: list[str]`, `apply_schema(session) -> None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_graph_schema.py
from unittest.mock import MagicMock

from src.graph.schema import SCHEMA_STATEMENTS, apply_schema


def test_schema_statements_cover_unique_keys_and_product_index():
    joined = " ".join(SCHEMA_STATEMENTS)
    assert "FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE" in joined
    assert "FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE" in joined
    assert "FOR (a:Asset) REQUIRE a.node_id IS UNIQUE" in joined
    assert "FOR (c:CVE) ON (c.product)" in joined
    assert all("IF NOT EXISTS" in s for s in SCHEMA_STATEMENTS)


def test_apply_schema_runs_every_statement():
    session = MagicMock()
    apply_schema(session)
    executed = [call.args[0] for call in session.run.call_args_list]
    assert executed == SCHEMA_STATEMENTS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_graph_schema.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.graph'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/graph/schema.py
"""Neo4j constraints/indexes derived from schemas/data_schema.yaml primary
keys. Community Edition has no property-existence constraints; required-field
enforcement lives in src/graph/validate.py instead."""

SCHEMA_STATEMENTS: list[str] = [
    "CREATE CONSTRAINT cve_id_unique IF NOT EXISTS "
    "FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE",
    "CREATE CONSTRAINT technique_id_unique IF NOT EXISTS "
    "FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE",
    "CREATE CONSTRAINT asset_node_id_unique IF NOT EXISTS "
    "FOR (a:Asset) REQUIRE a.node_id IS UNIQUE",
    "CREATE INDEX cve_product_index IF NOT EXISTS "
    "FOR (c:CVE) ON (c.product)",
]


def apply_schema(session) -> None:
    for statement in SCHEMA_STATEMENTS:
        session.run(statement)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_graph_schema.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/graph/__init__.py src/graph/schema.py tests/test_graph_schema.py
git commit -m "feat: add Neo4j constraint/index schema (Agent 3)"
```

---

### Task 2: CSV → Cypher param builders (`src/graph/importer.py`, pure functions)

**Files:**
- Create: `src/graph/importer.py`
- Test: `tests/test_graph_importer.py`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `cve_params(df: pd.DataFrame) -> list[dict]`, `technique_params(df: pd.DataFrame) -> list[dict]`, `asset_params(df: pd.DataFrame) -> list[dict]`, `topology_edge_params(df: pd.DataFrame) -> dict[str, list[dict]]` (keyed by `edge_type`), `affects_params(cve_df: pd.DataFrame, nodes_df: pd.DataFrame) -> list[dict]`, `maps_to_params(cve_df: pd.DataFrame, technique_df: pd.DataFrame) -> list[dict]`. These are consumed by Task 3.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_graph_importer.py
import pandas as pd

from src.graph.importer import (
    cve_params, technique_params, asset_params,
    topology_edge_params, affects_params, maps_to_params,
)


def test_cve_params_converts_nan_to_none():
    df = pd.DataFrame([
        {"cve_id": "CVE-2026-0001", "vendor": "microsoft", "product": "exchange server",
         "description": "RCE", "cwe_id": None, "base_severity": "HIGH", "base_score": 8.8,
         "attack_vector": "NETWORK", "epss_score": 0.5, "epss_percentile": 0.9,
         "kev_flag": True, "kev_date_added": "2026-01-05", "ransomware_used": "Known",
         "published_date": "2026-01-01"},
    ])
    [params] = cve_params(df)
    assert params["cve_id"] == "CVE-2026-0001"
    assert params["cwe_id"] is None
    assert params["kev_flag"] is True


def test_technique_params_splits_tactic_and_cwe_ids():
    df = pd.DataFrame([
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
         "tactic": "initial-access, execution", "cwe_ids": "CWE-79;CWE-89"},
        {"technique_id": "T1055", "technique_name": "Process Injection",
         "tactic": "privilege-escalation", "cwe_ids": ""},
    ])
    params = technique_params(df)
    assert params[0]["tactic"] == ["initial-access", "execution"]
    assert params[0]["cwe_ids"] == ["CWE-79", "CWE-89"]
    assert params[1]["cwe_ids"] == []


def test_asset_params_splits_installed_software():
    df = pd.DataFrame([
        {"node_id": "computer-0001", "node_type": "Computer", "display_name": "Host",
         "criticality_tier": "High", "installed_software": "exchange server;windows 10",
         "management_group": "Platform/Management"},
        {"node_id": "user-0002", "node_type": "User", "display_name": "User",
         "criticality_tier": "High", "installed_software": "", "management_group": "Platform/Management"},
    ])
    params = asset_params(df)
    assert params[0]["installed_software"] == ["exchange server", "windows 10"]
    assert params[1]["installed_software"] == []


def test_topology_edge_params_groups_by_edge_type():
    df = pd.DataFrame([
        {"source_id": "a", "target_id": "b", "edge_type": "RUNS", "properties": ""},
        {"source_id": "c", "target_id": "d", "edge_type": "MEMBER_OF", "properties": ""},
        {"source_id": "e", "target_id": "f", "edge_type": "RUNS", "properties": "level=admin"},
    ])
    grouped = topology_edge_params(df)
    assert {p["source_id"] for p in grouped["RUNS"]} == {"a", "e"}
    assert grouped["MEMBER_OF"] == [{"source_id": "c", "target_id": "d", "properties": {}}]
    assert {"source_id": "e", "target_id": "f", "properties": {"level": "admin"}} in grouped["RUNS"]


def test_affects_params_matches_installed_software_to_product_case_insensitively():
    cve_df = pd.DataFrame([
        {"cve_id": "CVE-1", "product": "Exchange Server"},
        {"cve_id": "CVE-2", "product": "windows 10"},
        {"cve_id": "CVE-3", "product": "sql server"},
    ])
    nodes_df = pd.DataFrame([
        {"node_id": "computer-0001", "installed_software": "exchange server;windows 10"},
        {"node_id": "user-0002", "installed_software": ""},
    ])
    pairs = affects_params(cve_df, nodes_df)
    assert {"cve_id": "CVE-1", "node_id": "computer-0001"} in pairs
    assert {"cve_id": "CVE-2", "node_id": "computer-0001"} in pairs
    assert not any(p["node_id"] == "user-0002" for p in pairs)
    assert not any(p["cve_id"] == "CVE-3" for p in pairs)


def test_maps_to_params_matches_cwe_id_to_cwe_ids_list():
    cve_df = pd.DataFrame([
        {"cve_id": "CVE-1", "cwe_id": "CWE-79"},
        {"cve_id": "CVE-2", "cwe_id": None},
    ])
    technique_df = pd.DataFrame([
        {"technique_id": "T1190", "cwe_ids": "CWE-79;CWE-89"},
        {"technique_id": "T1055", "cwe_ids": ""},
    ])
    pairs = maps_to_params(cve_df, technique_df)
    assert pairs == [{"cve_id": "CVE-1", "technique_id": "T1190"}]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_graph_importer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.graph.importer'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/graph/importer.py
"""CSV -> Cypher parameter builders and the MERGE statements that load
data/processed/*.csv and data/synthetic/*.csv into Neo4j."""
import pathlib

import pandas as pd

CVE_MASTER = pathlib.Path("data/processed/microsoft_cve_master.csv")
TECHNIQUE_MAP = pathlib.Path("data/processed/technique_map.csv")
NODES = pathlib.Path("data/synthetic/nodes_topology.csv")
EDGES = pathlib.Path("data/synthetic/edges_topology.csv")


def _split(value: str, sep: str) -> list[str]:
    if not value or (isinstance(value, float) and pd.isna(value)):
        return []
    return [v for v in value.split(sep) if v]


def _clean(record: dict) -> dict:
    return {k: (None if isinstance(v, float) and pd.isna(v) else v) for k, v in record.items()}


def cve_params(df: pd.DataFrame) -> list[dict]:
    return [_clean(r) for r in df.to_dict(orient="records")]


def technique_params(df: pd.DataFrame) -> list[dict]:
    params = []
    for r in df.to_dict(orient="records"):
        r = _clean(r)
        r["tactic"] = _split(r.get("tactic") or "", ", ")
        r["cwe_ids"] = _split(r.get("cwe_ids") or "", ";")
        params.append(r)
    return params


def asset_params(df: pd.DataFrame) -> list[dict]:
    params = []
    for r in df.to_dict(orient="records"):
        r = _clean(r)
        r["installed_software"] = _split(r.get("installed_software") or "", ";")
        params.append(r)
    return params


def topology_edge_params(df: pd.DataFrame) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for r in df.to_dict(orient="records"):
        props_raw = r.get("properties") or ""
        props = dict(pair.split("=", 1) for pair in props_raw.split(";") if "=" in pair) if props_raw and not pd.isna(props_raw) else {}
        grouped.setdefault(r["edge_type"], []).append({
            "source_id": r["source_id"], "target_id": r["target_id"], "properties": props,
        })
    return grouped


def affects_params(cve_df: pd.DataFrame, nodes_df: pd.DataFrame) -> list[dict]:
    product_to_cves: dict[str, list[str]] = {}
    for r in cve_df.to_dict(orient="records"):
        product_to_cves.setdefault(str(r["product"]).lower(), []).append(r["cve_id"])

    pairs = []
    for r in nodes_df.to_dict(orient="records"):
        for software in _split(r.get("installed_software") or "", ";"):
            for cve_id in product_to_cves.get(software.lower(), []):
                pairs.append({"cve_id": cve_id, "node_id": r["node_id"]})
    return pairs


def maps_to_params(cve_df: pd.DataFrame, technique_df: pd.DataFrame) -> list[dict]:
    cwe_to_techniques: dict[str, list[str]] = {}
    for r in technique_df.to_dict(orient="records"):
        for cwe_id in _split(r.get("cwe_ids") or "", ";"):
            cwe_to_techniques.setdefault(cwe_id, []).append(r["technique_id"])

    pairs = []
    for r in cve_df.to_dict(orient="records"):
        cwe_id = r.get("cwe_id")
        if not cwe_id or (isinstance(cwe_id, float) and pd.isna(cwe_id)):
            continue
        for technique_id in cwe_to_techniques.get(cwe_id, []):
            pairs.append({"cve_id": r["cve_id"], "technique_id": technique_id})
    return pairs
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_graph_importer.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/graph/importer.py tests/test_graph_importer.py
git commit -m "feat: add CSV-to-Cypher param builders (Agent 3)"
```

---

### Task 3: Import orchestration (`import_graph` in `src/graph/importer.py`)

**Files:**
- Modify: `src/graph/importer.py` (append)
- Test: `tests/test_graph_importer.py` (append)

**Interfaces:**
- Consumes: every builder function from Task 2.
- Produces: `import_graph(session, processed_dir: pathlib.Path, synthetic_dir: pathlib.Path) -> dict[str, int]` — returns e.g. `{"CVE": 3, "Technique": 2, "Asset": 5, "topology_edges": 4, "AFFECTS": 2, "MAPS_TO": 1}`. Consumed by Task 5 (`scripts/build_graph.py`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_graph_importer.py — add `from unittest.mock import MagicMock` and
# `from src.graph.importer import import_graph` to the existing imports at the
# top of the file (it already has `import pandas as pd` from Task 2), then
# append the helper and tests below.


def _write(dir_, name, df):
    dir_.mkdir(parents=True, exist_ok=True)
    df.to_csv(dir_ / name, index=False)


def test_import_graph_merges_nodes_and_relationships(tmp_path):
    processed = tmp_path / "processed"
    synthetic = tmp_path / "synthetic"
    _write(processed, "microsoft_cve_master.csv", pd.DataFrame([
        {"cve_id": "CVE-1", "vendor": "microsoft", "product": "exchange server",
         "description": "RCE", "cwe_id": "CWE-79", "base_severity": "HIGH", "base_score": 8.8,
         "attack_vector": "NETWORK", "epss_score": 0.5, "epss_percentile": 0.9,
         "kev_flag": True, "kev_date_added": "2026-01-05", "ransomware_used": "Known",
         "published_date": "2026-01-01"},
    ]))
    _write(processed, "technique_map.csv", pd.DataFrame([
        {"technique_id": "T1190", "technique_name": "x", "tactic": "initial-access", "cwe_ids": "CWE-79"},
    ]))
    _write(synthetic, "nodes_topology.csv", pd.DataFrame([
        {"node_id": "computer-0001", "node_type": "Computer", "display_name": "Host",
         "criticality_tier": "High", "installed_software": "exchange server", "management_group": "Platform/Management"},
    ]))
    _write(synthetic, "edges_topology.csv", pd.DataFrame([
        {"source_id": "computer-0001", "target_id": "computer-0001", "edge_type": "CONNECTS_TO", "properties": ""},
    ]))

    session = MagicMock()
    counts = import_graph(session, processed, synthetic)

    assert counts == {"CVE": 1, "Technique": 1, "Asset": 1, "topology_edges": 1, "AFFECTS": 1, "MAPS_TO": 1}
    queries = [call.args[0] for call in session.run.call_args_list]
    assert any("MERGE (c:CVE" in q for q in queries)
    assert any("MERGE (t:Technique" in q for q in queries)
    assert any("MERGE (a:Asset" in q for q in queries)
    assert any(":CONNECTS_TO]" in q for q in queries)
    assert any("MERGE (c)-[:AFFECTS]->(a)" in q for q in queries)
    assert any("MERGE (c)-[:MAPS_TO]->(t)" in q for q in queries)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_graph_importer.py -v`
Expected: FAIL with `ImportError: cannot import name 'import_graph'`

- [ ] **Step 3: Write minimal implementation**

```python
# append to src/graph/importer.py

def _merge_nodes(session, label: str, key: str, params: list[dict]) -> int:
    if not params:
        return 0
    session.run(
        f"UNWIND $rows AS row MERGE (n:{label} {{{key}: row.{key}}}) SET n += row",
        rows=params,
    )
    return len(params)


def import_graph(session, processed_dir: pathlib.Path, synthetic_dir: pathlib.Path) -> dict[str, int]:
    cve_df = pd.read_csv(processed_dir / "microsoft_cve_master.csv")
    technique_df = pd.read_csv(processed_dir / "technique_map.csv")
    nodes_df = pd.read_csv(synthetic_dir / "nodes_topology.csv")
    edges_df = pd.read_csv(synthetic_dir / "edges_topology.csv")

    counts = {
        "CVE": _merge_nodes(session, "CVE", "cve_id", cve_params(cve_df)),
        "Technique": _merge_nodes(session, "Technique", "technique_id", technique_params(technique_df)),
        "Asset": _merge_nodes(session, "Asset", "node_id", asset_params(nodes_df)),
    }
    for a in asset_params(nodes_df):
        session.run(f"MATCH (a:Asset {{node_id: $node_id}}) SET a:{a['node_type']}", node_id=a["node_id"])

    edge_total = 0
    for edge_type, rows in topology_edge_params(edges_df).items():
        session.run(
            f"UNWIND $rows AS row "
            f"MATCH (s:Asset {{node_id: row.source_id}}), (t:Asset {{node_id: row.target_id}}) "
            f"MERGE (s)-[r:{edge_type}]->(t) SET r += row.properties",
            rows=rows,
        )
        edge_total += len(rows)
    counts["topology_edges"] = edge_total

    affects = affects_params(cve_df, nodes_df)
    if affects:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (c:CVE {cve_id: row.cve_id}), (a:Asset {node_id: row.node_id}) "
            "MERGE (c)-[:AFFECTS]->(a)",
            rows=affects,
        )
    counts["AFFECTS"] = len(affects)

    maps_to = maps_to_params(cve_df, technique_df)
    if maps_to:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (c:CVE {cve_id: row.cve_id}), (t:Technique {technique_id: row.technique_id}) "
            "MERGE (c)-[:MAPS_TO]->(t)",
            rows=maps_to,
        )
    counts["MAPS_TO"] = len(maps_to)

    return counts
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_graph_importer.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/graph/importer.py tests/test_graph_importer.py
git commit -m "feat: add Neo4j graph import orchestration (Agent 3)"
```

---

### Task 4: Post-import validation (`src/graph/validate.py`)

**Files:**
- Create: `src/graph/validate.py`
- Test: `tests/test_graph_validate.py`

**Interfaces:**
- Consumes: nothing directly (queries the graph via `session`, and CSVs via `processed_dir`/`synthetic_dir` for expected counts — same signature style as `src.ingestion.validate.validate_outputs`).
- Produces: `validate_graph(session, processed_dir: pathlib.Path, synthetic_dir: pathlib.Path) -> list[str]`, `main()`. Consumed by Task 5.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_graph_validate.py
from unittest.mock import MagicMock

import pandas as pd

from src.graph.validate import validate_graph


def _write(dir_, name, df):
    dir_.mkdir(parents=True, exist_ok=True)
    df.to_csv(dir_ / name, index=False)


def _fake_session(records_by_call):
    """records_by_call: list of single-record dicts, one per expected session.run() call, in order."""
    session = MagicMock()
    results = []
    for record in records_by_call:
        result = MagicMock()
        result.single.return_value = record
        results.append(result)
    session.run.side_effect = results
    return session


def _setup_csvs(tmp_path):
    processed, synthetic = tmp_path / "processed", tmp_path / "synthetic"
    _write(processed, "microsoft_cve_master.csv", pd.DataFrame([{"cve_id": "CVE-1"}]))
    _write(processed, "technique_map.csv", pd.DataFrame([{"technique_id": "T1"}]))
    _write(synthetic, "nodes_topology.csv", pd.DataFrame([{"node_id": "n1"}]))
    _write(synthetic, "edges_topology.csv", pd.DataFrame([{"source_id": "n1", "target_id": "n1"}]))
    return processed, synthetic


def test_validate_graph_passes_when_counts_and_coverage_match(tmp_path):
    processed, synthetic = _setup_csvs(tmp_path)
    session = _fake_session([
        {"n": 1},  # CVE count
        {"n": 1},  # Technique count
        {"n": 1},  # Asset count
        {"n": 1},  # topology edge count
        {"n": 0},  # CVE nodes with a null required field
        {"n": 0},  # Assets with installed_software but zero AFFECTS edges
    ])
    assert validate_graph(session, processed, synthetic) == []


def test_validate_graph_flags_count_mismatch_and_missing_coverage(tmp_path):
    processed, synthetic = _setup_csvs(tmp_path)
    session = _fake_session([
        {"n": 0},  # CVE count mismatch (expected 1)
        {"n": 1},
        {"n": 1},
        {"n": 1},
        {"n": 2},  # 2 CVE nodes missing a required field
        {"n": 3},  # 3 assets with software but no AFFECTS edge
    ])
    violations = validate_graph(session, processed, synthetic)
    assert any("CVE node count" in v for v in violations)
    assert any("missing a required field" in v for v in violations)
    assert any("no AFFECTS relationship" in v for v in violations)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_graph_validate.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.graph.validate'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/graph/validate.py
"""Validates the imported Neo4j graph against contract 02/data_schema.yaml
expectations: node/edge counts match the source CSVs, required CVE fields are
non-null (Community Edition has no existence constraints, see
src/graph/schema.py), and every Asset carrying installed_software is reachable
from at least one CVE via AFFECTS (the FR3 guarantee from requirements.md)."""
import pathlib

import pandas as pd

REQUIRED_CVE_FIELDS = [
    "vendor", "product", "description", "base_severity", "base_score",
    "epss_score", "epss_percentile", "kev_flag", "published_date",
]


def _count(session, query: str, **params) -> int:
    return session.run(query, **params).single()["n"]


def validate_graph(session, processed_dir: pathlib.Path, synthetic_dir: pathlib.Path) -> list[str]:
    violations: list[str] = []

    expected_cve = len(pd.read_csv(processed_dir / "microsoft_cve_master.csv"))
    expected_technique = len(pd.read_csv(processed_dir / "technique_map.csv"))
    expected_asset = len(pd.read_csv(synthetic_dir / "nodes_topology.csv"))
    expected_edges = len(pd.read_csv(synthetic_dir / "edges_topology.csv"))

    actual_cve = _count(session, "MATCH (c:CVE) RETURN count(c) AS n")
    if actual_cve != expected_cve:
        violations.append(f"CVE node count {actual_cve} != microsoft_cve_master.csv rows {expected_cve}")

    actual_technique = _count(session, "MATCH (t:Technique) RETURN count(t) AS n")
    if actual_technique != expected_technique:
        violations.append(f"Technique node count {actual_technique} != technique_map.csv rows {expected_technique}")

    actual_asset = _count(session, "MATCH (a:Asset) RETURN count(a) AS n")
    if actual_asset != expected_asset:
        violations.append(f"Asset node count {actual_asset} != nodes_topology.csv rows {expected_asset}")

    actual_edges = _count(session, "MATCH ()-[r]->() WHERE type(r) IN "
                           "['RUNS','CONNECTS_TO','MEMBER_OF','HAS_SESSION','CONTROLS'] RETURN count(r) AS n")
    if actual_edges != expected_edges:
        violations.append(f"topology relationship count {actual_edges} != edges_topology.csv rows {expected_edges}")

    null_field_clause = " OR ".join(f"c.{f} IS NULL" for f in REQUIRED_CVE_FIELDS)
    missing_required = _count(session, f"MATCH (c:CVE) WHERE {null_field_clause} RETURN count(c) AS n")
    if missing_required:
        violations.append(f"{missing_required} CVE node(s) missing a required field")

    uncovered = _count(session, "MATCH (a:Asset) WHERE size(a.installed_software) > 0 "
                        "AND NOT (a)<-[:AFFECTS]-(:CVE) RETURN count(a) AS n")
    if uncovered:
        violations.append(f"{uncovered} Asset node(s) with installed_software have no AFFECTS relationship")

    return violations


def main() -> None:
    import os

    from neo4j import GraphDatabase

    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        violations = validate_graph(session, pathlib.Path("data/processed"), pathlib.Path("data/synthetic"))
    driver.close()
    if violations:
        print(f"FAILED: {len(violations)} violation(s)")
        for v in violations:
            print(f"  - {v}")
        raise SystemExit(1)
    print("PASSED: all contract 02/03 graph checks satisfied")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_graph_validate.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/graph/validate.py tests/test_graph_validate.py
git commit -m "feat: add post-import graph validation (Agent 3)"
```

---

### Task 5: Orchestrator CLI (`scripts/build_graph.py`)

**Files:**
- Create: `scripts/build_graph.py`
- Test: `tests/test_build_graph.py`

**Interfaces:**
- Consumes: `apply_schema` (Task 1), `import_graph` (Task 3), `validate_graph` (Task 4).
- Produces: `main() -> None`. Nothing downstream in this plan consumes it directly — it's the manual/CI entry point, mirroring `scripts/build_dataset.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_build_graph.py
from unittest.mock import MagicMock, patch

import pytest


def test_main_exits_nonzero_when_validation_fails(monkeypatch):
    monkeypatch.setenv("NEO4J_PASSWORD", "test-password")
    fake_session = MagicMock()
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = fake_session

    with patch("scripts.build_graph.GraphDatabase") as fake_gdb, \
         patch("scripts.build_graph.apply_schema") as fake_apply, \
         patch("scripts.build_graph.import_graph") as fake_import, \
         patch("scripts.build_graph.validate_graph", return_value=["bad thing"]) as fake_validate:
        fake_gdb.driver.return_value = fake_driver

        from scripts.build_graph import main
        with pytest.raises(SystemExit) as exc:
            main()

        assert exc.value.code == 1
        fake_apply.assert_called_once_with(fake_session)
        fake_import.assert_called_once()
        fake_validate.assert_called_once()


def test_main_exits_zero_when_validation_passes(monkeypatch):
    monkeypatch.setenv("NEO4J_PASSWORD", "test-password")
    fake_session = MagicMock()
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = fake_session

    with patch("scripts.build_graph.GraphDatabase") as fake_gdb, \
         patch("scripts.build_graph.apply_schema"), \
         patch("scripts.build_graph.import_graph"), \
         patch("scripts.build_graph.validate_graph", return_value=[]):
        fake_gdb.driver.return_value = fake_driver

        from scripts.build_graph import main
        main()  # should not raise
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_build_graph.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.build_graph'`

- [ ] **Step 3: Write minimal implementation**

```python
# scripts/build_graph.py
"""Runs the full Agent 3 (Graph Architect) pipeline: apply schema -> import
CSVs -> validate the loaded graph. Exits non-zero if validation fails."""
import os
import pathlib
import sys

sys.path.insert(0, ".")

from neo4j import GraphDatabase  # noqa: E402

from src.graph.importer import import_graph  # noqa: E402
from src.graph.schema import apply_schema  # noqa: E402
from src.graph.validate import validate_graph  # noqa: E402

PROCESSED_DIR = pathlib.Path("data/processed")
SYNTHETIC_DIR = pathlib.Path("data/synthetic")


def main() -> None:
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]

    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        apply_schema(session)
        counts = import_graph(session, PROCESSED_DIR, SYNTHETIC_DIR)
        print(f"Imported: {counts}")
        violations = validate_graph(session, PROCESSED_DIR, SYNTHETIC_DIR)
    driver.close()

    if violations:
        print(f"FAILED: {len(violations)} violation(s)")
        for v in violations:
            print(f"  - {v}")
        raise SystemExit(1)
    print("PASSED: graph import satisfies contract 02/03")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_build_graph.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/build_graph.py tests/test_build_graph.py
git commit -m "feat: add Graph Architect pipeline orchestrator (Agent 3)"
```

---

### Task 6: Local Neo4j, contracts, and agent doc (no new logic — config and handoff docs)

**Files:**
- Create: `docker-compose.yml`
- Create: `.env.example`
- Modify: `contracts/02_data_to_graph.yaml` (currently empty placeholder)
- Modify: `contracts/03_graph_to_paths.yaml` (currently empty placeholder)
- Modify: `agents/graph_architect/prompt.md` (currently empty placeholder)

**Interfaces:** None (config/docs only — no function signatures produced or consumed).

- [ ] **Step 1: Write `docker-compose.yml`**

```yaml
services:
  neo4j:
    image: neo4j:5-community
    ports:
      - "7474:7474"   # browser UI
      - "7687:7687"   # bolt
    environment:
      - NEO4J_AUTH=neo4j/${NEO4J_PASSWORD:?set NEO4J_PASSWORD in .env}
    volumes:
      - neo4j_data:/data

volumes:
  neo4j_data:
```

- [ ] **Step 2: Write `.env.example`**

```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=changeme-min-8-chars
```

- [ ] **Step 3: Write `contracts/02_data_to_graph.yaml`**

```yaml
contract: 02_data_to_graph
producer: data_engineer
consumer: graph_architect

# Backfilled by Agent 3 — Agent 2's commits produced the four output files
# below but never wrote this handoff file. Documents what was actually
# delivered, verified against the files present in the repo.

inputs:
  - path: data/processed/microsoft_cve_master.csv
    description: 29205 in-scope CVE rows, columns per schemas/data_schema.yaml -> microsoft_cve_master.
  - path: data/processed/technique_map.csv
    description: 858 ATT&CK Enterprise technique rows. cwe_ids is empty for every row (documented gap, see src/ingestion/technique_map.py).
  - path: data/synthetic/nodes_topology.csv
    description: 80 synthetic AzureHound-shaped nodes (User/Group/Computer/Application/Device).
  - path: data/synthetic/edges_topology.csv
    description: 79 synthetic relationships (RUNS/CONNECTS_TO/MEMBER_OF/HAS_SESSION/CONTROLS).

outputs:
  - path: (Neo4j graph, not a file — see contract 03 for connection details)
    description: CVE/Technique/Asset nodes and topology/AFFECTS/MAPS_TO relationships loaded via scripts/build_graph.py.

consumer_must_validate:
  - Every required field in schemas/data_schema.yaml -> microsoft_cve_master is non-null on every row (already enforced by src/ingestion/validate.py at Agent 2's handoff; re-verified post-import by src/graph/validate.py since Neo4j Community Edition has no existence constraints).
  - Every edges_topology.csv source_id/target_id resolves to a node_id present in nodes_topology.csv (already enforced by src/ingestion/validate.py; re-verified post-import as a relationship-count match in src/graph/validate.py).
  - installed_software values only ever reference products present in microsoft_cve_master.product (Agent 2's FR3 guarantee) — verified post-import as the AFFECTS coverage check in src/graph/validate.py.

handoff_status: ready
```

- [ ] **Step 4: Write `contracts/03_graph_to_paths.yaml`**

```yaml
contract: 03_graph_to_paths
producer: graph_architect
consumer: path_engine

inputs:
  - path: contracts/02_data_to_graph.yaml
    description: The CSVs this phase imports.

outputs:
  - path: Neo4j graph database (bolt://$NEO4J_URI, credentials in .env, see .env.example)
    description: >
      Loaded via scripts/build_graph.py. Node labels: (:CVE {cve_id, vendor,
      product, description, cwe_id, base_severity, base_score, attack_vector,
      epss_score, epss_percentile, kev_flag, kev_date_added, ransomware_used,
      published_date}), (:Technique {technique_id, technique_name,
      tactic: list[string], cwe_ids: list[string]}), (:Asset:<node_type>
      {node_id, display_name, criticality_tier, installed_software: list[string],
      management_group}) where <node_type> is one of User/Group/Computer/
      Application/Device. Relationship types: topology edges
      (RUNS/CONNECTS_TO/MEMBER_OF/HAS_SESSION/CONTROLS) between (:Asset) nodes
      with an optional properties map; (:CVE)-[:AFFECTS]->(:Asset) derived from
      installed_software matching CVE.product; (:CVE)-[:MAPS_TO]->(:Technique)
      derived from cwe_id matching Technique.cwe_ids (currently always empty
      upstream — see contract 02 — so this relationship type exists in the
      import code but has 0 edges until Agent 2's technique_map.cwe_ids gap
      closes).
  - path: schemas/data_schema.yaml (unchanged)
    description: Still the source of truth for property names/types on every node.

consumer_must_validate:
  - src/graph/validate.py's checklist passes (node/edge counts match source CSVs, no CVE node missing a required field, every Asset with installed_software has >=1 AFFECTS relationship).
  - Uniqueness constraints from src/graph/schema.py exist on (:CVE.cve_id), (:Technique.technique_id), (:Asset.node_id) — `SHOW CONSTRAINTS` before running path queries.
  - CVSS x EPSS x criticality scoring (requirements.md FR6) reads base_score and epss_score from (:CVE) and criticality_tier from (:Asset) — both are guaranteed non-null by the validation above.

handoff_status: ready
```

- [ ] **Step 5: Write `agents/graph_architect/prompt.md`**

```markdown
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
```

- [ ] **Step 6: Verify the two contract YAML files still parse**

Run: `python3 -c "import yaml; [yaml.safe_load(open(p)) for p in ['contracts/02_data_to_graph.yaml', 'contracts/03_graph_to_paths.yaml']]; print('ok')"`
Expected: `ok`

- [ ] **Step 7: Commit**

```bash
git add docker-compose.yml .env.example contracts/02_data_to_graph.yaml contracts/03_graph_to_paths.yaml agents/graph_architect/prompt.md
git commit -m "docs: add Graph Architect contracts, prompt, and local Neo4j compose (Agent 3)"
```

---

## Out of scope for this plan

- Actually running `scripts/build_graph.py` end-to-end against a live Neo4j (no Docker in this sandbox — the user runs `docker compose up -d && python3 -m dotenv run -- python3 scripts/build_graph.py`, or exports the three env vars manually, once they have Docker available).
- Populating `technique_map.cwe_ids` (blocked on Agent 2 finding/adding a CWE↔ATT&CK cross-reference to `data/raw/` — tracked as a `ponytail:` gap in `src/ingestion/technique_map.py`, not something Agent 3 can fix without fabricating data).
- Path extraction, scoring, or Cypher path queries — that's Agent 4 (Path Engine), scoped by `contracts/03_graph_to_paths.yaml`.
