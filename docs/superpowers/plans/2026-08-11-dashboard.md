# Attack Graph Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Streamlit dashboard (`dashboard/`) with three pages — Overview, Attack Paths, Graph Explorer — that browses the existing pipeline output in Neo4j (Agents 3-5's `:Asset`/`:CVE`/`:Technique`/`:AttackPath`/`:Reasoning` graph) for demoing to others.

**Architecture:** A Streamlit multipage app (`dashboard/app.py` + `dashboard/pages/*.py`), a shared cached Neo4j connection module (`dashboard/db.py`), and one query module per page (`dashboard/_overview_queries.py`, `dashboard/_attack_paths_queries.py`, `dashboard/_graph_explorer_queries.py`) — all flat inside `dashboard/`, never under `dashboard/pages/`, because Streamlit only adds the main script's own directory to `sys.path` (verified directly against Streamlit 1.61's source — see design spec's Architecture section). Query modules are pure functions over a `neo4j` session, unit-tested with a mocked session exactly like `tests/test_reasoning_read_paths.py`. Page scripts are thin composition, verified with Streamlit's official headless `streamlit.testing.v1.AppTest` API against the real local Neo4j (no browser needed, no mocking needed — mirrors this project's existing "live run against local Neo4j" verification task pattern from the Path Engine and Reasoning Agent plans).

**Tech Stack:** Python 3.11, `streamlit==1.61.1` (new), `pyvis==0.3.2` (new), `neo4j` 5.28.4 driver and `pandas` (already installed, no version change).

## Global Constraints

- **Read-only.** No task in this plan writes to Neo4j. Every query is `MATCH`/`OPTIONAL MATCH`/`RETURN` only.
- **No new analysis logic.** Every number and graph element comes from data Agents 3-5 already wrote (`:Asset.blast_radius`/`.choke_point_count`, `:AttackPath.*`, `:Reasoning.*`). No task recomputes blast radius, choke points, or scores.
- **Query modules live flat in `dashboard/`**, never in `dashboard/pages/` (see Architecture above — this is a correctness requirement, not a style preference: a query module placed under `dashboard/pages/` would fail to import at runtime).
- **Page scripts use bare imports** (`from db import get_driver`, `from _overview_queries import ...`) — not `from dashboard.db import ...` — because Streamlit's `sys.path` only contains `dashboard/`, not the project root, when running the app. Tests import the same files via the package path (`from dashboard.db import ...`, `from dashboard._overview_queries import ...`) since `conftest.py` puts the project root on `sys.path` for pytest.
- **`db.py`'s driver is `st.cache_resource`-wrapped** so Streamlit reuses one Neo4j driver across reruns instead of opening a new connection per widget interaction.
- **pyvis `Network` is constructed with `cdn_resources="in_line"`**, not the default `"local"` — verified directly: the default mode leaves a relative `lib/bindings/utils.js` reference that 404s once embedded in Streamlit's iframe (and pulls vis-network's core JS/CSS from a CDN); `"in_line"` inlines everything into the generated HTML string, so the graph renders with zero external requests.
- **Neo4j connection env vars:** `NEO4J_URI` (default `bolt://localhost:7687`), `NEO4J_USER` (default `neo4j`), `NEO4J_PASSWORD` (required, `KeyError` if unset) — same names and defaults as `scripts/find_paths.py`/`scripts/reason_paths.py`.
- Follow TDD: write the failing test, confirm it fails, implement, confirm it passes, commit.

## File Structure

- `dashboard/__init__.py` — empty, package marker (so pytest can `from dashboard.db import ...`).
- `dashboard/db.py` — `get_driver()` (cached), `_driver_config()` (pure, testable).
- `dashboard/_overview_queries.py` — 5 query functions for `app.py`.
- `dashboard/app.py` — Overview page (Streamlit's default landing page).
- `dashboard/_attack_paths_queries.py` — 1 query function for `pages/1_Attack_Paths.py`.
- `dashboard/pages/1_Attack_Paths.py` — Attack Paths page.
- `dashboard/_graph_explorer_queries.py` — 2 query functions for `pages/2_Graph_Explorer.py`.
- `dashboard/pages/2_Graph_Explorer.py` — Graph Explorer page.
- `tests/test_dashboard_db.py`, `tests/test_dashboard_overview_queries.py`, `tests/test_dashboard_attack_paths_queries.py`, `tests/test_dashboard_graph_explorer_queries.py`.
- `requirements.txt` — add `streamlit==1.61.1`, `pyvis==0.3.2`.

---

### Task 1: Dependencies + Neo4j connection module (`dashboard/db.py`)

**Files:**
- Modify: `requirements.txt`
- Create: `dashboard/__init__.py` (empty)
- Create: `dashboard/db.py`
- Test: `tests/test_dashboard_db.py`

**Interfaces:**
- Produces: `get_driver() -> neo4j.Driver` (cached via `st.cache_resource`), `_driver_config() -> dict[str, str]` (keys `uri`, `user`, `password`). Consumed by Tasks 2-4's page scripts (via bare import `from db import get_driver`).

- [ ] **Step 1: Add dependencies**

```bash
echo "streamlit==1.61.1" >> requirements.txt
echo "pyvis==0.3.2" >> requirements.txt
pip install streamlit==1.61.1 pyvis==0.3.2
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_dashboard_db.py
import pytest

from dashboard.db import _driver_config


def test_driver_config_reads_env(monkeypatch):
    monkeypatch.setenv("NEO4J_URI", "bolt://example:7687")
    monkeypatch.setenv("NEO4J_USER", "test-user")
    monkeypatch.setenv("NEO4J_PASSWORD", "test-pass")

    assert _driver_config() == {
        "uri": "bolt://example:7687", "user": "test-user", "password": "test-pass",
    }


def test_driver_config_defaults_uri_and_user(monkeypatch):
    monkeypatch.delenv("NEO4J_URI", raising=False)
    monkeypatch.delenv("NEO4J_USER", raising=False)
    monkeypatch.setenv("NEO4J_PASSWORD", "test-pass")

    config = _driver_config()

    assert config["uri"] == "bolt://localhost:7687"
    assert config["user"] == "neo4j"


def test_driver_config_requires_password(monkeypatch):
    monkeypatch.delenv("NEO4J_PASSWORD", raising=False)

    with pytest.raises(KeyError):
        _driver_config()
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_dashboard_db.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dashboard'`

- [ ] **Step 4: Write minimal implementation**

```python
# dashboard/__init__.py
```

```python
# dashboard/db.py
"""Neo4j connection for the dashboard -- same NEO4J_URI/USER/PASSWORD env
pattern as scripts/find_paths.py, cached so Streamlit reuses one driver
across reruns instead of opening a new connection per widget interaction
(see docs/superpowers/specs/2026-08-11-dashboard-design.md, Architecture)."""
import os

import streamlit as st
from neo4j import GraphDatabase


def _driver_config() -> dict[str, str]:
    return {
        "uri": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        "user": os.environ.get("NEO4J_USER", "neo4j"),
        "password": os.environ["NEO4J_PASSWORD"],
    }


@st.cache_resource
def get_driver():
    config = _driver_config()
    return GraphDatabase.driver(config["uri"], auth=(config["user"], config["password"]))
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_dashboard_db.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add requirements.txt dashboard/__init__.py dashboard/db.py tests/test_dashboard_db.py
git commit -m "feat: add dashboard dependencies and Neo4j connection module"
```

---

### Task 2: Overview page (`dashboard/app.py`)

**Files:**
- Create: `dashboard/_overview_queries.py`
- Create: `dashboard/app.py`
- Test: `tests/test_dashboard_overview_queries.py`

**Interfaces:**
- Consumes: `get_driver` (Task 1, by bare import within `app.py` only — not by the query module, which takes a `session` directly).
- Produces: `count_attack_paths(session) -> int`, `count_crown_jewel_targets(session) -> int`, `top_choke_points(session, limit=5) -> list[dict]`, `top_blast_radius(session, limit=5) -> list[dict]`, `path_counts_by_criticality(session) -> list[dict]`. Not consumed by later tasks (page-scoped).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dashboard_overview_queries.py
from unittest.mock import MagicMock

from dashboard._overview_queries import (
    COUNT_ATTACK_PATHS_QUERY,
    COUNT_CROWN_JEWEL_TARGETS_QUERY,
    PATH_COUNTS_BY_CRITICALITY_QUERY,
    TOP_BLAST_RADIUS_QUERY,
    TOP_CHOKE_POINTS_QUERY,
    count_attack_paths,
    count_crown_jewel_targets,
    path_counts_by_criticality,
    top_blast_radius,
    top_choke_points,
)


def test_count_attack_paths_runs_query_and_returns_count():
    session = MagicMock()
    session.run.return_value.single.return_value = {"n": 50}

    result = count_attack_paths(session)

    assert result == 50
    session.run.assert_called_once_with(COUNT_ATTACK_PATHS_QUERY)


def test_count_crown_jewel_targets_query_joins_attackpath_and_asset():
    assert "AttackPath" in COUNT_CROWN_JEWEL_TARGETS_QUERY
    assert "Crown Jewel" in COUNT_CROWN_JEWEL_TARGETS_QUERY
    assert "DISTINCT" in COUNT_CROWN_JEWEL_TARGETS_QUERY


def test_count_crown_jewel_targets_runs_query_and_returns_count():
    session = MagicMock()
    session.run.return_value.single.return_value = {"n": 3}

    result = count_crown_jewel_targets(session)

    assert result == 3
    session.run.assert_called_once_with(COUNT_CROWN_JEWEL_TARGETS_QUERY)


def test_top_choke_points_runs_query_with_limit_and_returns_rows():
    session = MagicMock()
    rows = [{"node_id": "computer-0001", "display_name": "Host-1", "choke_point_count": 4}]
    session.run.return_value = rows

    result = top_choke_points(session, limit=5)

    assert result == rows
    session.run.assert_called_once_with(TOP_CHOKE_POINTS_QUERY, limit=5)


def test_top_blast_radius_runs_query_with_limit_and_returns_rows():
    session = MagicMock()
    rows = [{"node_id": "computer-0002", "display_name": "Host-2", "blast_radius": 12}]
    session.run.return_value = rows

    result = top_blast_radius(session, limit=5)

    assert result == rows
    session.run.assert_called_once_with(TOP_BLAST_RADIUS_QUERY, limit=5)


def test_path_counts_by_criticality_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{"tier": "Crown Jewel", "count": 10}, {"tier": "High", "count": 5}]
    session.run.return_value = rows

    result = path_counts_by_criticality(session)

    assert result == rows
    session.run.assert_called_once_with(PATH_COUNTS_BY_CRITICALITY_QUERY)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_dashboard_overview_queries.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dashboard._overview_queries'`

- [ ] **Step 3: Write minimal implementation**

```python
# dashboard/_overview_queries.py
"""Cypher queries for the Overview page's risk-focused stat tiles -- pure
functions over a Neo4j session, no Streamlit dependency (see
docs/superpowers/specs/2026-08-11-dashboard-design.md, Page 1: Overview)."""

COUNT_ATTACK_PATHS_QUERY = "MATCH (p:AttackPath) RETURN count(p) AS n"

COUNT_CROWN_JEWEL_TARGETS_QUERY = """
MATCH (p:AttackPath)
MATCH (a:Asset {node_id: p.target_asset_id})
WHERE a.criticality_tier = "Crown Jewel"
RETURN count(DISTINCT a.node_id) AS n
""".strip()

TOP_CHOKE_POINTS_QUERY = """
MATCH (a:Asset)
WHERE a.choke_point_count IS NOT NULL
RETURN a.node_id AS node_id, a.display_name AS display_name, a.choke_point_count AS choke_point_count
ORDER BY a.choke_point_count DESC
LIMIT $limit
""".strip()

TOP_BLAST_RADIUS_QUERY = """
MATCH (a:Asset)
WHERE a.blast_radius IS NOT NULL
RETURN a.node_id AS node_id, a.display_name AS display_name, a.blast_radius AS blast_radius
ORDER BY a.blast_radius DESC
LIMIT $limit
""".strip()

PATH_COUNTS_BY_CRITICALITY_QUERY = """
MATCH (p:AttackPath)
MATCH (a:Asset {node_id: p.target_asset_id})
RETURN a.criticality_tier AS tier, count(p) AS count
ORDER BY count DESC
""".strip()


def count_attack_paths(session) -> int:
    return session.run(COUNT_ATTACK_PATHS_QUERY).single()["n"]


def count_crown_jewel_targets(session) -> int:
    return session.run(COUNT_CROWN_JEWEL_TARGETS_QUERY).single()["n"]


def top_choke_points(session, limit: int = 5) -> list[dict]:
    return [dict(record) for record in session.run(TOP_CHOKE_POINTS_QUERY, limit=limit)]


def top_blast_radius(session, limit: int = 5) -> list[dict]:
    return [dict(record) for record in session.run(TOP_BLAST_RADIUS_QUERY, limit=limit)]


def path_counts_by_criticality(session) -> list[dict]:
    return [dict(record) for record in session.run(PATH_COUNTS_BY_CRITICALITY_QUERY)]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_dashboard_overview_queries.py -v`
Expected: PASS

- [ ] **Step 5: Write the Overview page (not unit-tested here — verified live in Task 5)**

```python
# dashboard/app.py
"""Overview page: risk-focused stat tiles over the pipeline's existing
Neo4j output -- see docs/superpowers/specs/2026-08-11-dashboard-design.md,
Page 1: Overview. Streamlit auto-loads this as the default landing page."""
import pandas as pd
import streamlit as st

from _overview_queries import (
    count_attack_paths,
    count_crown_jewel_targets,
    path_counts_by_criticality,
    top_blast_radius,
    top_choke_points,
)
from db import get_driver

st.set_page_config(page_title="Attack Graph Overview", layout="wide")
st.title("Attack Graph Overview")

with get_driver().session() as session:
    attack_path_count = count_attack_paths(session)
    crown_jewel_count = count_crown_jewel_targets(session)
    choke_points = top_choke_points(session)
    blast_radii = top_blast_radius(session)
    tier_counts = path_counts_by_criticality(session)

col1, col2 = st.columns(2)
col1.metric("Attack Paths Found", attack_path_count)
col2.metric("Crown Jewel Assets Targeted", crown_jewel_count)

st.subheader("Top Choke-Point Assets")
st.dataframe(pd.DataFrame(choke_points), hide_index=True)

st.subheader("Top Blast-Radius Assets")
st.dataframe(pd.DataFrame(blast_radii), hide_index=True)

st.subheader("Attack Paths by Target Criticality")
tier_df = pd.DataFrame(tier_counts)
if not tier_df.empty:
    st.bar_chart(tier_df.set_index("tier"))
```

- [ ] **Step 6: Commit**

```bash
git add dashboard/_overview_queries.py dashboard/app.py tests/test_dashboard_overview_queries.py
git commit -m "feat: add dashboard Overview page"
```

---

### Task 3: Attack Paths page (`dashboard/pages/1_Attack_Paths.py`)

**Files:**
- Create: `dashboard/_attack_paths_queries.py`
- Create: `dashboard/pages/1_Attack_Paths.py`
- Test: `tests/test_dashboard_attack_paths_queries.py`

**Interfaces:**
- Consumes: `get_driver` (Task 1, by bare import within the page only).
- Produces: `read_attack_paths_with_reasoning(session) -> list[dict]` (each dict has keys `path_id`, `rank`, `source_cve`, `source_asset_id`, `target_asset_id`, `hop_count`, `base_score`, `epss_score`, `target_criticality_tier`, `explanation`, `technique_ids`, `threat_actors`, `mitigations` — the last four are `None` when no `:Reasoning` node is linked). Not consumed by later tasks (page-scoped).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dashboard_attack_paths_queries.py
from unittest.mock import MagicMock

from dashboard._attack_paths_queries import (
    READ_ATTACK_PATHS_WITH_REASONING_QUERY,
    read_attack_paths_with_reasoning,
)


def test_query_joins_attack_path_cve_target_and_optional_reasoning():
    assert "AttackPath" in READ_ATTACK_PATHS_WITH_REASONING_QUERY
    assert "OPTIONAL MATCH" in READ_ATTACK_PATHS_WITH_REASONING_QUERY
    assert "EXPLAINED_BY" in READ_ATTACK_PATHS_WITH_REASONING_QUERY
    assert "ORDER BY p.rank" in READ_ATTACK_PATHS_WITH_REASONING_QUERY


def test_read_attack_paths_with_reasoning_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{
        "path_id": "abc123", "rank": 1, "source_cve": "CVE-2023-1234",
        "source_asset_id": "computer-0002", "target_asset_id": "sql-prod-01",
        "hop_count": 3, "base_score": 8.8, "epss_score": 0.94,
        "target_criticality_tier": "Crown Jewel", "explanation": "explained.",
        "technique_ids": ["T1190"], "threat_actors": ["APT38"], "mitigations": [],
    }]
    session.run.return_value = rows

    result = read_attack_paths_with_reasoning(session)

    assert result == rows
    session.run.assert_called_once_with(READ_ATTACK_PATHS_WITH_REASONING_QUERY)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_dashboard_attack_paths_queries.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dashboard._attack_paths_queries'`

- [ ] **Step 3: Write minimal implementation**

```python
# dashboard/_attack_paths_queries.py
"""Cypher query for the Attack Paths page: every AttackPath left-joined
with its CVE/target-asset facts and (if resolved) its Reasoning
explanation -- see docs/superpowers/specs/2026-08-11-dashboard-design.md,
Page 2: Attack Paths."""

READ_ATTACK_PATHS_WITH_REASONING_QUERY = """
MATCH (p:AttackPath)
MATCH (c:CVE {cve_id: p.source_cve})
MATCH (target:Asset {node_id: p.target_asset_id})
OPTIONAL MATCH (p)-[:EXPLAINED_BY]->(r:Reasoning)
RETURN p.path_id AS path_id, p.rank AS rank, p.source_cve AS source_cve,
       p.source_asset_id AS source_asset_id, p.target_asset_id AS target_asset_id,
       p.hop_count AS hop_count, c.base_score AS base_score, c.epss_score AS epss_score,
       target.criticality_tier AS target_criticality_tier,
       r.explanation AS explanation, r.technique_ids AS technique_ids,
       r.threat_actors AS threat_actors, r.mitigations AS mitigations
ORDER BY p.rank
""".strip()


def read_attack_paths_with_reasoning(session) -> list[dict]:
    return [dict(record) for record in session.run(READ_ATTACK_PATHS_WITH_REASONING_QUERY)]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_dashboard_attack_paths_queries.py -v`
Expected: PASS

- [ ] **Step 5: Write the Attack Paths page (not unit-tested here — verified live in Task 5)**

```python
# dashboard/pages/1_Attack_Paths.py
"""Attack Paths page: ranked table + detail panel with grounded
explanation -- see docs/superpowers/specs/2026-08-11-dashboard-design.md,
Page 2: Attack Paths."""
import pandas as pd
import streamlit as st

from _attack_paths_queries import read_attack_paths_with_reasoning
from db import get_driver

st.set_page_config(page_title="Attack Paths", layout="wide")
st.title("Attack Paths")

with get_driver().session() as session:
    paths = read_attack_paths_with_reasoning(session)

df = pd.DataFrame(paths)
display_columns = [
    "rank", "source_cve", "base_score", "epss_score",
    "source_asset_id", "target_asset_id", "target_criticality_tier", "hop_count",
]

event = st.dataframe(
    df[display_columns],
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row-required",
)
selected_row = df.iloc[event["selection"]["rows"][0]]

st.subheader(f"{selected_row['source_cve']} -> {selected_row['target_asset_id']}")
st.write(selected_row["explanation"] or "Not resolved for this path.")

technique_ids = selected_row["technique_ids"] or []
threat_actors = selected_row["threat_actors"] or []
mitigations = selected_row["mitigations"] or []

st.write("**MITRE ATT&CK Techniques:**", ", ".join(technique_ids) or "Not resolved for this path.")
st.write("**Threat Actors:**", ", ".join(threat_actors) or "Not resolved for this path.")
st.write("**Mitigations:**", ", ".join(mitigations) or "Not resolved for this path.")
```

- [ ] **Step 6: Commit**

```bash
git add dashboard/_attack_paths_queries.py dashboard/pages/1_Attack_Paths.py tests/test_dashboard_attack_paths_queries.py
git commit -m "feat: add dashboard Attack Paths page"
```

---

### Task 4: Graph Explorer page (`dashboard/pages/2_Graph_Explorer.py`)

**Files:**
- Create: `dashboard/_graph_explorer_queries.py`
- Create: `dashboard/pages/2_Graph_Explorer.py`
- Test: `tests/test_dashboard_graph_explorer_queries.py`

**Interfaces:**
- Consumes: `get_driver` (Task 1, by bare import within the page only).
- Produces: `read_asset_network(session) -> dict` (`{"nodes": list[dict], "edges": list[dict]}` — node dicts have keys `node_id`, `display_name`, `node_type`, `criticality_tier`, `blast_radius`, `choke_point_count`; edge dicts have keys `source_id`, `target_id`, `rel_type`), `read_asset_detail(session, node_id) -> list[dict]` (each dict has keys `cve_id`, `base_score`, `epss_score`, `technique_ids`). Not consumed by later tasks (page-scoped).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dashboard_graph_explorer_queries.py
from unittest.mock import MagicMock, call

from dashboard._graph_explorer_queries import (
    ASSET_DETAIL_QUERY,
    ASSET_NETWORK_EDGES_QUERY,
    ASSET_NETWORK_NODES_QUERY,
    read_asset_detail,
    read_asset_network,
)


def test_edges_query_covers_all_five_topology_relationship_types():
    for rel_type in ("RUNS", "CONNECTS_TO", "MEMBER_OF", "HAS_SESSION", "CONTROLS"):
        assert rel_type in ASSET_NETWORK_EDGES_QUERY


def test_asset_detail_query_joins_affects_and_optional_maps_to():
    assert "AFFECTS" in ASSET_DETAIL_QUERY
    assert "OPTIONAL MATCH" in ASSET_DETAIL_QUERY
    assert "MAPS_TO" in ASSET_DETAIL_QUERY


def test_read_asset_network_runs_both_queries_and_returns_nodes_and_edges():
    session = MagicMock()
    nodes = [{
        "node_id": "computer-0001", "display_name": "Host-1", "node_type": "Computer",
        "criticality_tier": "High", "blast_radius": 5, "choke_point_count": 2,
    }]
    edges = [{"source_id": "computer-0001", "target_id": "computer-0002", "rel_type": "CONNECTS_TO"}]
    session.run.side_effect = [nodes, edges]

    result = read_asset_network(session)

    assert result == {"nodes": nodes, "edges": edges}
    assert session.run.call_args_list == [
        call(ASSET_NETWORK_NODES_QUERY), call(ASSET_NETWORK_EDGES_QUERY),
    ]


def test_read_asset_detail_runs_query_with_node_id_and_returns_rows():
    session = MagicMock()
    rows = [{"cve_id": "CVE-2023-1234", "base_score": 8.8, "epss_score": 0.94, "technique_ids": ["T1190"]}]
    session.run.return_value = rows

    result = read_asset_detail(session, "computer-0001")

    assert result == rows
    session.run.assert_called_once_with(ASSET_DETAIL_QUERY, node_id="computer-0001")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_dashboard_graph_explorer_queries.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dashboard._graph_explorer_queries'`

- [ ] **Step 3: Write minimal implementation**

```python
# dashboard/_graph_explorer_queries.py
"""Cypher queries for the Graph Explorer page: the 80-asset topology
network plus per-asset CVE/technique drill-down -- see
docs/superpowers/specs/2026-08-11-dashboard-design.md, Page 3: Graph
Explorer. Scoped to :Asset nodes only, not the full CVE/Technique graph."""

ASSET_NETWORK_NODES_QUERY = """
MATCH (a:Asset)
RETURN a.node_id AS node_id, a.display_name AS display_name, a.node_type AS node_type,
       a.criticality_tier AS criticality_tier, a.blast_radius AS blast_radius,
       a.choke_point_count AS choke_point_count
""".strip()

ASSET_NETWORK_EDGES_QUERY = """
MATCH (s:Asset)-[r:RUNS|CONNECTS_TO|MEMBER_OF|HAS_SESSION|CONTROLS]->(t:Asset)
RETURN s.node_id AS source_id, t.node_id AS target_id, type(r) AS rel_type
""".strip()

ASSET_DETAIL_QUERY = """
MATCH (c:CVE)-[:AFFECTS]->(a:Asset {node_id: $node_id})
OPTIONAL MATCH (c)-[:MAPS_TO]->(t:Technique)
RETURN c.cve_id AS cve_id, c.base_score AS base_score, c.epss_score AS epss_score,
       collect(DISTINCT t.technique_id) AS technique_ids
ORDER BY c.base_score DESC
""".strip()


def read_asset_network(session) -> dict:
    nodes = [dict(record) for record in session.run(ASSET_NETWORK_NODES_QUERY)]
    edges = [dict(record) for record in session.run(ASSET_NETWORK_EDGES_QUERY)]
    return {"nodes": nodes, "edges": edges}


def read_asset_detail(session, node_id: str) -> list[dict]:
    return [dict(record) for record in session.run(ASSET_DETAIL_QUERY, node_id=node_id)]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_dashboard_graph_explorer_queries.py -v`
Expected: PASS

- [ ] **Step 5: Write the Graph Explorer page (not unit-tested here — verified live in Task 5)**

```python
# dashboard/pages/2_Graph_Explorer.py
"""Graph Explorer page: interactive asset network + per-asset CVE/technique
drill-down -- see docs/superpowers/specs/2026-08-11-dashboard-design.md,
Page 3: Graph Explorer."""
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

from _graph_explorer_queries import read_asset_detail, read_asset_network
from db import get_driver

st.set_page_config(page_title="Graph Explorer", layout="wide")
st.title("Asset Network")

with get_driver().session() as session:
    network_data = read_asset_network(session)

net = Network(height="600px", width="100%", directed=True, cdn_resources="in_line")
for node in network_data["nodes"]:
    blast_radius = node["blast_radius"] or 0
    choke_point_count = node["choke_point_count"] or 0
    net.add_node(
        node["node_id"],
        label=node["display_name"],
        title=f"{node['criticality_tier']} | blast radius {blast_radius} | choke point {choke_point_count}",
        value=blast_radius + 1,
        color="#d62728" if choke_point_count > 0 else "#1f77b4",
    )
for edge in network_data["edges"]:
    net.add_edge(edge["source_id"], edge["target_id"], title=edge["rel_type"])

components.html(net.generate_html(notebook=False), height=620, scrolling=True)

st.subheader("Asset Detail")
node_ids = [n["node_id"] for n in network_data["nodes"]]
selected_node_id = st.selectbox("Select an asset", options=node_ids)

with get_driver().session() as session:
    cves = read_asset_detail(session, selected_node_id)

if cves:
    for row in cves:
        techniques = ", ".join(row["technique_ids"]) or "No mapped technique"
        st.write(f"**{row['cve_id']}** (CVSS {row['base_score']}, EPSS {row['epss_score']}) — {techniques}")
else:
    st.write("No known CVEs affect this asset.")
```

- [ ] **Step 6: Commit**

```bash
git add dashboard/_graph_explorer_queries.py dashboard/pages/2_Graph_Explorer.py tests/test_dashboard_graph_explorer_queries.py
git commit -m "feat: add dashboard Graph Explorer page"
```

---

### Task 5: Live verification against the local Neo4j

**Files:** None tracked in git (`.env` is gitignored — this task only exercises already-committed code against a live database, mirroring the Path Engine and Reasoning Agent plans' final live-run task).

**Interfaces:** None (verification task).

- [ ] **Step 1: Run each page headlessly with Streamlit's official test API**

```bash
set -a; source .env; set +a
python3 -c "
from streamlit.testing.v1 import AppTest

at = AppTest.from_file('dashboard/app.py', default_timeout=30).run()
print('Overview exception:', at.exception)
assert not at.exception, at.exception
assert len(at.metric) == 2, f'expected 2 metrics, got {len(at.metric)}'
print('Overview metrics:', [(m.label, m.value) for m in at.metric])

# Use switch_page, not a second AppTest.from_file() call: AppTest.from_file()
# treats the given script as its own entrypoint (that script's own directory
# goes on sys.path), which breaks the pages' bare imports. switch_page keeps
# app.py as the entrypoint, matching how Streamlit actually resolves
# sys.path for real multipage navigation -- verified directly against this
# failure mode during Task 5. Paths passed to switch_page are relative to
# the entrypoint's directory (dashboard/), not the CWD.
at2 = at.switch_page('pages/1_Attack_Paths.py').run()
print('Attack Paths exception:', at2.exception)
assert not at2.exception, at2.exception

at3 = at.switch_page('pages/2_Graph_Explorer.py').run()
print('Graph Explorer exception:', at3.exception)
assert not at3.exception, at3.exception
print('All three pages ran with no exceptions.')
"
```

Expected: `Overview exception: ElementList()`, `Attack Paths exception: ElementList()`, `Graph Explorer exception: ElementList()` (empty means no error), 2 Overview metrics printed, and the final confirmation line. If any page raises, the printed exception names the file and line — fix before proceeding (this is still TDD: a failure here is a real bug the unit tests couldn't catch, since it only surfaces against the real schema).

- [ ] **Step 2: Manually launch the full app and click through it**

```bash
set -a; source .env; set +a
streamlit run dashboard/app.py
```

Open the printed local URL in a browser. Confirm: Overview shows non-zero "Attack Paths Found" and a populated criticality bar chart; Attack Paths table is sortable and selecting a row updates the detail panel below (expect "Not resolved for this path" text for MITRE fields — see contract 05's `known_limitations`, this is expected, not a bug); Graph Explorer renders an interactive 80-node network and the asset dropdown shows CVE/technique details for at least one asset. Stop the server (Ctrl-C) when done.

No commit for this task — it verifies already-committed code against a live database; no tracked file changes.

---

## Out of scope for this plan

- Auth/deployment beyond local `streamlit run` (see design spec, Scope).
- Live/auto-refresh — data is static per pipeline run.
- Editing the graph from the UI.
- Rendering CVE/Technique nodes as first-class Graph Explorer nodes (scoped to the 80-asset network; CVEs/techniques only appear in the per-asset detail panel).
