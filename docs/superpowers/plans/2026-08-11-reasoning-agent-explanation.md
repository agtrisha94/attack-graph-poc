# Reasoning Agent (Agent 5) Explanation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Agent 5 (Reasoning Agent) layer that reads Agent 4's `(:AttackPath)` nodes, grounds each in real MITRE ATT&CK threat-actor and mitigation data, generates a template-based explanation, and writes the result back into Neo4j as `(:Reasoning)` nodes linked via `:EXPLAINED_BY` — then hands off contract 05 and the agent's own prompt doc.

**Architecture:** Four small pure-function modules split by responsibility (`src/reasoning/mitre_lookup.py` for parsing the MITRE CTI STIX bundle into technique-grounded threat-actor/mitigation facts, `src/reasoning/read_paths.py` for the Cypher query that reads `:AttackPath`+`:CVE`+`:Technique` facts, `src/reasoning/explain.py` for the pure string template, `src/reasoning/writeback.py` for the `MERGE`/`SET` statements) and a thin orchestrator (`scripts/reason_paths.py`) that wires them together, mirroring `scripts/find_paths.py`. A live local Neo4j is running in this environment, already populated with 50 `:AttackPath` nodes by Agent 4, so the last task runs the real pipeline end-to-end against it.

**Tech Stack:** Python 3.11, `neo4j` 5.28.4 driver, pytest 9.1.1 (all already installed — no new dependency; no LLM SDK, no live API call).

## Global Constraints

- **No new dependencies.** MITRE STIX parsing uses stdlib `json`/`pathlib`, same pattern as `src/ingestion/technique_map.py`. No LLM SDK — this phase ships a deterministic template, not a live API call (no `ANTHROPIC_API_KEY` available in this environment; see design spec's "LLM deviation").
- **Grounding source:** `data/raw/mitre-cti/enterprise-attack/enterprise-attack.json`. Threat actors = `uses` relationships whose `source_ref` starts `intrusion-set--` (the bundle's `uses` relationship type is also emitted by `malware`/`tool`/`campaign` source objects, which must be excluded — they are not threat-actor groups). Mitigations = `mitigates` relationships (`source_ref` always `course-of-action--` in this bundle, no filtering needed). Both resolved to names via each object's `id`/`name`, keyed by the target `attack-pattern`'s ATT&CK `technique_id` (from `external_references`, `source_name == "mitre-attack"`).
- **No invented facts.** A path whose `source_cve` has no `MAPS_TO` Technique edge still gets a `:Reasoning` node — `technique_ids`/`threat_actors`/`mitigations` are empty lists, never fabricated or omitted.
- **Idempotent writes.** Every write uses `MERGE`, never bare `CREATE` — `path_id` (already assigned by Agent 4) is the merge key for `:Reasoning`, consistent with Agents 3-4's import pattern.
- **No invented properties.** Every `:Reasoning` field traces to the design spec (`docs/superpowers/specs/2026-08-11-reasoning-agent-design.md`) — no field beyond what's documented there.
- Follow TDD: write the failing test, confirm it fails, implement, confirm it passes, commit.
- A live local Neo4j (`neo4j:5-community`, via `docker-compose.yml`) is running in this environment (container `attack-graph-poc-neo4j-1`), already populated by Agents 3-4: 50 `:AttackPath` nodes exist, 5678 distinct `:CVE` nodes have a `MAPS_TO` edge to a `:Technique`. The checked-in `.env` password already matches the running container (verified directly) — no sync step needed, unlike Agent 4's plan.

---

## File Structure

- `src/reasoning/__init__.py` — empty, package marker.
- `src/reasoning/mitre_lookup.py` — `STIX_PATH`, `build_technique_facts(stix_path=STIX_PATH) -> dict[str, dict[str, list[str]]]` (`technique_id -> {"threat_actors": [...], "mitigations": [...]}`, both deduped and sorted), `resolve_facts_for_techniques(technique_ids, technique_facts) -> dict` (unions facts across a path's mapped technique_ids into `{"threat_actors": [...], "mitigations": [...]}`).
- `src/reasoning/explain.py` — `build_explanation(path: dict, resolved_facts: dict) -> str`.
- `src/reasoning/read_paths.py` — `READ_PATHS_QUERY`, `read_attack_paths(session) -> list[dict]`.
- `src/reasoning/writeback.py` — `clear_previous_results(session) -> None`, `write_reasoning(session, rows: list[dict]) -> int`.
- `scripts/reason_paths.py` — orchestrator CLI: connect, clear stale results, read paths, resolve MITRE facts, build explanations, write back, print summary.
- `contracts/05_baseline_to_watchdog.yaml` — Agent 5's handoff to the Watchdog agent.
- `agents/reasoning_agent/prompt.md` — Agent 5's mission doc, same format as `agents/path_engine/prompt.md`.
- `tests/test_reasoning_mitre_lookup.py`, `tests/test_reasoning_explain.py`, `tests/test_reasoning_read_paths.py`, `tests/test_reasoning_writeback.py`, `tests/test_reason_paths.py`.

---

### Task 1: MITRE grounding lookup (`src/reasoning/mitre_lookup.py`)

**Files:**
- Create: `src/reasoning/__init__.py` (empty)
- Create: `src/reasoning/mitre_lookup.py`
- Test: `tests/test_reasoning_mitre_lookup.py`

**Interfaces:**
- Produces: `STIX_PATH: pathlib.Path`, `build_technique_facts(stix_path: pathlib.Path = STIX_PATH) -> dict[str, dict[str, list[str]]]`, `resolve_facts_for_techniques(technique_ids: list[str], technique_facts: dict[str, dict[str, list[str]]]) -> dict[str, list[str]]`. Consumed by Task 5 (`scripts/reason_paths.py`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reasoning_mitre_lookup.py
import json

from src.reasoning.mitre_lookup import build_technique_facts, resolve_facts_for_techniques


def _bundle(objects):
    return {"objects": objects}


def test_build_technique_facts_maps_intrusion_set_uses_to_threat_actors(tmp_path):
    bundle = _bundle([
        {
            "type": "attack-pattern", "id": "attack-pattern--ap1", "name": "Exploit Public-Facing Application",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
        },
        {"type": "intrusion-set", "id": "intrusion-set--g1", "name": "APT38"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--g1", "target_ref": "attack-pattern--ap1"},
    ])
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    result = build_technique_facts(stix_path)

    assert result == {"T1190": {"threat_actors": ["APT38"], "mitigations": []}}


def test_build_technique_facts_excludes_non_intrusion_set_uses_relationships(tmp_path):
    bundle = _bundle([
        {
            "type": "attack-pattern", "id": "attack-pattern--ap1", "name": "Exploit Public-Facing Application",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
        },
        {"type": "malware", "id": "malware--m1", "name": "Not A Threat Actor"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "malware--m1", "target_ref": "attack-pattern--ap1"},
    ])
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    result = build_technique_facts(stix_path)

    assert result == {}


def test_build_technique_facts_maps_course_of_action_mitigates_to_mitigations(tmp_path):
    bundle = _bundle([
        {
            "type": "attack-pattern", "id": "attack-pattern--ap1", "name": "Exploit Public-Facing Application",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
        },
        {"type": "course-of-action", "id": "course-of-action--c1", "name": "Vulnerability Scanning"},
        {"type": "relationship", "relationship_type": "mitigates", "source_ref": "course-of-action--c1", "target_ref": "attack-pattern--ap1"},
    ])
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    result = build_technique_facts(stix_path)

    assert result == {"T1190": {"threat_actors": [], "mitigations": ["Vulnerability Scanning"]}}


def test_build_technique_facts_dedupes_and_sorts_names(tmp_path):
    bundle = _bundle([
        {
            "type": "attack-pattern", "id": "attack-pattern--ap1", "name": "T",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
        },
        {"type": "intrusion-set", "id": "intrusion-set--g1", "name": "Zeta Group"},
        {"type": "intrusion-set", "id": "intrusion-set--g2", "name": "Alpha Group"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--g1", "target_ref": "attack-pattern--ap1"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--g2", "target_ref": "attack-pattern--ap1"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--g1", "target_ref": "attack-pattern--ap1"},
    ])
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    result = build_technique_facts(stix_path)

    assert result["T1190"]["threat_actors"] == ["Alpha Group", "Zeta Group"]


def test_resolve_facts_for_techniques_unions_across_multiple_technique_ids():
    technique_facts = {
        "T1190": {"threat_actors": ["APT38"], "mitigations": ["Vulnerability Scanning"]},
        "T1059": {"threat_actors": ["Lazarus Group"], "mitigations": ["Vulnerability Scanning"]},
    }

    result = resolve_facts_for_techniques(["T1190", "T1059"], technique_facts)

    assert result == {
        "threat_actors": ["APT38", "Lazarus Group"],
        "mitigations": ["Vulnerability Scanning"],
    }


def test_resolve_facts_for_techniques_empty_technique_ids_returns_empty_lists():
    assert resolve_facts_for_techniques([], {"T1190": {"threat_actors": ["APT38"], "mitigations": []}}) == {
        "threat_actors": [], "mitigations": [],
    }


def test_resolve_facts_for_techniques_unknown_technique_id_yields_empty_lists():
    assert resolve_facts_for_techniques(["T9999"], {}) == {"threat_actors": [], "mitigations": []}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reasoning_mitre_lookup.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.reasoning'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/reasoning/mitre_lookup.py
"""Grounds ATT&CK technique IDs in real threat-actor and mitigation facts
from the MITRE CTI STIX bundle -- no invented names (see
docs/superpowers/specs/2026-08-11-reasoning-agent-design.md, MITRE
grounding)."""
import json
import pathlib

STIX_PATH = pathlib.Path("data/raw/mitre-cti/enterprise-attack/enterprise-attack.json")


def _technique_id_of(attack_pattern: dict) -> str | None:
    return next(
        (r["external_id"] for r in attack_pattern.get("external_references", [])
         if r.get("source_name") == "mitre-attack"),
        None,
    )


def build_technique_facts(stix_path: pathlib.Path = STIX_PATH) -> dict[str, dict[str, list[str]]]:
    objects = json.loads(stix_path.read_text())["objects"]

    id_to_name = {o["id"]: o["name"] for o in objects if "id" in o and "name" in o}
    technique_id_by_ap_id = {
        o["id"]: _technique_id_of(o) for o in objects if o.get("type") == "attack-pattern"
    }

    facts: dict[str, dict[str, set[str]]] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel_type = obj.get("relationship_type")
        source_ref = obj.get("source_ref", "")
        technique_id = technique_id_by_ap_id.get(obj.get("target_ref"))
        if not technique_id:
            continue

        if rel_type == "uses" and source_ref.startswith("intrusion-set--"):
            key = "threat_actors"
        elif rel_type == "mitigates" and source_ref.startswith("course-of-action--"):
            key = "mitigations"
        else:
            continue

        name = id_to_name.get(source_ref)
        if not name:
            continue
        entry = facts.setdefault(technique_id, {"threat_actors": set(), "mitigations": set()})
        entry[key].add(name)

    return {
        technique_id: {
            "threat_actors": sorted(entry["threat_actors"]),
            "mitigations": sorted(entry["mitigations"]),
        }
        for technique_id, entry in facts.items()
    }


def resolve_facts_for_techniques(
    technique_ids: list[str], technique_facts: dict[str, dict[str, list[str]]]
) -> dict[str, list[str]]:
    threat_actors: set[str] = set()
    mitigations: set[str] = set()
    for technique_id in technique_ids:
        entry = technique_facts.get(technique_id, {"threat_actors": [], "mitigations": []})
        threat_actors.update(entry["threat_actors"])
        mitigations.update(entry["mitigations"])
    return {"threat_actors": sorted(threat_actors), "mitigations": sorted(mitigations)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_reasoning_mitre_lookup.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/reasoning/__init__.py src/reasoning/mitre_lookup.py tests/test_reasoning_mitre_lookup.py
git commit -m "feat: add MITRE ATT&CK threat-actor/mitigation grounding lookup (Agent 5)"
```

---

### Task 2: Explanation template (`src/reasoning/explain.py`)

**Files:**
- Create: `src/reasoning/explain.py`
- Test: `tests/test_reasoning_explain.py`

**Interfaces:**
- Consumes: nothing directly (takes plain dicts shaped like `read_attack_paths`' output (Task 3) and `resolve_facts_for_techniques`' output (Task 1), by shape convention, not by import).
- Produces: `build_explanation(path: dict, resolved_facts: dict) -> str`. `path` requires keys `source_cve`, `base_score`, `epss_score`, `source_asset_id`, `target_asset_id`, `target_criticality_tier`, `hop_count`, `technique_ids`. `resolved_facts` requires keys `threat_actors`, `mitigations`. Consumed by Task 5.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reasoning_explain.py
from src.reasoning.explain import build_explanation


def _path(**overrides):
    base = {
        "source_cve": "CVE-2023-1234", "base_score": 8.8, "epss_score": 0.94,
        "source_asset_id": "computer-0002", "target_asset_id": "sql-prod-01",
        "target_criticality_tier": "Crown Jewel", "hop_count": 3, "technique_ids": [],
    }
    base.update(overrides)
    return base


def test_build_explanation_covers_path_facts_with_no_technique():
    result = build_explanation(_path(technique_ids=[]), {"threat_actors": [], "mitigations": []})

    assert result == (
        "CVE-2023-1234 (CVSS 8.8, EPSS 0.94) exploits computer-0002 and reaches "
        "sql-prod-01 (Crown Jewel) via 3 hop(s)."
    )


def test_build_explanation_appends_technique_and_grounded_facts():
    result = build_explanation(
        _path(technique_ids=["T1190"]),
        {"threat_actors": ["APT29", "APT38", "Lazarus Group"], "mitigations": ["Vulnerability Scanning"]},
    )

    assert "Maps to ATT&CK technique(s) T1190." in result
    assert "Used by APT29, APT38, Lazarus Group." in result
    assert "Mitigations: Vulnerability Scanning." in result


def test_build_explanation_caps_long_lists_with_a_remainder_count():
    result = build_explanation(
        _path(technique_ids=["T1190"]),
        {"threat_actors": ["A", "B", "C", "D", "E"], "mitigations": []},
    )

    assert "Used by A, B, C, and 2 other(s)." in result


def test_build_explanation_notes_absence_of_threat_actors_and_mitigations():
    result = build_explanation(_path(technique_ids=["T1190"]), {"threat_actors": [], "mitigations": []})

    assert "No known threat-actor group on record." in result
    assert "No known mitigation on record." in result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reasoning_explain.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.reasoning.explain'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/reasoning/explain.py
"""Builds a grounded, deterministic explanation string for an AttackPath --
a template stand-in for a live LLM call (see
docs/superpowers/specs/2026-08-11-reasoning-agent-design.md, LLM deviation
and Explanation template). Never states a fact not present in `path` or
`resolved_facts`."""


def _format_list(names: list[str], cap: int = 3) -> str:
    if len(names) <= cap:
        return ", ".join(names)
    shown = ", ".join(names[:cap])
    remaining = len(names) - cap
    return f"{shown}, and {remaining} other(s)"


def build_explanation(path: dict, resolved_facts: dict) -> str:
    base = (
        f"{path['source_cve']} (CVSS {path['base_score']}, EPSS {path['epss_score']}) "
        f"exploits {path['source_asset_id']} and reaches {path['target_asset_id']} "
        f"({path['target_criticality_tier']}) via {path['hop_count']} hop(s)."
    )

    technique_ids = path.get("technique_ids") or []
    if not technique_ids:
        return base

    threat_actors = resolved_facts.get("threat_actors", [])
    mitigations = resolved_facts.get("mitigations", [])

    actor_sentence = (
        f" Used by {_format_list(threat_actors)}."
        if threat_actors else " No known threat-actor group on record."
    )
    mitigation_sentence = (
        f" Mitigations: {_format_list(mitigations)}."
        if mitigations else " No known mitigation on record."
    )

    return (
        f"{base} Maps to ATT&CK technique(s) {', '.join(technique_ids)}."
        f"{actor_sentence}{mitigation_sentence}"
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_reasoning_explain.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/reasoning/explain.py tests/test_reasoning_explain.py
git commit -m "feat: add grounded attack-path explanation template (Agent 5)"
```

---

### Task 3: Read AttackPaths from Neo4j (`src/reasoning/read_paths.py`)

**Files:**
- Create: `src/reasoning/read_paths.py`
- Test: `tests/test_reasoning_read_paths.py`

**Interfaces:**
- Consumes: nothing (queries the graph Agents 3-4 populated).
- Produces: `READ_PATHS_QUERY: str`, `read_attack_paths(session) -> list[dict]` (each dict has keys `path_id`, `source_cve`, `source_asset_id`, `target_asset_id`, `hop_count`, `base_score`, `epss_score`, `target_criticality_tier`, `technique_ids: list[str]`). Consumed by Task 5.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reasoning_read_paths.py
from unittest.mock import MagicMock

from src.reasoning.read_paths import READ_PATHS_QUERY, read_attack_paths


def test_read_paths_query_joins_cve_target_and_optional_technique():
    assert "AttackPath" in READ_PATHS_QUERY
    assert "MAPS_TO" in READ_PATHS_QUERY
    assert "OPTIONAL MATCH" in READ_PATHS_QUERY
    assert "collect(DISTINCT t.technique_id)" in READ_PATHS_QUERY


def test_read_attack_paths_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{
        "path_id": "abc123", "source_cve": "CVE-2023-1234", "source_asset_id": "computer-0002",
        "target_asset_id": "sql-prod-01", "hop_count": 3, "base_score": 8.8, "epss_score": 0.94,
        "target_criticality_tier": "Crown Jewel", "technique_ids": ["T1190"],
    }]
    session.run.return_value = rows

    result = read_attack_paths(session)

    assert result == rows
    session.run.assert_called_once_with(READ_PATHS_QUERY)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reasoning_read_paths.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.reasoning.read_paths'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/reasoning/read_paths.py
"""Reads AttackPath nodes and their source_cve's MAPS_TO Technique ids from
Neo4j for the Reasoning Agent to ground and explain (see
docs/superpowers/specs/2026-08-11-reasoning-agent-design.md)."""

READ_PATHS_QUERY = """
MATCH (p:AttackPath)
MATCH (c:CVE {cve_id: p.source_cve})
MATCH (target:Asset {node_id: p.target_asset_id})
OPTIONAL MATCH (c)-[:MAPS_TO]->(t:Technique)
RETURN p.path_id AS path_id, p.source_cve AS source_cve,
       p.source_asset_id AS source_asset_id, p.target_asset_id AS target_asset_id,
       p.hop_count AS hop_count, c.base_score AS base_score, c.epss_score AS epss_score,
       target.criticality_tier AS target_criticality_tier,
       collect(DISTINCT t.technique_id) AS technique_ids
""".strip()


def read_attack_paths(session) -> list[dict]:
    return [dict(record) for record in session.run(READ_PATHS_QUERY)]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_reasoning_read_paths.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/reasoning/read_paths.py tests/test_reasoning_read_paths.py
git commit -m "feat: add AttackPath+Technique read query for Reasoning Agent (Agent 5)"
```

---

### Task 4: Write-back (`src/reasoning/writeback.py`)

**Files:**
- Create: `src/reasoning/writeback.py`
- Test: `tests/test_reasoning_writeback.py`

**Interfaces:**
- Consumes: nothing directly (takes the row dicts the orchestrator assembles from Tasks 1-3's outputs, by shape convention).
- Produces: `clear_previous_results(session) -> None`, `write_reasoning(session, rows: list[dict]) -> int`. `rows` entries require keys `path_id`, `explanation`, `technique_ids`, `threat_actors`, `mitigations`. Consumed by Task 5.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reasoning_writeback.py
from unittest.mock import MagicMock

from src.reasoning.writeback import clear_previous_results, write_reasoning


def test_clear_previous_results_detach_deletes_reasoning_nodes():
    session = MagicMock()

    clear_previous_results(session)

    query = session.run.call_args[0][0]
    assert "MATCH (r:Reasoning)" in query
    assert "DETACH DELETE r" in query


def test_write_reasoning_merges_on_path_id_and_links_explained_by():
    session = MagicMock()
    rows = [{
        "path_id": "abc123", "explanation": "CVE-... exploits ... reaches ...",
        "technique_ids": ["T1190"], "threat_actors": ["APT38"], "mitigations": ["Vulnerability Scanning"],
    }]

    written = write_reasoning(session, rows)

    assert written == 1
    query, kwargs = session.run.call_args
    assert "MATCH (p:AttackPath {path_id: row.path_id})" in query[0]
    assert "MERGE (r:Reasoning {path_id: row.path_id})" in query[0]
    assert "MERGE (p)-[:EXPLAINED_BY]->(r)" in query[0]
    [row] = kwargs["rows"]
    assert row["path_id"] == "abc123"
    assert row["threat_actors"] == ["APT38"]


def test_write_reasoning_noop_on_empty_rows():
    session = MagicMock()

    assert write_reasoning(session, []) == 0
    session.run.assert_not_called()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reasoning_writeback.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.reasoning.writeback'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/reasoning/writeback.py
"""Persists Reasoning Agent results into Neo4j: one (:Reasoning) node per
AttackPath, linked via :EXPLAINED_BY (see
docs/superpowers/specs/2026-08-11-reasoning-agent-design.md, Write-back
model). MERGE-based, idempotent, consistent with Agents 3-4's import
pattern."""


def clear_previous_results(session) -> None:
    session.run("MATCH (r:Reasoning) DETACH DELETE r")


def write_reasoning(session, rows: list[dict]) -> int:
    if not rows:
        return 0
    session.run(
        "UNWIND $rows AS row "
        "MATCH (p:AttackPath {path_id: row.path_id}) "
        "MERGE (r:Reasoning {path_id: row.path_id}) "
        "SET r += row "
        "MERGE (p)-[:EXPLAINED_BY]->(r)",
        rows=rows,
    )
    return len(rows)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_reasoning_writeback.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/reasoning/writeback.py tests/test_reasoning_writeback.py
git commit -m "feat: add Reasoning node write-back to Neo4j (Agent 5)"
```

---

### Task 5: Orchestrator CLI (`scripts/reason_paths.py`)

**Files:**
- Create: `scripts/reason_paths.py`
- Test: `tests/test_reason_paths.py`

**Interfaces:**
- Consumes: `build_technique_facts`, `resolve_facts_for_techniques`, `STIX_PATH` (Task 1); `build_explanation` (Task 2); `read_attack_paths` (Task 3); `clear_previous_results`, `write_reasoning` (Task 4).
- Produces: `main() -> None`. Nothing downstream in this plan consumes it directly — it's the manual/CI entry point, mirroring `scripts/find_paths.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reason_paths.py
from unittest.mock import MagicMock, patch


def test_main_reads_resolves_explains_and_writes_back(monkeypatch, capsys):
    monkeypatch.setenv("NEO4J_PASSWORD", "test-password")
    fake_session = MagicMock()
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = fake_session

    paths = [{
        "path_id": "abc123", "source_cve": "CVE-2023-1234", "source_asset_id": "computer-0002",
        "target_asset_id": "sql-prod-01", "hop_count": 3, "base_score": 8.8, "epss_score": 0.94,
        "target_criticality_tier": "Crown Jewel", "technique_ids": ["T1190"],
    }]
    technique_facts = {"T1190": {"threat_actors": ["APT38"], "mitigations": []}}
    resolved = {"threat_actors": ["APT38"], "mitigations": []}

    with patch("scripts.reason_paths.GraphDatabase") as fake_gdb, \
         patch("scripts.reason_paths.build_technique_facts", return_value=technique_facts) as fake_build_facts, \
         patch("scripts.reason_paths.resolve_facts_for_techniques", return_value=resolved) as fake_resolve, \
         patch("scripts.reason_paths.build_explanation", return_value="explained.") as fake_explain, \
         patch("scripts.reason_paths.read_attack_paths", return_value=paths) as fake_read, \
         patch("scripts.reason_paths.clear_previous_results") as fake_clear, \
         patch("scripts.reason_paths.write_reasoning", return_value=1) as fake_write:
        fake_gdb.driver.return_value = fake_driver

        from scripts.reason_paths import main
        main()

        fake_build_facts.assert_called_once()
        fake_clear.assert_called_once_with(fake_session)
        fake_read.assert_called_once_with(fake_session)
        fake_resolve.assert_called_once_with(["T1190"], technique_facts)
        fake_explain.assert_called_once_with(paths[0], resolved)
        fake_write.assert_called_once_with(fake_session, [{
            "path_id": "abc123", "explanation": "explained.",
            "technique_ids": ["T1190"], "threat_actors": ["APT38"], "mitigations": [],
        }])

    captured = capsys.readouterr()
    assert "Read 1 AttackPath node(s), wrote 1 Reasoning node(s)" in captured.out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reason_paths.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.reason_paths'`

- [ ] **Step 3: Write minimal implementation**

```python
# scripts/reason_paths.py
"""Runs the full Agent 5 (Reasoning Agent) pipeline: read AttackPaths ->
resolve MITRE-grounded threat-actor/mitigation facts -> build a deterministic
explanation -> write results back into Neo4j as (:Reasoning) nodes linked
via :EXPLAINED_BY."""
import os
import sys

sys.path.insert(0, ".")

from neo4j import GraphDatabase  # noqa: E402

from src.reasoning.explain import build_explanation  # noqa: E402
from src.reasoning.mitre_lookup import (  # noqa: E402
    build_technique_facts,
    resolve_facts_for_techniques,
)
from src.reasoning.read_paths import read_attack_paths  # noqa: E402
from src.reasoning.writeback import clear_previous_results, write_reasoning  # noqa: E402


def main() -> None:
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]

    technique_facts = build_technique_facts()

    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        clear_previous_results(session)
        paths = read_attack_paths(session)

        rows = []
        for path in paths:
            resolved = resolve_facts_for_techniques(path["technique_ids"], technique_facts)
            rows.append({
                "path_id": path["path_id"],
                "explanation": build_explanation(path, resolved),
                "technique_ids": path["technique_ids"],
                "threat_actors": resolved["threat_actors"],
                "mitigations": resolved["mitigations"],
            })

        written = write_reasoning(session, rows)
    driver.close()

    print(f"Read {len(paths)} AttackPath node(s), wrote {written} Reasoning node(s)")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_reason_paths.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/reason_paths.py tests/test_reason_paths.py
git commit -m "feat: add Reasoning Agent pipeline orchestrator (Agent 5)"
```

---

### Task 6: Contract 05 and agent doc (no new logic — handoff docs)

**Files:**
- Modify: `contracts/05_baseline_to_watchdog.yaml` (currently empty placeholder)
- Modify: `agents/reasoning_agent/prompt.md` (currently empty placeholder)

**Interfaces:** None (docs only — no function signatures produced or consumed).

- [ ] **Step 1: Write `contracts/05_baseline_to_watchdog.yaml`**

```yaml
contract: 05_baseline_to_watchdog
producer: reasoning_agent
consumer: watchdog

inputs:
  - path: contracts/04_paths_to_reasoning.yaml
    description: The Neo4j graph and AttackPath set this phase reads and annotates.

outputs:
  - path: Neo4j graph database (bolt://$NEO4J_URI, credentials in .env, see .env.example)
    description: >
      Annotated in place by scripts/reason_paths.py. New node label:
      (:Reasoning {path_id, explanation, technique_ids: list[string],
      threat_actors: list[string], mitigations: list[string]}) -- one node
      per (:AttackPath), linked (:AttackPath)-[:EXPLAINED_BY]->(:Reasoning).
      explanation is a deterministic, template-generated narrative grounded
      in the path's CVE/asset facts and (where resolvable) its ATT&CK
      technique's real threat-actor and mitigation data from the MITRE CTI
      STIX bundle -- not a live LLM call (see
      docs/superpowers/specs/2026-08-11-reasoning-agent-design.md, LLM
      deviation, for why and the upgrade path). technique_ids/threat_actors/
      mitigations are empty lists, never null, when no MAPS_TO Technique
      edge or no matching MITRE relationship exists for this path's CVE.
      The "baseline" for Watchdog is this graph state as it exists at
      handoff time -- the current top-50 :AttackPath set plus their
      :Reasoning annotations; Watchdog's own re-scoring/diffing logic
      against future graph changes is that agent's own phase, not
      addressed here.
  - path: src/reasoning/{mitre_lookup,read_paths,explain,writeback}.py
    description: >
      Query module Watchdog can import directly instead of writing its own
      Cypher/STIX-parsing logic: build_technique_facts,
      resolve_facts_for_techniques, read_attack_paths, build_explanation.

consumer_must_validate:
  - "Every (:Reasoning).path_id matches an existing (:AttackPath {path_id})."
  - "(:Reasoning).threat_actors and (:Reasoning).mitigations are lists (possibly empty) of real MITRE ATT&CK names -- never null, never fabricated."
  - "(:Reasoning).explanation is non-empty."

handoff_status: ready
```

- [ ] **Step 2: Write `agents/reasoning_agent/prompt.md`**

```markdown
# Agent: Reasoning Agent

## Mission

Read the `(:AttackPath)` nodes Agent 4 built, ground each in real MITRE
ATT&CK threat-actor and mitigation data, generate an explanation, and write
the results back into the graph for the Watchdog Agent to consume.

## Inputs

- The Neo4j graph annotated by `scripts/find_paths.py` (per
  `contracts/04_paths_to_reasoning.yaml`): `(:AttackPath)` nodes, `:CVE`
  `MAPS_TO` `:Technique` edges.
- `data/raw/mitre-cti/enterprise-attack/enterprise-attack.json` -- the MITRE
  CTI STIX bundle, for threat-actor (`intrusion-set` `uses`) and mitigation
  (`course-of-action` `mitigates`) facts.

## Outputs

- `src/reasoning/mitre_lookup.py`, `src/reasoning/read_paths.py`,
  `src/reasoning/explain.py`, `src/reasoning/writeback.py`,
  `scripts/reason_paths.py`.
- `(:Reasoning)` nodes linked `(:AttackPath)-[:EXPLAINED_BY]->(:Reasoning)`.
- `contracts/05_baseline_to_watchdog.yaml` -- formal handoff to the
  Watchdog Agent.

## Constraints

- No live LLM call -- `requirements.md` calls for "LLM-powered" explanation,
  but no API key is available in this environment. `explain.py` ships a
  deterministic template instead; its function signature is designed so a
  real Claude API call can replace the template body later without changing
  callers.
- No fabricated threat-actor or mitigation facts -- both are resolved
  deterministically from the local MITRE CTI STIX bundle, never
  guessed or generated.
- Paths whose CVE has no `MAPS_TO` Technique edge still get a `:Reasoning`
  node -- `technique_ids`/`threat_actors`/`mitigations` are empty lists, not
  omitted.
- Writes are idempotent (`MERGE` on `path_id`), consistent with Agents 3-4's
  import pattern.

## Acceptance criteria

- [ ] `scripts/reason_paths.py` runs against a real Neo4j instance (the one
      `docker-compose.yml` provides, already populated by Agents 3-4) and
      exits 0.
- [ ] Every `(:AttackPath)` node has exactly one linked `(:Reasoning)` node
      via `:EXPLAINED_BY`.
- [ ] Every `(:Reasoning).threat_actors`/`mitigations` entry is a real MITRE
      ATT&CK name traceable to the STIX bundle -- never fabricated.
- [ ] `contracts/05_baseline_to_watchdog.yaml` documents the graph
      annotations and query module precisely enough for the Watchdog Agent
      to consume them without reading this repo's Reasoning Agent code.
```

- [ ] **Step 3: Verify the contract YAML still parses**

Run: `python3 -c "import yaml; yaml.safe_load(open('contracts/05_baseline_to_watchdog.yaml')); print('ok')"`
Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add contracts/05_baseline_to_watchdog.yaml agents/reasoning_agent/prompt.md
git commit -m "docs: add Reasoning Agent contract and agent prompt (Agent 5)"
```

---

### Task 7: Live run against the local Neo4j

**Files:** None tracked in git (`.env` is gitignored — this task only exercises already-committed code against a live database).

**Interfaces:** None (verification task).

- [ ] **Step 1: Run the pipeline**

```bash
set -a; source .env; set +a
python3 scripts/reason_paths.py
```

Expected: prints `Read 50 AttackPath node(s), wrote 50 Reasoning node(s)` (the local graph already has 50 `:AttackPath` nodes from Agent 4's run — verified directly via `cypher-shell` before writing this plan).

- [ ] **Step 2: Verify results directly against the graph**

```bash
docker compose exec neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
  "MATCH (p:AttackPath)-[:EXPLAINED_BY]->(r:Reasoning) RETURN count(r) AS reasoning_nodes;"
docker compose exec neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
  "MATCH (r:Reasoning) WHERE size(r.threat_actors) > 0 RETURN count(r) AS with_threat_actors;"
docker compose exec neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
  "MATCH (r:Reasoning) WHERE r.explanation IS NULL OR r.explanation = '' RETURN count(r) AS missing_explanation;"
```

Expected: `reasoning_nodes` = 50 (one per `:AttackPath`); `with_threat_actors` > 0 (at least some of the 50 paths' CVEs map to a technique with known threat-actor groups); `missing_explanation` = 0.

No commit for this task — it verifies already-committed code against a live database; no tracked file changes.

---

## Out of scope for this plan

- Live LLM calls (see design spec, LLM deviation).
- Real-time/incremental re-scoring and alerting -- that's Agent 6 (Watchdog), scoped by `contracts/05_baseline_to_watchdog.yaml`.
- CAPEC-level technique detail.
- Confidence scoring on threat-actor attribution.
