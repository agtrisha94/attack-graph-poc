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
