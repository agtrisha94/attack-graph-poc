# Watchdog Agent (Agent 6) Design

## Mission

Consume the :AttackPath/:Reasoning baseline Agent 5 left (contract 05),
simulate a real-world graph change via a deterministic synthetic scenario
injector, re-score affected paths, diff the result against the baseline, and
persist the diff as :Alert nodes -- then hand off contract 06 to QA & Docs.

## Scope

- **No live feed deviation:** requirements.md specifies "real-time edge
  monitoring." This is a static synthetic dataset with no live feed -- both
  path-engine-design.md and reasoning-agent-design.md explicitly deferred
  this to Agent 6 rather than fake it early. This phase ships a synthetic
  scenario injector (src/watchdog/scenario.py) instead: three deterministic,
  parameterized Cypher mutations against specific already-existing CVE/Asset
  nodes (a KEV disclosure, an EPSS update, a new topology edge), standing in
  for what a live feed would eventually push. Same shape of behavior a real
  feed-driven watchdog would trigger on (re-score -> diff -> alert), fully
  reproducible with no network dependency. Upgrade path: replace
  scenario.py's mutation source with a real feed poller later;
  rescore.py/writeback.py's signatures don't need to change. No fabricated
  CVEs, assets, or topology facts (NFR2/NFR3) -- every mutation targets a
  real, already-existing node in the live graph.
- **Watchdog does not rewrite :AttackPath/:Reasoning:** re-running Agent 4's
  clear_previous_results/write_attack_paths would DETACH DELETE every
  :AttackPath node before re-MERGEing, severing Agent 5's :EXPLAINED_BY
  edges even for paths whose path_id is unchanged (a deleted node isn't the
  same node a later MERGE recreates). Watchdog treats rescoring as read-only
  analysis for diffing/alerting; it mutates only the scenario's CVE/Asset/
  edge and writes :Alert nodes. A future phase that wants the persisted
  :AttackPath set to reflect live state would need to re-run Agent 4 and
  Agent 5 together, not addressed here.
- **Alert output = Neo4j :Alert nodes + printed summary.** No dashboard page
  in this phase (dashboard/ is untouched) -- explicitly out of scope, could
  be a future phase per the dashboard design's own scope notes.
- **Out of scope:** live threat-intel/topology feed integration, a Watchdog
  dashboard page, configurable/tunable alert thresholds (fixed defaults
  only -- YAGNI), alerting on anything besides the three fixed diff types
  below, re-running Reasoning Agent explanations for newly-entered paths.

## Architecture

Same split as Agents 3-5: pure functions over a passed-in Neo4j session,
plus a thin orchestrator.

```
src/watchdog/
  __init__.py
  scenario.py    # apply_kev_disclosure, apply_epss_spike,
                 # apply_new_topology_edge -- deterministic, idempotent
                 # Cypher mutations against specific real CVE/Asset IDs
  rescore.py     # read_baseline_paths(session) -> {path_id: {...}};
                 # diff_paths(baseline, rescored_routes) -> list[alert dict],
                 # SCORE_CHANGE_THRESHOLD = 0.20 (fixed default)
  writeback.py   # clear_previous_alerts, write_alerts -- MERGE (:Alert
                 # {alert_id}), same idempotent idiom as src/paths/writeback.py

scripts/watch_paths.py   # orchestrator CLI: connect, read baseline, apply
                          # the 3 scenario mutations, re-extract/re-rank via
                          # src.paths.extract (reused, not reimplemented),
                          # diff, write Alert nodes, print summary --
                          # mirrors scripts/reason_paths.py

contracts/06_watchdog_to_qa.yaml   # handoff to Agent 7 (QA & Docs)
agents/watchdog/prompt.md           # mission doc, same format as
                                     # agents/reasoning_agent/prompt.md
tests/test_watchdog_scenario.py
tests/test_watchdog_rescore.py
tests/test_watchdog_writeback.py
tests/test_watch_paths.py
```

No new dependencies. Reuses src/paths/{score,extract,writeback}.py
directly: extract_candidate_paths/dedupe_and_rank for re-scoring (path_id is
stable and deterministic per path_id_for, verified against
src/paths/writeback.py), path_id_for itself for matching rescored routes
back to baseline path_ids.

## Scenario injector

Three fixed, parameterized mutations (defaults chosen against the live
graph, verified to produce a real, non-trivial score change). Each is a
single idempotent Cypher statement (SET/MERGE), no separate read-then-write
round trip:

- apply_kev_disclosure(session, cve_id="CVE-2009-0133") -- flips kev_flag
  false -> true on an existing baseline-sourcing CVE (currently sources 5 of
  the top-50 paths; doubles their score via the KEV 2x multiplier in
  score_path).
- apply_epss_spike(session, cve_id="CVE-2024-29988", new_epss=0.95) --
  bumps epss_score on the CVE currently sourcing the rank-50 (bottom of
  top-50) path from 0.45151 to 0.95.
- apply_new_topology_edge(session, source_asset_id="computer-0078",
  target_asset_id="computer-0160") -- MERGEs a CONNECTS_TO edge between two
  existing Assets (edge type fixed to CONNECTS_TO -- relationship types
  can't be Cypher parameters, so unlike the CVE args this one is hardcoded
  rather than accepted as an argument). Shortens the existing 4-hop
  computer-0078 -> computer-0160 route to 1 hop. allShortestPaths (used by
  src/paths/extract.py) returns only minimum-length matches, so the old
  4-hop route's path_id disappears from the candidate set entirely and a
  new 1-hop path_id appears -- demonstrating both dropped_from_top50 and
  new_top50_entry from a single realistic mutation ("a new network
  connection/misconfigured firewall rule shortens an attacker's route").

scripts/watch_paths.py applies all three unconditionally on every run -- a
single-command demo. All three are idempotent: a second run is a no-op
mutation (kev_flag already true, epss_score already 0.95, edge already
MERGEd) and produces zero new alerts, which is correct incremental-
monitoring behavior, not a bug.

## Re-score + diff logic

src/watchdog/rescore.py:

- read_baseline_paths(session) -> dict[str, dict] reads the current
  :AttackPath set (Agent 5's handoff state, before any mutation this run)
  keyed by path_id.
- After the orchestrator applies the scenario mutations, it re-runs
  extract_candidate_paths + dedupe_and_rank(candidates, top_n=50) from
  src/paths/extract.py unmodified -- this is the "incremental re-scoring"
  contract 05/FR8 calls for, reusing Agent 4's exact scoring logic rather
  than reimplementing it.
- diff_paths(baseline, rescored_routes) -> list[dict] computes path_id for
  each rescored route via src.paths.writeback.path_id_for and classifies
  exactly three alert types, fixed thresholds, not configurable:
  - new_top50_entry: path_id in the rescored top-50, absent from baseline.
  - score_change: path_id in both sets, abs(new_score - old_score) /
    old_score > 0.20 (20% -- clearly above float noise, comfortably below
    the ~2x/~2.1x swings the two CVE mutations actually produce).
  - dropped_from_top50: path_id in baseline, absent from the rescored
    top-50 (either outscored past the top-50 cut, or -- as with the
    topology mutation -- no longer returned by allShortestPaths at all).
  "Baseline" here means the persisted top-50 set at handoff time, per
  contract 05's own definition -- not the full unranked candidate universe,
  so a new_top50_entry may have existed as a low-ranked, unpersisted
  candidate before the mutation; Watchdog has no visibility into that and
  doesn't claim otherwise.

## Alert node shape and write-back

```
(:Alert {
  alert_id: string,          # f"{alert_type}:{path_id}" -- MERGE key,
                              # deterministic, no timestamp (keeps repeated
                              # runs idempotent and output reproducible)
  alert_type: string,        # "new_top50_entry" | "score_change" |
                              # "dropped_from_top50"
  path_id: string,
  old_score: float | null,
  new_score: float | null,
  old_rank: int | null,
  new_rank: int | null,
  source_cve: string,
  source_asset_id: string,
  target_asset_id: string,
})
```

No relationship to :AttackPath -- a dropped_from_top50 alert's path may no
longer have a corresponding node at all (Watchdog doesn't rewrite the
:AttackPath set, see Scope), so a plain string path_id property (not a
graph edge) is the only option that works for all three alert types
uniformly. clear_previous_alerts DETACH DELETEs stale :Alert nodes before
each run writes fresh ones, same idempotency reasoning as Agents 4-5.
Writes use MERGE on alert_id, consistent with the established pattern.

scripts/watch_paths.py prints: each mutation's before/after value, the
candidate/route counts from re-extraction, and an alert-type breakdown with
total written -- mirrors scripts/find_paths.py/scripts/reason_paths.py's
summary-line style.

## Testing

Same TDD pattern as Agents 3-5:

- scenario.py unit-tested with unittest.mock.MagicMock() sessions --
  asserting Cypher substrings and params, not a live DB.
- rescore.py is pure-logic (diff_paths) tested with hand-built
  baseline/rescored dict fixtures, no mocks; read_baseline_paths mocked
  like src/paths/extract.py's tests.
- writeback.py mocked the same way as src/paths/writeback.py's tests.
- scripts/watch_paths.py gets a unittest.mock.patch-everything orchestrator
  test (same shape as tests/test_reason_paths.py) plus a live integration
  run against the local Neo4j (already populated by Agents 3-5).

## Contract 06 (watchdog_to_qa)

Documents for Agent 7 (QA & Docs):

- The :Alert node shape above, and that alerts have no graph relationship
  to :AttackPath (see Write-back model for why).
- :AttackPath/:Reasoning are unchanged by this phase except for the
  CVE/Asset property values and one new topology edge the scenario injector
  applies -- Watchdog does not re-run Agent 4/5's writeback.
- src/watchdog/'s public functions as the queryable interface.
- consumer_must_validate checklist: every :Alert.alert_type is one of the
  three fixed values; score_change/new_top50_entry/dropped_from_top50
  alerts have the expected non-null score/rank fields for their type;
  alert_id is unique per :Alert node (MERGE key).
- known_limitations: exact alert counts depend on the top-50 cutoff cascade
  (a new high-scoring path entering can push an unrelated marginal path out
  even though that path's own CVE/asset facts didn't change) -- QA should
  assert minimum expected alert counts per mutation, not exact totals.

## Out of scope for this design

- Live threat-intel/topology feed integration (see scope deviation above).
- A Watchdog dashboard page.
- Configurable/tunable alert thresholds.
- Re-running Reasoning Agent explanations for newly-entered paths.
- Rewriting the persisted :AttackPath/:Reasoning set to reflect
  post-mutation state.
