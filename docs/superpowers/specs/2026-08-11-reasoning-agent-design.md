# Reasoning Agent (Agent 5) Design

## Mission

Consume the `:AttackPath` graph Agent 4 built (contract 04), ground each path
in real MITRE ATT&CK threat-actor and mitigation data, generate an
explanation, and hand off a queryable result to the Watchdog Agent (Agent 6)
via contract 05.

## Scope

- **LLM deviation:** `requirements.md` specifies "LLM-powered" explanation.
  No Anthropic API key is available in this environment, so this phase ships
  a deterministic template instead: same shape of output (explanation +
  threat-actor mapping + remediation) an LLM call would produce, but fully
  reproducible and unit-testable with no network dependency or per-run cost.
  Upgrade path: swap `src/reasoning/explain.py`'s template body for a real
  Claude API call later; its function signature
  (`build_explanation(path, technique_facts) -> str`) doesn't need to change.
- **Grounding, not generation:** threat-actor and mitigation facts are never
  invented. They're resolved deterministically from the MITRE ATT&CK STIX
  bundle already present at `data/raw/mitre-cti/enterprise-attack/enterprise-attack.json`
  (same file Agent 2 used to build `technique_map.csv`), matching
  `requirements.md` NFR2/NFR3 (provenance, no fabricated claims).
- **Out of scope:** live LLM calls, real-time/incremental re-scoring
  (Watchdog's job), CAPEC-level technique detail, confidence scoring on
  threat-actor attribution.

## Architecture

Same split as Agents 3/4: pure functions, unit-testable without a live DB or
network call, plus a thin orchestrator.

```
src/reasoning/
  __init__.py
  mitre_lookup.py   # load STIX bundle once; build technique_id ->
                     # {threat_actors: [...], mitigations: [...]}
  explain.py         # pure function: build_explanation(path, technique_facts)
                      # -> str (template, no I/O)
  writeback.py        # MERGE (:Reasoning {path_id}) nodes, MERGE
                       # (:AttackPath)-[:EXPLAINED_BY]->(:Reasoning)

scripts/reason_paths.py   # orchestrator CLI: connect, read AttackPaths +
                           # their source_cve's MAPS_TO Technique(s) from
                           # Neo4j, resolve MITRE facts, build explanation,
                           # write back -- mirrors scripts/find_paths.py

contracts/05_baseline_to_watchdog.yaml   # handoff to Agent 6
agents/reasoning_agent/prompt.md          # mission doc, same format as
                                           # agents/path_engine/prompt.md
tests/test_reasoning_mitre_lookup.py
tests/test_reasoning_explain.py
tests/test_reasoning_writeback.py
tests/test_reason_paths.py
```

No new dependencies -- STIX parsing reuses the `json`/`pathlib` pattern
already established in `src/ingestion/technique_map.py`.

## MITRE grounding

Verified directly against the bundle: 18,457 `uses` relationships and 1,448
`mitigates` relationships.

- **Threat actors:** `uses` relationships where `source_ref` starts
  `intrusion-set--` (the `uses` relationship type is also used by
  `malware`/`tool`/`campaign` source objects in this bundle, which must be
  excluded -- they aren't threat-actor groups), `target_ref` an
  `attack-pattern`. Resolved to the intrusion-set's `name` (e.g. "APT38",
  "Lazarus Group").
- **Mitigations:** `mitigates` relationships, `source_ref` a
  `course-of-action`, `target_ref` an `attack-pattern`. `mitigates` is not
  used by any other source type in this bundle, so no filtering needed.
  Resolved to the course-of-action's `name`.
- Both sides resolved via an `id -> name` map built once per STIX object
  type. `mitre_lookup.py` builds the full `technique_id -> {threat_actors,
  mitigations}` dict once per run (~20k relationship objects, sub-second in
  plain Python); `attack-pattern` objects are matched to `technique_id` via
  `external_references` (`source_name == "mitre-attack"`), same as
  `technique_map.py`.

## Explanation template

For each `:AttackPath`: read `source_cve`'s `base_score`/`epss_score` from
its `:CVE` node, resolve its `MAPS_TO` `:Technique` edge(s) (a CVE can carry
multiple CWEs and so map to more than one technique -- contract 03), union
threat-actors/mitigations across all mapped techniques, dedupe, sort
alphabetically (determinism -- makes output reproducible and testable).

Paths whose CVE has no `MAPS_TO` edge at all (contract 03's documented case:
"produce no MAPS_TO edge rather than a fabricated one") still get a
`:Reasoning` node -- the explanation covers path/CVE/asset facts only,
`technique_ids`/`threat_actors`/`mitigations` are empty lists, never omitted
or null. An explicit "none found" is more useful to a consumer than a
missing node.

Template, capped at 3 named entries + a count of the rest for readability
(full deduped lists still stored as node properties):

```
{source_cve} (CVSS {base_score}, EPSS {epss_score}) exploits {source_asset_id}
and reaches {target_asset_id} ({criticality_tier}) via {hop_count} hop(s).
[Maps to ATT&CK technique(s) {technique_ids}. Used by {threat_actors[:3]}
[and N other known threat actor group(s)]. Mitigations: {mitigations[:3]}
[and N other(s)].]
```

The bracketed technique/threat-actor/mitigation sentence is omitted entirely
when `technique_ids` is empty.

## Write-back model

```
(:Reasoning {
  path_id: string,             # = source AttackPath.path_id, MERGE key
  explanation: string,
  technique_ids: list[string],    # may be empty
  threat_actors: list[string],    # deduped, sorted, may be empty
  mitigations: list[string],      # deduped, sorted, may be empty
})
(:AttackPath)-[:EXPLAINED_BY]->(:Reasoning)
```

`clear_previous_results` deletes stale `:Reasoning` nodes (and their
`:EXPLAINED_BY` edges via `DETACH DELETE`) before a re-run writes fresh
ones, same idempotency reasoning as Agent 4's writeback (a re-run's AttackPath
set can shift, e.g. a different subset of a tie group at the top-50 cut).
Writes use `MERGE` on `path_id`, consistent with Agents 3 and 4.

## Testing

Same TDD pattern as Agents 3/4:

- `mitre_lookup.py` is pure JSON parsing over the real bundle -- tested
  directly against `data/raw/mitre-cti/...` (it's already a checked-in
  fixture-sized file, same as `test_technique_map.py` does for Agent 2's
  extractor), no mocks needed.
- `explain.py` is pure string templating over plain dicts -- tested with
  hand-built path/technique_facts fixtures, no I/O.
- `writeback.py` unit-tested with `unittest.mock.MagicMock()` sessions,
  asserting Cypher text and params passed to `session.run(...)`.
- `scripts/reason_paths.py` gets an integration smoke test against the local
  Neo4j instance (already populated by Agents 3 and 4).

## Contract 05 (baseline_to_watchdog)

Documents for Agent 6:

- The `:Reasoning` node shape and `:EXPLAINED_BY` edge above.
- `src/reasoning/`'s public functions as the queryable interface.
- The "baseline" Watchdog consumes is the current graph state as it exists in
  Neo4j at handoff time -- the top-50 `:AttackPath` set plus their
  `:Reasoning` annotations. Watchdog's own re-scoring/diffing logic against
  future graph changes is that agent's phase, not designed here.
- `consumer_must_validate` checklist: every `:Reasoning.path_id` matches an
  existing `:AttackPath.path_id`; `threat_actors`/`mitigations` are lists
  (possibly empty) of real MITRE ATT&CK names, never null; `explanation` is
  non-empty.

## Out of scope for this design

- Live LLM calls (see LLM deviation above).
- Real-time/incremental re-scoring and alerting (Agent 6, Watchdog).
- CAPEC-level technique detail.
- Confidence scoring on threat-actor attribution.
