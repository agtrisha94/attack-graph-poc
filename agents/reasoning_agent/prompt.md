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
