# Requirements — Attack Graph POC (Microsoft Enterprise)

## Overview

Proof-of-concept attack graph for Microsoft enterprise environments: real CVE
data (CISA KEV, EPSS, NVD/Kaggle-merged) mapped onto a synthetic enterprise
topology, scored by exploitability and business impact, and queryable for
attack paths, blast radius, and choke points. Built as a 7-agent structured
SDLC, each agent producing a defined output consumed by the next via a
handoff contract in `contracts/`.

## Pipeline (agent roles)

1. **Requirements Architect** (this phase) — defines `schemas/data_schema.yaml`
   and this document; no upstream input, root of the pipeline.
2. **Data Engineer** — ingests CISA KEV, EPSS, the Kaggle merged CVE dataset,
   and MITRE ATT&CK; produces `microsoft_cve_master.csv` and
   `technique_map.csv`; generates the synthetic enterprise topology
   (`nodes_*.csv`, `edges_*.csv`) grounded in Azure Enterprise-Scale reference
   architecture and AzureHound's object model. Consumes contract 01.
3. **Graph Architect** — Neo4j import scripts, node/edge constraints, and
   validation queries derived from `data_schema.yaml`. Consumes contract 02.
4. **Path Engine** — attack path extraction; scoring = CVSS × EPSS ×
   criticality; blast radius and choke-point analysis. Consumes contract 03.
5. **Reasoning Agent** — LLM-powered path explanation, threat-actor mapping,
   remediation suggestions. Consumes contract 04.
6. **Watchdog Agent** — real-time edge monitoring, incremental re-scoring,
   alerting. Consumes contract 05.
7. **QA & Docs** — acceptance tests and documentation for the full pipeline.

## Microsoft scope definition

A CVE or topology entry is in-scope only if it matches one of the vendor
aliases defined in `schemas/data_schema.yaml` → `microsoft_scope_filter`
(microsoft, windows, azure, office, exchange, sql server, .net, edge,
sharepoint, active directory). This is the single source of truth for the
filter; Agent 2 applies it and Agent 7 verifies it (zero out-of-scope rows).

## Functional requirements

### Phase 1 → 2 (this handoff, high detail)

- FR1: `schemas/data_schema.yaml` must define every field Agent 2 needs to
  produce `microsoft_cve_master.csv`, `technique_map.csv`, `nodes_*.csv`, and
  `edges_*.csv`, with each field traceable to a column in an actual file
  under `data/raw/` (no invented fields).
- FR2: Agent 2's merge logic — join
  `cve_cisa_epss_enriched_dataset.csv` + `cve_corpus.csv` on `cve_id`, left-join
  `kev_catalog.csv` for KEV enrichment, refresh EPSS from the live
  `api.first.org/data/v1/epss` feed (or latest `epss_scores-*.csv.gz` snapshot)
  — must run before the Microsoft-scope filter is applied.
- FR3: Synthetic topology generation must use
  `data/raw/azure-enterprise-scale/docs/reference` as the management-group /
  subscription shape, and must only assign `installed_software` values that
  exist in `microsoft_cve_master.product`, so every synthetic asset is
  attackable via a real CVE.
- FR4: `technique_map.csv` must be derived from
  `data/raw/mitre-cti/enterprise-attack/enterprise-attack.json`; Agent 2 must
  document the CWE↔technique cross-reference source used (ATT&CK does not
  embed CWEs on all technique objects).

### Phases 3-7 (pointers only — detailed at their own phase)

- FR5: Graph Architect output must satisfy contract 02 and pass constraint
  validation against `schemas/data_schema.yaml`.
- FR6: Path Engine scoring must satisfy contract 03 (CVSS × EPSS ×
  criticality formula, blast radius, choke points).
- FR7: Reasoning Agent output must satisfy contract 04 (explanation +
  threat-actor mapping + remediation, grounded in graph data — no fabricated
  claims).
- FR8: Watchdog Agent must satisfy contract 05 (incremental re-scoring on
  edge change, alerting).
- FR9: QA & Docs must produce acceptance tests covering every contract's
  `consumer_must_validate` checklist.

## Non-functional requirements

- NFR1: Reproducibility — every processed file records the source snapshot
  date(s) it was built from (EPSS score_date, KEV dateAdded range).
- NFR2: Provenance — every row in every processed CSV must be traceable back
  to a specific raw source file; no fabricated CVEs, scores, or topology
  facts.
- NFR3: No downstream agent invents data outside its contract's declared
  inputs.

## Acceptance criteria — this phase (Requirements Architect)

- [ ] `schemas/data_schema.yaml` parses as valid YAML.
- [ ] Every field in `schemas/data_schema.yaml` maps to a real column/source
      named in this document's Phase 1→2 requirements.
- [ ] `contracts/01_requirements_to_data.yaml` exists and references both
      `schemas/data_schema.yaml` and this file as outputs.
- [ ] `agents/requirements_architect/prompt.md` documents this agent's
      mission, inputs, outputs, and acceptance criteria.
