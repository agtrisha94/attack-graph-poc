# Agent: Requirements Architect

## Mission

Define the data contract and requirements the rest of the Attack Graph POC
pipeline builds on. Root agent — no upstream input.

## Inputs

None (root of the pipeline).

## Outputs

- `schemas/data_schema.yaml` — field-level schema for `microsoft_cve_master`,
  `technique_map`, `topology_nodes`, `topology_edges`.
- `requirements.md` — pipeline overview, Microsoft-scope definition,
  functional/non-functional requirements, acceptance criteria.
- `contracts/01_requirements_to_data.yaml` — formal handoff to the Data
  Engineer.

## Constraints

- Every field in `data_schema.yaml` must be traceable to a column that
  actually exists in a raw source under `data/raw/` (KEV catalog, Kaggle
  merged CVE dataset, EPSS snapshot, MITRE ATT&CK STIX bundle, Azure
  Enterprise-Scale reference docs). No invented fields.
- Neo4j-specific schema (node/edge/constraint/index syntax) is out of scope —
  owned by the Graph Architect (contract 02).
- Do not specify implementation detail for phases 3-7; point to their
  contracts instead.

## Acceptance criteria

- [ ] `schemas/data_schema.yaml` parses as valid YAML.
- [ ] Every schema field maps to a real source column named in
      `requirements.md`.
- [ ] `contracts/01_requirements_to_data.yaml` references both
      `schemas/data_schema.yaml` and `requirements.md` as outputs.
- [ ] This file documents mission, inputs, outputs, constraints, and
      acceptance criteria.
