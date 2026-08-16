# Agent: QA & Docs

## Mission

Verify, against the live pipeline output (not mocks), that every one of the
6 contracts' `consumer_must_validate` checklists actually holds -- then
write the docs that let a new reader run the whole 7-agent pipeline and see
it work. Terminal phase: no downstream contract.

## Inputs

- The Neo4j graph and `:Alert` nodes handed off by `scripts/watch_paths.py`
  (per `contracts/06_watchdog_to_qa.yaml`).
- Every prior contract (`contracts/01_requirements_to_data.yaml` through
  `contracts/06_watchdog_to_qa.yaml`) -- this phase's job is to check all of
  them, not just the most recent handoff.
- `src/graph/validate.py`'s `validate_graph`, `src/paths/score.py`'s
  `score_path` -- reused directly rather than reimplemented.

## Outputs

- `tests/acceptance/conftest.py`, `tests/acceptance/test_contracts.py`.
- `docs/architecture.md`, `docs/demo_walkthrough.md`.

## Constraints

- Tests connect to the real running Neo4j instance and read the real
  processed CSVs -- no mocking, no skip-if-down (a live-verification suite
  that silently skips proves nothing).
- Reports violations, does not fix them -- a failing acceptance test names a
  bug in whichever phase produced the bad data, not something for this
  phase to patch over.
- No new `src/` package -- this phase has no reusable business logic of its
  own.

## Acceptance criteria

- [ ] `python3 -m pytest tests/acceptance/test_contracts.py -v` passes all 6
      contract checks against the live pipeline output.
- [ ] `docs/architecture.md` covers all 7 agents, the contract chain, and
      the Neo4j graph model.
- [ ] `docs/demo_walkthrough.md` gives a new reader runnable commands to
      reproduce the pipeline end to end and confirm it worked at each step.
