# Attack Graph Dashboard Design

## Mission

Give a live, browsable view of the whole pipeline's output — attack paths,
their grounded explanations, and the underlying asset graph — for demoing
to others, not just querying via `cypher-shell`.

## Scope

- **Audience:** demo to stakeholders/teammates, running locally against the
  existing `docker-compose` Neo4j. No auth, no deployment.
- **Read-only.** The dashboard never writes to the graph; all pipeline
  writes stay in `scripts/*.py`.
- **Reuses existing data.** No new analysis logic — every number and graph
  the dashboard shows already exists in Neo4j, written by Agents 3-5
  (`:Asset.blast_radius`/`.choke_point_count`, `:AttackPath`, `:Reasoning`).
- **Out of scope:** editing/annotating the graph from the UI, historical
  trend views (nothing in the graph is timestamped for that yet), the full
  26k-node CVE graph (the Graph Explorer scopes to the 80-asset network,
  not CVEs/techniques as first-class graph nodes).

## Tech Stack

- **Streamlit** (new dependency) — multipage app, `streamlit run dashboard/app.py`.
- **pyvis** (new dependency) — renders the asset network as a self-contained
  HTML/JS graph, embedded via Streamlit's `components.html`. Chosen over
  hand-rolled SVG/D3 because it needs zero custom JS and over
  `streamlit-agraph` because pyvis is a thinner, more directly-maintained
  wrapper around vis.js with a simpler API for this use case (static graph,
  no need for st-native click round-tripping).
- `neo4j` driver, `pandas` (already installed) for the Attack Paths table.

## Architecture

```
dashboard/
  app.py            # Overview page (Streamlit's default landing page)
  db.py             # get_driver() -- same NEO4J_URI/USER/PASSWORD env
                     # pattern as scripts/find_paths.py; wrapped in
                     # st.cache_resource so Streamlit reuses one driver
                     # across reruns instead of opening a new connection
                     # on every widget interaction. Pages call
                     # get_driver().session() themselves, context-managed.
  pages/
    1_Attack_Paths.py
    2_Graph_Explorer.py
```

Streamlit auto-discovers `pages/*.py` for multipage nav — no router to
write. `db.py` is the only module every page imports. Each page's Cypher
queries live as small, page-scoped functions in a co-located `_queries.py`
(e.g. `dashboard/pages/_attack_paths_queries.py`) — testable by direct
import, not defined inline in the Streamlit script itself. No shared
query-builder abstraction across pages — there's no reuse across pages to
justify one.

## Page 1: Overview (`app.py`)

Risk-focused stat tiles, each a single Cypher aggregate:
- Total `:AttackPath` count.
- Count of distinct `target_asset_id` values among `:AttackPath` nodes
  whose `target_criticality_tier` is `"Crown Jewel"` (i.e. Crown Jewel
  assets actually targeted by a found path, not general graph
  reachability).
- Top 5 assets by `choke_point_count`.
- Top 5 assets by `blast_radius`.
- Bar chart: path count grouped by `target_criticality_tier`.

## Page 2: Attack Paths

- Sortable table: CVE, base score, EPSS, source asset → target asset,
  target criticality, hop count. Same row shape `read_attack_paths`
  already returns, left-joined with `:Reasoning` (`explanation`,
  `technique_ids`, `threat_actors`, `mitigations` via `:EXPLAINED_BY`).
- Selecting a row expands a detail panel: full explanation text and the
  technique/threat-actor/mitigation lists. Rows where those lists are
  empty (per contract 05's `known_limitations` — currently all 50, since
  the top-50 paths' CVEs don't overlap the technique-mapped CVE set) show
  "Not resolved for this path" rather than blank space, so it reads as
  expected behavior, not a bug.

## Page 3: Graph Explorer

- pyvis network diagram of the 80 `:Asset` nodes and their ~530
  relationships (`RUNS`/`CONNECTS_TO`/`MEMBER_OF`/`HAS_SESSION`/`CONTROLS`).
  Node size or color scaled by `blast_radius`/`choke_point_count`.
- A dropdown (not graph click-events, which don't round-trip cleanly from
  pyvis's embedded HTML into Streamlit's rerun model) to pick an asset and
  show its affecting CVEs and mapped ATT&CK techniques in a side panel.

## Testing

Cypher-query-returning functions (e.g. "build the Overview stat query
set", "build the asset-network query") get unit tests against a fake
session, mirroring the existing `tests/test_reasoning_read_paths.py`
pattern (assert query shape + assert function maps records to expected
dicts). Full-page rendering is not unit-tested — Streamlit page scripts are
thin composition over already-tested query functions, and are verified by
actually running the app (`streamlit run`) and checking each page renders,
per this project's UI-verification norm.

## Out of scope for this design

- Auth/deployment beyond local `streamlit run`.
- Live/auto-refresh (data is static per pipeline run; a manual page reload
  is sufficient for a demo).
- Editing the graph from the UI.
- Rendering CVE/Technique nodes in the Graph Explorer (scoped to assets).
