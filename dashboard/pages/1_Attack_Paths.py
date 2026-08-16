"""Attack Paths page: ranked table + detail panel with grounded
explanation, an isolated path-chain graph for the selected row, and a
client-side "what-if" scoring playground -- see
docs/superpowers/plans/since-assets-are-synthetic-lexical-gizmo.md, Part 2,
Page 2."""
import pandas as pd
import streamlit as st

from _attack_paths_queries import (
    ATTACK_VECTOR_WEIGHT,
    EXPOSURE_MULTIPLIER,
    KEV_MULTIPLIER,
    SOURCE_TIER_WEIGHT_DEFAULTS,
    read_attack_paths_with_reasoning,
    read_path_chain_edge_types,
)
from _graph_render import render_graph
from db import get_driver

st.set_page_config(page_title="Attack Paths", layout="wide")
st.title("Attack Paths")

with get_driver().session() as session:
    paths = read_attack_paths_with_reasoning(session)

df = pd.DataFrame(paths)
if df.empty:
    st.info(
        "No attack paths found — run scripts/find_paths.py first. "
        "(This build only ran through stage 3 of the pipeline, so no "
        ":AttackPath data exists yet.)"
    )
    st.stop()

st.subheader("Scoring playground")
st.caption(
    "The pipeline's real score weights by the path's TARGET asset's "
    "criticality tier -- but every attack path's target is Crown Jewel by "
    "definition of the query, so that weight can only rescale scores "
    "uniformly, never reorder them. This playground instead weights by the "
    "path's SOURCE asset's tier (which does vary), as a 'what-if' "
    "exploration -- distinct from the pipeline's real (target-tier) score, "
    "shown alongside it below. Nothing here is written back to Neo4j."
)
weight_cols = st.columns(4)
weights = {}
for col, tier in zip(weight_cols, ["Crown Jewel", "High", "Medium", "Low"]):
    weights[tier] = col.slider(tier, 0, 10, SOURCE_TIER_WEIGHT_DEFAULTS[tier])

df["playground_score"] = df["base_score"] * df["epss_score"] * df["source_criticality_tier"].map(weights)
# Rank by playground_score without reordering df's rows -- the table stays
# sorted by the real pipeline rank (highest real score at top, as fetched
# via "ORDER BY p.rank"); playground_rank just shows where each row WOULD
# land under the what-if weights.
df["playground_rank"] = df["playground_score"].rank(ascending=False, method="min").astype(int)

display_columns = [
    "playground_rank", "rank", "source_cve", "base_score", "epss_score",
    "kev_flag", "attack_vector", "source_internet_facing",
    "source_asset_id", "source_criticality_tier", "target_asset_id",
    "target_criticality_tier", "hop_count", "pipeline_score", "playground_score",
]

event = st.dataframe(
    df[display_columns],
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row-required",
)

# path_idx is the source of truth for which path's detail is shown below;
# it can move via table clicks OR the Previous/Next browser. table_selected_idx
# tracks the table widget's own persisted selection so we only adopt it into
# path_idx on an actual new click, not on every rerun (e.g. a Previous/Next
# click reruns the script too, and the table's selection state would
# otherwise silently overwrite the button's change back to the old row).
if "path_idx" not in st.session_state:
    st.session_state.path_idx = 0
    st.session_state.table_selected_idx = None

table_idx = event["selection"]["rows"][0] if event["selection"]["rows"] else None
if table_idx is not None and table_idx != st.session_state.table_selected_idx:
    st.session_state.path_idx = table_idx
st.session_state.table_selected_idx = table_idx
st.session_state.path_idx = min(st.session_state.path_idx, len(df) - 1)

nav_prev, nav_next, nav_label = st.columns([1, 1, 6])
if nav_prev.button("◀ Previous", disabled=st.session_state.path_idx == 0):
    st.session_state.path_idx -= 1
if nav_next.button("Next ▶", disabled=st.session_state.path_idx >= len(df) - 1):
    st.session_state.path_idx += 1
nav_label.caption(
    f"Browsing path {st.session_state.path_idx + 1} of {len(df)} in isolation "
    "— Previous/Next steps through every ranked path, or click any table row to jump directly."
)

selected_row = df.iloc[st.session_state.path_idx]

st.subheader(f"{selected_row['source_cve']} -> {selected_row['target_asset_id']}")

tier_weight = SOURCE_TIER_WEIGHT_DEFAULTS[selected_row["target_criticality_tier"]]
kev_mult = KEV_MULTIPLIER if selected_row["kev_flag"] else 1.0
exposure_mult = EXPOSURE_MULTIPLIER if selected_row["source_internet_facing"] else 1.0
av_weight = ATTACK_VECTOR_WEIGHT.get(selected_row["attack_vector"], 1.0)
hop_divisor = selected_row["hop_count"] + 1
st.caption(
    f"**Score {selected_row['pipeline_score']:.2f}** = "
    f"CVSS {selected_row['base_score']} "
    f"× EPSS {selected_row['epss_score']} "
    f"× target tier weight {tier_weight} ({selected_row['target_criticality_tier']}) "
    f"× KEV {kev_mult}x ({'known exploited' if selected_row['kev_flag'] else 'not KEV'}) "
    f"× exposure {exposure_mult}x ({'internet-facing source' if selected_row['source_internet_facing'] else 'not internet-facing'}) "
    f"× attack vector {av_weight}x ({selected_row['attack_vector'] or 'unknown'}) "
    f"÷ (hops + 1) {hop_divisor} ({selected_row['hop_count']} hops)"
)

node_ids = selected_row["node_ids"]
with get_driver().session() as session:
    edge_types = read_path_chain_edge_types(session, node_ids)

chain_nodes = [{
    "id": selected_row["source_cve"], "label": selected_row["source_cve"],
    "color": "#d62728", "size": 25,
    "title": f"CVSS {selected_row['base_score']} | EPSS {selected_row['epss_score']}",
}]
chain_edges = [{
    "source": selected_row["source_cve"], "target": node_ids[0],
    "label": f"CVSS {selected_row['base_score']} / EPSS {selected_row['epss_score']}",
}]
for i, node_id in enumerate(node_ids):
    is_target = i == len(node_ids) - 1  # last node is always the Crown Jewel target (query guarantee)
    chain_nodes.append({
        "id": node_id, "label": node_id,
        "color": "#ffd700" if is_target else "#1f77b4",  # matches Graph Explorer's Crown Jewel color
        "size": 40 if is_target else 25,
    })
    if i > 0:
        chain_edges.append({
            "source": node_ids[i - 1], "target": node_id,
            "label": edge_types.get(i - 1, "?"),
        })

st.caption("🔵 Asset  |  🟡 Asset — Crown Jewel (target)  |  🔴 Source CVE")
render_graph(chain_nodes, chain_edges, height=350)

st.write(selected_row["explanation"] or "Not resolved for this path.")

technique_ids = selected_row["technique_ids"] or []
threat_actors = selected_row["threat_actors"] or []
mitigations = selected_row["mitigations"] or []

if technique_ids:
    st.write("**MITRE ATT&CK Techniques:**", ", ".join(technique_ids))
    st.write("**Threat Actors:**", ", ".join(threat_actors) or "No known threat-actor group on record.")
    st.write("**Mitigations:**", ", ".join(mitigations) or "No known mitigation on record.")
