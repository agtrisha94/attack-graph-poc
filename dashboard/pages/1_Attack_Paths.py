"""Attack Paths page: ranked table + detail panel with grounded
explanation, an isolated path-chain graph for the selected row, and a
client-side "what-if" scoring playground -- see
docs/superpowers/plans/since-assets-are-synthetic-lexical-gizmo.md, Part 2,
Page 2."""
import pandas as pd
import streamlit as st

from _attack_paths_queries import (
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
df = df.sort_values("playground_score", ascending=False).reset_index(drop=True)
df["playground_rank"] = df.index + 1

display_columns = [
    "playground_rank", "rank", "source_cve", "base_score", "epss_score",
    "source_asset_id", "source_criticality_tier", "target_asset_id",
    "target_criticality_tier", "hop_count", "pipeline_score", "playground_score",
]

event = st.dataframe(
    df[display_columns],
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row-required",
)
selected_row = df.iloc[event["selection"]["rows"][0]]

st.subheader(f"{selected_row['source_cve']} -> {selected_row['target_asset_id']}")

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
    chain_nodes.append({"id": node_id, "label": node_id, "color": "#1f77b4", "size": 25})
    if i > 0:
        chain_edges.append({
            "source": node_ids[i - 1], "target": node_id,
            "label": edge_types.get(i - 1, "?"),
        })

render_graph(chain_nodes, chain_edges, height=350)

st.write(selected_row["explanation"] or "Not resolved for this path.")

technique_ids = selected_row["technique_ids"] or []
threat_actors = selected_row["threat_actors"] or []
mitigations = selected_row["mitigations"] or []

st.write("**MITRE ATT&CK Techniques:**", ", ".join(technique_ids) or "Not resolved for this path.")
st.write("**Threat Actors:**", ", ".join(threat_actors) or "Not resolved for this path.")
st.write("**Mitigations:**", ", ".join(mitigations) or "Not resolved for this path.")
