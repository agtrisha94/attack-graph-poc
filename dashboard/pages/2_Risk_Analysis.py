"""Risk Analysis page: choke points (which assets sit on the most ranked
attack routes -- depends on stage 4's :AttackPath output) and blast radius
(how many assets are reachable from a CVE-exploitable start -- computed
live, independent of stage 4) -- see
docs/superpowers/plans/since-assets-are-synthetic-lexical-gizmo.md, Part 2,
Page 3."""
import math

import pandas as pd
import streamlit as st

from _chat_widget import render_chat_trigger
from _graph_render import render_graph
from _risk_analysis_queries import (
    read_blast_radius,
    read_choke_points,
    read_paths_through_asset,
    read_reachable_subgraph,
)
from db import get_driver

st.set_page_config(page_title="Risk Analysis", layout="wide")
render_chat_trigger()
st.title("Risk Analysis")

# jump-from-chatbot support -- read once, consumed by whichever of the two
# selectors below actually has this asset; cleared immediately so it doesn't
# keep re-forcing the selection on later interactions with this page.
jump_asset_id = st.query_params.get("asset_id")
if jump_asset_id:
    del st.query_params["asset_id"]

st.header("Choke points")
st.caption(
    "Choke point = how many of the top-ranked attack routes pass through "
    "this asset as an intermediate hop (not as the route's own start or "
    "end). Computed by the Path Engine (scripts/find_paths.py, stage 4)."
)

with get_driver().session() as session:
    choke_points = read_choke_points(session)

choke_df = pd.DataFrame(choke_points)
if choke_df.empty:
    st.info("No choke-point data yet — run scripts/find_paths.py first.")
else:
    if jump_asset_id and jump_asset_id in choke_df["asset_id"].values:
        st.session_state.choke_asset_select = jump_asset_id
    st.bar_chart(choke_df, x="display_name", y="choke_point_count", sort="-choke_point_count")
    selected_choke_asset = st.selectbox(
        "Show attack paths through", options=choke_df["asset_id"],
        format_func=lambda aid: choke_df.set_index("asset_id").loc[aid, "display_name"],
        key="choke_asset_select",
        on_change=lambda: st.session_state.update(
            chat_context=f"Asset {st.session_state.choke_asset_select}",
        ),
    )
    st.write("**Selected asset:**", choke_df.set_index("asset_id").loc[[selected_choke_asset]])
    with get_driver().session() as session:
        through_paths = read_paths_through_asset(session, selected_choke_asset)
    st.dataframe(pd.DataFrame(through_paths), hide_index=True)

st.header("Blast radius")
st.caption(
    "Blast radius = how many distinct assets are reachable (any topology "
    "relationship, up to 6 hops) from an asset that has at least one "
    "exploitable CVE. Computed live from the current graph."
)

with get_driver().session() as session:
    blast_radii = read_blast_radius(session)

blast_df = pd.DataFrame(blast_radii)
if blast_df.empty:
    st.info("No CVE-exploitable assets found.")
else:
    if jump_asset_id and jump_asset_id in blast_df["asset_id"].values:
        st.session_state.blast_asset_select = jump_asset_id
    st.bar_chart(blast_df, x="display_name", y="blast_radius", sort="-blast_radius")
    selected_blast_asset = st.selectbox(
        "Show reachable assets from", options=blast_df["asset_id"],
        format_func=lambda aid: blast_df.set_index("asset_id").loc[aid, "display_name"],
        key="blast_asset_select",
        on_change=lambda: st.session_state.update(
            chat_context=f"Asset {st.session_state.blast_asset_select}",
        ),
    )
    st.write("**Selected asset:**", blast_df.set_index("asset_id").loc[[selected_blast_asset]])
    with get_driver().session() as session:
        subgraph = read_reachable_subgraph(session, selected_blast_asset)

    start_row = blast_df.set_index("asset_id").loc[selected_blast_asset]
    mini_node_properties: dict[str, dict] = {
        selected_blast_asset: {"type": "Asset (start)", **start_row.to_dict()},
    }
    # Radial "blast radius" layout: ground zero at the origin, everything
    # else placed on a ring sized by its hop-distance and spread evenly
    # around that ring -- fixed positions (physics off) so the rings stay
    # exactly concentric instead of drifting under force simulation.
    RING_SPACING = 150
    nodes_by_hop: dict[int, list[dict]] = {}
    for n in subgraph["nodes"]:
        nodes_by_hop.setdefault(n["hop_distance"], []).append(n)

    mini_nodes = [{
        "id": selected_blast_asset, "label": start_row["display_name"],
        "color": "#ff7f0e", "size": 30, "title": "Start asset (ground zero)",
        "x": 0, "y": 0, "fixed": True,
    }]
    for hop in sorted(nodes_by_hop):
        ring_nodes = nodes_by_hop[hop]
        radius = hop * RING_SPACING
        for i, n in enumerate(ring_nodes):
            angle = 2 * math.pi * i / len(ring_nodes)
            mini_node_properties[n["node_id"]] = {"type": "Asset (reachable)", **n}
            mini_nodes.append({
                "id": n["node_id"], "label": n["display_name"], "color": "#1f77b4",
                "size": 20, "title": f"{n['node_type']} | {n['criticality_tier']} | {hop} hop(s) away",
                "x": radius * math.cos(angle), "y": radius * math.sin(angle), "fixed": True,
            })
    mini_edges = [
        {"source": e["source_id"], "target": e["target_id"], "label": e["rel_type"]}
        for e in subgraph["edges"]
    ]
    st.caption(
        f"{len(mini_nodes)} reachable node(s) (including start), {len(mini_edges)} edge(s) -- "
        "arranged in rings by hop-distance from the start asset, like a blast radius."
    )
    clicked_id = render_graph(mini_nodes, mini_edges, height=450, physics=False)

    st.sidebar.header("Selected node (blast-radius graph)")
    if clicked_id and clicked_id in mini_node_properties:
        st.sidebar.json(mini_node_properties[clicked_id])
    else:
        st.sidebar.write("Click a node in the blast-radius graph to see its properties.")
