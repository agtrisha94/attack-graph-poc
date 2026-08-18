"""Graph Explorer page: the attack-relevant subgraph (Assets + the CVEs that
exploit them + the Techniques those CVEs map to), colored by node type and
sized by score/criticality, with a click-to-inspect sidebar -- see
docs/superpowers/plans/since-assets-are-synthetic-lexical-gizmo.md, Part 2,
Page 1. Streamlit auto-loads this as the default landing page."""
import pandas as pd
import streamlit as st

from _chat_widget import render_chat_trigger
from _graph_explorer_queries import read_attack_relevant_subgraph
from _graph_render import render_graph
from db import get_driver

st.set_page_config(page_title="Graph Explorer", layout="wide")
render_chat_trigger()
st.title("Graph Explorer")

TIER_ORDER = ["Crown Jewel", "High", "Medium", "Low"]
TIER_SIZE = {"Crown Jewel": 40, "High": 30, "Medium": 20, "Low": 10}
TYPE_COLOR = {"Asset": "#1f77b4", "CVE": "#d62728", "Technique": "#2ca02c"}
CROWN_JEWEL_COLOR = "#ffd700"

st.markdown("🔵 Asset  |  🟡 Asset — Crown Jewel  |  🔴 CVE  |  🟢 ATT&CK Technique")
st.caption(
    "Node size reflects CVSS score (CVEs) or criticality tier (Assets); "
    "larger = higher."
)

with get_driver().session() as session:
    subgraph = read_attack_relevant_subgraph(session)

assets = pd.DataFrame(subgraph["assets"])
cves = pd.DataFrame(subgraph["cves"])
techniques = pd.DataFrame(subgraph["techniques"])
all_edges = pd.DataFrame(
    subgraph["topology_edges"] + subgraph["affects_edges"] + subgraph["maps_to_edges"]
)

# Property lookup for the click-to-inspect sidebar, keyed by node id, built
# from the full unfiltered subgraph so a previously-clicked node stays
# inspectable even if a filter changes after the click.
node_properties: dict[str, dict] = {}
for _, row in assets.iterrows():
    node_properties[row["node_id"]] = {"type": "Asset", **row.to_dict()}
for _, row in cves.iterrows():
    node_properties[row["cve_id"]] = {"type": "CVE", **row.to_dict()}
for _, row in techniques.iterrows():
    node_properties[row["technique_id"]] = {"type": "Technique", **row.to_dict()}

col_filters, col_graph = st.columns([1, 3])

with col_filters:
    st.subheader("Filters")
    type_filter = st.multiselect(
        "Node types", ["Asset", "CVE", "Technique"], default=["Asset"],
        help="CVE nodes are off by default -- there can be thousands once the "
             "graph is scaled up, and rendering them all at once makes the "
             "force-directed layout hang. Use the severity cap below when "
             "you turn them on. Technique nodes only connect to CVEs "
             "(no direct Asset edge), so they render as a disconnected ring "
             "unless CVE is also on -- off by default for the same reason.",
    )
    tier_filter = st.multiselect(
        "Asset criticality tier", TIER_ORDER, default=TIER_ORDER,
    )
    max_cve_nodes = None
    if "CVE" in type_filter and not cves.empty:
        max_cve_nodes = st.slider(
            "Max CVE nodes to show (highest severity first)",
            min_value=10, max_value=len(cves), value=min(200, len(cves)),
            help="Bounds how many CVE nodes get laid out -- the graph "
                 "widget can hang well before the full CVE set fits.",
        )

graph_nodes = []
included_ids: set[str] = set()

if "Asset" in type_filter and not assets.empty:
    shown_assets = assets[assets["criticality_tier"].isin(tier_filter)]
    for _, row in shown_assets.iterrows():
        included_ids.add(row["node_id"])
        is_crown_jewel = row["criticality_tier"] == "Crown Jewel"
        graph_nodes.append({
            "id": row["node_id"],
            "label": row["display_name"],
            "color": CROWN_JEWEL_COLOR if is_crown_jewel else TYPE_COLOR["Asset"],
            "size": TIER_SIZE.get(row["criticality_tier"], 15),
            "title": f"{row['node_type']} | {row['criticality_tier']}",
        })

if "CVE" in type_filter and not cves.empty:
    shown_cves = cves.sort_values("base_score", ascending=False)
    if max_cve_nodes is not None:
        shown_cves = shown_cves.head(max_cve_nodes)
    for _, row in shown_cves.iterrows():
        included_ids.add(row["cve_id"])
        graph_nodes.append({
            "id": row["cve_id"],
            "label": row["cve_id"],
            "color": TYPE_COLOR["CVE"],
            "size": 10 + (row["base_score"] or 0) * 3,
            "title": f"{row['vendor']} {row['product']} | CVSS {row['base_score']} "
                     f"EPSS {row['epss_score']} | KEV={row['kev_flag']}",
        })

if "Technique" in type_filter and not techniques.empty:
    for _, row in techniques.iterrows():
        included_ids.add(row["technique_id"])
        graph_nodes.append({
            "id": row["technique_id"],
            "label": row["technique_id"],
            "color": TYPE_COLOR["Technique"],
            "size": 20,
            "title": row["technique_name"],
        })

graph_edges = []
if not all_edges.empty:
    shown_edges = all_edges[
        all_edges["source_id"].isin(included_ids) & all_edges["target_id"].isin(included_ids)
    ]
    graph_edges = [
        {"source": row["source_id"], "target": row["target_id"], "label": row["rel_type"]}
        for _, row in shown_edges.iterrows()
    ]

with col_graph:
    st.caption(f"{len(graph_nodes)} node(s), {len(graph_edges)} edge(s) shown.")
    clicked_id = render_graph(graph_nodes, graph_edges)

st.sidebar.header("Selected node")
if clicked_id and clicked_id in node_properties:
    props = node_properties[clicked_id]
    st.session_state.chat_context = f"{props['type']} {clicked_id}"
    if props["type"] == "Asset":
        blast_radius = props.get("blast_radius")
        choke_point_count = props.get("choke_point_count")
        st.sidebar.metric(
            "Blast radius",
            blast_radius if blast_radius is not None else "—",
            help="Distinct assets reachable within 5 hops from this asset, "
                 "computed only for assets that are a CVE-exploitable entry "
                 "point on a ranked attack path. \"—\" means this asset isn't "
                 "one of those entry points.",
        )
        st.sidebar.metric(
            "Choke point count",
            choke_point_count if choke_point_count is not None else "—",
            help="Number of the top-50 ranked attack paths that pass through "
                 "this asset as an intermediate hop. \"—\" means it's not a "
                 "choke point on any ranked path.",
        )
    st.sidebar.json(props)
else:
    st.sidebar.write("Click a node in the graph to see its properties.")

st.sidebar.header("Edges")
st.sidebar.caption(
    "Node clicks round-trip to Python; edge clicks don't (streamlit-agraph "
    "only wires a node-select event), so edges are listed here instead."
)
if not all_edges.empty:
    edge_type_options = sorted({e["label"] for e in graph_edges})
    edge_type_filter = st.sidebar.multiselect(
        "Filter by edge type", edge_type_options, default=edge_type_options,
    )
    edge_source_options = sorted(included_ids)
    edge_focus = st.sidebar.selectbox(
        "Show edges touching", options=["(all shown)"] + edge_source_options,
    )

    filtered_edges = [e for e in graph_edges if e["label"] in edge_type_filter]
    if edge_focus != "(all shown)":
        filtered_edges = [e for e in filtered_edges if edge_focus in (e["source"], e["target"])]

    st.sidebar.dataframe(
        pd.DataFrame(filtered_edges)[["source", "target", "label"]] if filtered_edges
        else pd.DataFrame(columns=["source", "target", "label"]),
        hide_index=True,
    )
