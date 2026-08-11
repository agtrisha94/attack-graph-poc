"""Graph Explorer page: interactive asset network + per-asset CVE/technique
drill-down -- see docs/superpowers/specs/2026-08-11-dashboard-design.md,
Page 3: Graph Explorer."""
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

from _graph_explorer_queries import read_asset_detail, read_asset_network
from db import get_driver

st.set_page_config(page_title="Graph Explorer", layout="wide")
st.title("Asset Network")

with get_driver().session() as session:
    network_data = read_asset_network(session)

net = Network(height="600px", width="100%", directed=True, cdn_resources="in_line")
for node in network_data["nodes"]:
    blast_radius = node["blast_radius"] or 0
    choke_point_count = node["choke_point_count"] or 0
    net.add_node(
        node["node_id"],
        label=node["display_name"],
        title=f"{node['criticality_tier']} | blast radius {blast_radius} | choke point {choke_point_count}",
        value=blast_radius + 1,
        color="#d62728" if choke_point_count > 0 else "#1f77b4",
    )
for edge in network_data["edges"]:
    net.add_edge(edge["source_id"], edge["target_id"], title=edge["rel_type"])

components.html(net.generate_html(notebook=False), height=620, scrolling=True)

st.subheader("Asset Detail")
node_ids = [n["node_id"] for n in network_data["nodes"]]
selected_node_id = st.selectbox("Select an asset", options=node_ids)

with get_driver().session() as session:
    cves = read_asset_detail(session, selected_node_id)

if cves:
    for row in cves:
        techniques = ", ".join(row["technique_ids"]) or "No mapped technique"
        st.write(f"**{row['cve_id']}** (CVSS {row['base_score']}, EPSS {row['epss_score']}) — {techniques}")
else:
    st.write("No known CVEs affect this asset.")
