"""Overview page: risk-focused stat tiles over the pipeline's existing
Neo4j output -- see docs/superpowers/specs/2026-08-11-dashboard-design.md,
Page 1: Overview. Streamlit auto-loads this as the default landing page."""
import pandas as pd
import streamlit as st

from _overview_queries import (
    count_attack_paths,
    count_crown_jewel_targets,
    path_counts_by_criticality,
    top_blast_radius,
    top_choke_points,
)
from db import get_driver

st.set_page_config(page_title="Attack Graph Overview", layout="wide")
st.title("Attack Graph Overview")

with get_driver().session() as session:
    attack_path_count = count_attack_paths(session)
    crown_jewel_count = count_crown_jewel_targets(session)
    choke_points = top_choke_points(session)
    blast_radii = top_blast_radius(session)
    tier_counts = path_counts_by_criticality(session)

col1, col2 = st.columns(2)
col1.metric("Attack Paths Found", attack_path_count)
col2.metric("Crown Jewel Assets Targeted", crown_jewel_count)

st.subheader("Top Choke-Point Assets")
st.dataframe(pd.DataFrame(choke_points), hide_index=True)

st.subheader("Top Blast-Radius Assets")
st.dataframe(pd.DataFrame(blast_radii), hide_index=True)

st.subheader("Attack Paths by Target Criticality")
tier_df = pd.DataFrame(tier_counts)
if not tier_df.empty:
    st.bar_chart(tier_df.set_index("tier"))
