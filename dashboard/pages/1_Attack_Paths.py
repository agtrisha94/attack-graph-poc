"""Attack Paths page: ranked table + detail panel with grounded
explanation -- see docs/superpowers/specs/2026-08-11-dashboard-design.md,
Page 2: Attack Paths."""
import pandas as pd
import streamlit as st

from _attack_paths_queries import read_attack_paths_with_reasoning
from db import get_driver

st.set_page_config(page_title="Attack Paths", layout="wide")
st.title("Attack Paths")

with get_driver().session() as session:
    paths = read_attack_paths_with_reasoning(session)

df = pd.DataFrame(paths)
display_columns = [
    "rank", "source_cve", "base_score", "epss_score",
    "source_asset_id", "target_asset_id", "target_criticality_tier", "hop_count",
]

event = st.dataframe(
    df[display_columns],
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row-required",
)
selected_row = df.iloc[event["selection"]["rows"][0]]

st.subheader(f"{selected_row['source_cve']} -> {selected_row['target_asset_id']}")
st.write(selected_row["explanation"] or "Not resolved for this path.")

technique_ids = selected_row["technique_ids"] or []
threat_actors = selected_row["threat_actors"] or []
mitigations = selected_row["mitigations"] or []

st.write("**MITRE ATT&CK Techniques:**", ", ".join(technique_ids) or "Not resolved for this path.")
st.write("**Threat Actors:**", ", ".join(threat_actors) or "Not resolved for this path.")
st.write("**Mitigations:**", ", ".join(mitigations) or "Not resolved for this path.")
