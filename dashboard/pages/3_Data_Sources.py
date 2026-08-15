"""Data Sources page: a presentation-oriented explainer of the CVE
ingestion pipeline, field provenance, summary stats, and how the synthetic
topology's installed_software links to real CVEs -- see
docs/superpowers/plans/since-assets-are-synthetic-lexical-gizmo.md, Part 2,
Page 4."""
import altair as alt
import pandas as pd
import streamlit as st

from _data_sources_queries import (
    read_cve_stats,
    read_installed_software_example,
    read_sample_cve_rows,
    read_severity_breakdown,
    read_top_products,
)
from db import get_driver

st.set_page_config(page_title="Data Sources", layout="wide")
st.title("Data Sources")

st.header("Pipeline")
st.caption("How the 4 raw sources become microsoft_cve_master.csv (src/ingestion/cve_merge.py).")
cols = st.columns([1, 1, 1, 1, 0.3, 1, 0.3, 1, 0.3, 1])
sources = [
    ("Kaggle\ncve_cisa_epss_enriched_dataset.csv", "CVSS, EPSS, severity"),
    ("Kaggle\ncve_corpus.csv", "description, CWE"),
    ("CISA\nkev_catalog.csv", "KEV flag, ransomware use"),
    ("EPSS\nepss_scores-*.csv.gz", "refreshed EPSS score"),
]
for col, (name, desc) in zip(cols[:4], sources):
    with col:
        st.markdown(f"**{name}**")
        st.caption(desc)
cols[4].markdown("&rarr;")
with cols[5]:
    st.markdown("**inner + left joins**\non `cve_id`")
cols[6].markdown("&rarr;")
with cols[7]:
    st.markdown("**Microsoft-scope\nfilter**")
cols[8].markdown("&rarr;")
with cols[9]:
    st.markdown("**microsoft_cve_master.csv**")

st.header("Sample CVE rows")
st.caption("5 rows, guaranteed to include at least one KEV and one non-KEV row.")

with get_driver().session() as session:
    sample_rows = read_sample_cve_rows(session)

st.dataframe(pd.DataFrame(sample_rows), hide_index=True)

st.caption("Field provenance:")
provenance = pd.DataFrame([
    {"field": "cve_id, description, cwe_id (primary)", "source": "Kaggle cve_corpus.csv"},
    {"field": "base_severity, base_score, attack_vector, epss_score/epss_percentile (fallback)",
     "source": "Kaggle cve_cisa_epss_enriched_dataset.csv"},
    {"field": "vendor, product, kev_flag, kev_date_added, ransomware_used", "source": "CISA kev_catalog.csv"},
    {"field": "epss_score, epss_percentile (refreshed)", "source": "epss_scores-*.csv.gz"},
    {"field": "published_date", "source": "Kaggle cve_cisa_epss_enriched_dataset.csv"},
])
st.dataframe(provenance, hide_index=True)

st.header("Stats")
with get_driver().session() as session:
    stats = read_cve_stats(session)
    severity_rows = read_severity_breakdown(session)
    top_products = read_top_products(session)

col1, col2 = st.columns(2)
col1.metric("Total CVEs", stats["total"])
col2.metric("KEV (known exploited)", stats["kev_count"])

col_pie, col_bar = st.columns(2)
with col_pie:
    st.subheader("Severity breakdown")
    severity_df = pd.DataFrame(severity_rows)
    pie = alt.Chart(severity_df).mark_arc().encode(
        theta="count", color="severity", tooltip=["severity", "count"],
    )
    st.altair_chart(pie, width="stretch")

with col_bar:
    st.subheader("Top 10 products")
    products_df = pd.DataFrame(top_products)
    if not products_df.empty:
        st.bar_chart(products_df.set_index("product")["count"])

st.header("How installed_software links to real CVEs")
st.write(
    "Synthetic computers are tagged with software names sampled directly "
    "from the real CVE dataset's `product` column -- not invented names. "
    "The `AFFECTS` relationship is a case-insensitive exact string match "
    "between an asset's `installed_software` entries and `CVE.product` "
    "(see `src/graph/importer.py`'s `affects_params`), so every synthetic "
    "asset with installed software is attackable via a real CVE."
)

with get_driver().session() as session:
    example = read_installed_software_example(session)

if example:
    st.write(
        f"**Example:** `{example['display_name']}` ({example['asset_id']}) has "
        f"`{example['product']}` installed, which matches `{example['cve_id']}`."
    )
