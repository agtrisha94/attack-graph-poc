"""Neo4j connection for the dashboard -- same NEO4J_URI/USER/PASSWORD env
pattern as scripts/find_paths.py, cached so Streamlit reuses one driver
across reruns instead of opening a new connection per widget interaction
(see docs/superpowers/specs/2026-08-11-dashboard-design.md, Architecture)."""
import os

import streamlit as st
from neo4j import GraphDatabase


def _driver_config() -> dict[str, str]:
    return {
        "uri": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        "user": os.environ.get("NEO4J_USER", "neo4j"),
        "password": os.environ["NEO4J_PASSWORD"],
    }


@st.cache_resource
def get_driver():
    config = _driver_config()
    return GraphDatabase.driver(config["uri"], auth=(config["user"], config["password"]))
