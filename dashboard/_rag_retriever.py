"""Loads the local RAG index (built offline by scripts/build_rag_index.py)
and retrieves the top-k MITRE ATT&CK chunks most similar to a chat question
-- self-contained rather than importing from src/reasoning, because
Streamlit only puts dashboard/ on sys.path, not the repo root (same
convention as _attack_paths_queries.py). Embeddings are pre-normalized at
build time, so cosine similarity is a plain dot product.

A short question like "What is T1078?" barely carries semantic content for
the embedding model to match against, so a bare ID lookup can lose to
unrelated chunks on embedding similarity alone -- exact_id_indices() checks
for a literal MITRE ID in the question first and puts that chunk first,
falling back to embedding similarity to fill the rest."""
import pathlib
import re

import numpy as np
import streamlit as st
from sentence_transformers import SentenceTransformer

INDEX_PATH = pathlib.Path("data/rag_index.npz")
MODEL_NAME = "all-MiniLM-L6-v2"  # must match scripts/build_rag_index.py

_ID_TOKEN_PATTERN = re.compile(r"\b[TMGS]\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def index_available() -> bool:
    return INDEX_PATH.exists()


@st.cache_resource
def _get_model():
    return SentenceTransformer(MODEL_NAME)


@st.cache_resource
def _load_index():
    data = np.load(INDEX_PATH, allow_pickle=True)
    return {key: data[key] for key in ("embeddings", "ids", "source_types", "names", "texts")}


def top_k_indices(query_vec: np.ndarray, embeddings: np.ndarray, k: int) -> np.ndarray:
    scores = embeddings @ query_vec
    return np.argsort(scores)[::-1][:k]


def exact_id_indices(question: str, ids: np.ndarray) -> list[int]:
    tokens = {m.upper() for m in _ID_TOKEN_PATTERN.findall(question)}
    if not tokens:
        return []
    return [i for i, chunk_id in enumerate(ids) if str(chunk_id).upper() in tokens]


def top_k_chunks(question: str, k: int = 5) -> list[dict]:
    index = _load_index()
    exact_idx = exact_id_indices(question, index["ids"])

    query_vec = _get_model().encode([question], normalize_embeddings=True)[0]
    ranked_idx = top_k_indices(query_vec, index["embeddings"], k + len(exact_idx))
    ranked_idx = [i for i in ranked_idx if i not in exact_idx]

    top_idx = (exact_idx + ranked_idx)[:k]
    return [
        {
            "id": index["ids"][i],
            "source_type": index["source_types"][i],
            "name": index["names"][i],
            "text": index["texts"][i],
        }
        for i in top_idx
    ]
