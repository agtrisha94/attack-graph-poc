"""Global chat access: a sidebar button on every page that opens the
chatbot in a popup (st.dialog) instead of living on its own tab, so asking
about whatever the user is currently looking at doesn't mean leaving the
page. Absorbs the logic that used to live in the standalone Chatbot page --
see docs (RAG chatbot plan) for the grounding design: graph facts and MITRE
reference material are kept in separate labeled prompt blocks so the model
never attributes a reference-material fact to a specific path unless the
graph facts confirm it.

Context-passing reuses the existing retrieval as-is: st.session_state
["chat_context"] is a plain label set by whichever page has a "current
selection" (e.g. "AttackPath #e06b8... (CVE-2021-26855 -> computer-0154)").
It's concatenated onto the question before retrieval, so a CVE/technique ID
embedded in the label gets picked up by _chatbot_queries.py's existing
regex extraction for free -- no new parameters needed there.

Also pulls in: score components + hop-by-hop topology for attack paths,
concrete through-path details for choke-point assets, a small fixed
glossary (dashboard/_glossary.py) for definitional questions ("what is a
CVE", "how are attack paths scored"), and dataset-wide stats straight from
dashboard/_data_sources_queries.py -- a plain sibling import rather than a
duplicate, safe here specifically because this module has no direct unit
tests and is never imported under pytest, so it never hits the qualified-
import problem that forced _chatbot_queries.py's query duplication."""
import json
import pathlib
from datetime import datetime, timezone

import streamlit as st

from _chat_formatting import (
    format_asset_block,
    format_dataset_block,
    format_glossary_block,
    format_graph_block,
    format_mitre_block,
    mentioned_asset_ids,
    mentioned_path_ids,
)
from _chatbot_queries import (
    read_path_chain_edge_types,
    relevant_assets_for_question,
    relevant_paths_for_question,
)
from _data_sources_queries import read_cve_stats, read_severity_breakdown, read_top_products
from _glossary import relevant_glossary_entries
from _llm_client import NoApiKeyError, ask
from _rag_retriever import index_available, top_k_chunks
from db import get_driver

UNANSWERED_LOG_PATH = pathlib.Path("data/rag_unanswered_log.jsonl")

SYSTEM_PROMPT = (
    "You are a security analyst assistant for an attack-graph proof-of-concept. "
    "Answer the user's question using ONLY the facts given below -- never state a "
    "fact that isn't present in them, and say so plainly if the facts don't cover "
    "the question rather than guessing.\n\n"
    "Several sections follow: verified facts about specific attack paths, assets, "
    "and dataset-wide stats from the live graph; a glossary of terms; and general "
    "MITRE ATT&CK reference material. Only state that a fact applies to a "
    "specific path or asset if it appears in the graph-facts section. Material in "
    "the MITRE reference section must never be described as applying to a "
    "specific path unless the graph-facts section independently confirms the "
    "same technique, threat actor, or mitigation.\n\n"
    "Glossary entries are tagged [app_specific] or [general]. [app_specific] "
    "entries -- including the attack-path scoring formula -- describe design "
    "choices this particular application made; explain them as this app's own "
    "approach, never as a generic industry rule. [general] entries are "
    "standard, well-established terminology independent of this app.\n\n"
    "End your answer with a 'Sources:' line listing what you used, tagged as "
    "(your graph), (glossary), or (general reference). Whenever you refer to "
    "a specific attack path or asset from the graph-facts section, include "
    "its exact ID as given (e.g. #e06b81e2c476d21a or computer-0081) -- the "
    "app uses this to offer a direct link to it."
)


def _log_unanswered(question: str, paths: list[dict], assets: list[dict], glossary: list[dict], chunks: list[dict]) -> None:
    UNANSWERED_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with UNANSWERED_LOG_PATH.open("a") as f:
        f.write(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "question": question,
            "resolved_path_count": sum(1 for p in paths if p.get("explanation")),
            "asset_count": len(assets),
            "glossary_count": len(glossary),
            "mitre_chunk_count": len(chunks),
        }) + "\n")


@st.dialog("Chat with your data", width="large")
def _chat_dialog() -> None:
    context = st.session_state.get("chat_context")
    if context:
        chip_col, clear_col = st.columns([5, 1])
        chip_col.info(f"Currently viewing: {context}")
        if clear_col.button("Clear"):
            st.session_state.chat_context = None
            st.rerun()

    if not index_available():
        st.warning(
            "RAG index not built yet -- run `python scripts/build_rag_index.py` to "
            "enable MITRE ATT&CK knowledge lookups. Graph questions still work."
        )

    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []

    for message in st.session_state.chat_messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])

    question = st.chat_input("Ask a question")
    if not question:
        return

    st.session_state.chat_messages.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.write(question)

    search_text = f"{question} {context}" if context else question
    with get_driver().session() as session:
        paths = relevant_paths_for_question(session, search_text)
        for path in paths:
            node_ids = path.get("node_ids") or []
            if len(node_ids) > 1:
                path["edge_types"] = read_path_chain_edge_types(session, node_ids)
        assets = relevant_assets_for_question(session, search_text)
        dataset_stats = read_cve_stats(session)
        severity_rows = read_severity_breakdown(session)
        top_products = read_top_products(session)
    chunks = top_k_chunks(search_text) if index_available() else []
    glossary_entries = relevant_glossary_entries(search_text)

    if not any(p.get("explanation") for p in paths) and not assets and not glossary_entries and not chunks:
        _log_unanswered(question, paths, assets, glossary_entries, chunks)

    graph_facts = "\n".join(filter(None, [format_graph_block(paths), format_asset_block(assets)])) or "(none found)"
    user_message = (
        f"## Currently viewing\n{context or '(nothing selected)'}\n\n"
        "## Verified facts about specific attack paths and assets (from your graph)\n"
        f"{graph_facts}\n\n"
        "## Dataset overview (from your graph)\n"
        f"{format_dataset_block(dataset_stats, severity_rows, top_products)}\n\n"
        "## Glossary\n"
        f"{format_glossary_block(glossary_entries)}\n\n"
        "## General MITRE ATT&CK reference material\n"
        f"{format_mitre_block(chunks)}\n\n"
        f"## Question\n{question}"
    )

    with st.chat_message("assistant"):
        jump_path_ids, jump_asset_ids = [], []
        try:
            answer = ask(SYSTEM_PROMPT, user_message)
            jump_path_ids = mentioned_path_ids(answer, paths)
            jump_asset_ids = mentioned_asset_ids(answer, assets)
        except NoApiKeyError:
            answer = (
                "Add `OPENAI_API_KEY` to your `.env` to enable answers. "
                "Retrieval is already working -- here's the context that would "
                f"have been sent to the model:\n\n{user_message}"
            )
        st.write(answer)
        # Only ever shown under the answer that was just generated -- older
        # turns replay as plain text from chat_messages below, with no
        # paths/assets kept around to validate jump targets against.
        for pid in jump_path_ids:
            if st.button(f"🔎 Open AttackPath #{pid} in Attack Paths", key=f"jump_path_{pid}"):
                st.switch_page("pages/1_Attack_Paths.py", query_params={"path_id": pid})
        for aid in jump_asset_ids:
            if st.button(f"🔎 Open Asset {aid} in Risk Analysis", key=f"jump_asset_{aid}"):
                st.switch_page("pages/2_Risk_Analysis.py", query_params={"asset_id": aid})
    st.session_state.chat_messages.append({"role": "assistant", "content": answer})


def render_chat_trigger() -> None:
    """Call once near the top of every page -- adds the sidebar button that
    opens the chat popup, reachable regardless of which page is active."""
    if st.sidebar.button("💬 Ask AI", width="stretch"):
        _chat_dialog()
