"""Pure prompt-formatting functions for the chatbot -- data in, string out,
no DB/network calls, no imports at all. Split out from _chat_widget.py so
these are importable and testable under pytest: _chat_widget.py does bare
sibling imports (from _chatbot_queries import ..., from db import ...) that
only resolve when dashboard/ itself is on sys.path (true at Streamlit
runtime, not under pytest's qualified `dashboard.*` import), so importing
it directly in a test fails -- this module has none of that, by design."""


def format_graph_block(paths: list[dict]) -> str:
    if not paths:
        return "(none found)"
    lines = []
    for p in paths:
        score_bits = []
        if p.get("pipeline_score") is not None:
            score_bits.append(f"score {p['pipeline_score']:.2f}")
        if p.get("base_score") is not None:
            score_bits.append(f"CVSS {p['base_score']}")
        if p.get("epss_score") is not None:
            score_bits.append(f"EPSS {p['epss_score']}")
        if p.get("kev_flag") is not None:
            score_bits.append("KEV" if p["kev_flag"] else "not KEV")
        if p.get("attack_vector"):
            score_bits.append(f"vector {p['attack_vector']}")
        if p.get("source_internet_facing") is not None:
            score_bits.append("internet-facing source" if p["source_internet_facing"] else "not internet-facing")
        if p.get("hop_count") is not None:
            score_bits.append(f"{p['hop_count']} hop(s)")
        score_str = f" [{', '.join(score_bits)}]" if score_bits else ""

        route_str = ""
        node_ids = p.get("node_ids") or []
        edge_types = p.get("edge_types")
        if edge_types and len(node_ids) > 1:
            chain = " -> ".join(edge_types.get(i, "?") for i in range(len(node_ids) - 1))
            route_str = f" Route: {chain}."

        line = (
            f"- AttackPath #{p['path_id']} (rank {p['rank']}){score_str}: {p['source_cve']} on "
            f"{p['source_asset_id']} reaches {p['target_asset_id']} "
            f"({p['target_criticality_tier']})."
        )
        line += f" {p['explanation']}" if p.get("explanation") else " No resolved MITRE technique mapping for this path."
        line += route_str
        lines.append(line)
    return "\n".join(lines)


def format_asset_block(assets: list[dict]) -> str:
    lines = []
    for a in assets:
        choke = a["choke_point_count"] if a.get("choke_point_count") is not None else "not a choke point on any ranked path"
        blast = a["blast_radius"] if a.get("blast_radius") is not None else "not computed (not a CVE-exploitable entry point)"
        through_paths = a.get("through_paths") or []
        through = "; ".join(
            f"#{tp['path_id']} (rank {tp['rank']}, {tp['source_cve']} -> {tp['target_asset_id']})"
            for tp in through_paths
        ) or "none"
        lines.append(
            f"- Asset {a['asset_id']} ({a['display_name']}): choke-point count = {choke}; "
            f"blast radius = {blast}; interior hop on ranked path(s): {through}."
        )
    return "\n".join(lines)


def format_dataset_block(stats: dict, severity_rows: list[dict], top_products: list[dict]) -> str:
    severity_str = ", ".join(f"{r['severity']}: {r['count']}" for r in severity_rows) or "(none)"
    products_str = ", ".join(f"{r['product']} ({r['count']})" for r in top_products[:5]) or "(none)"
    return (
        f"- Total CVEs: {stats['total']}; KEV (known exploited): {stats['kev_count']}.\n"
        f"- Severity breakdown: {severity_str}.\n"
        f"- Top products by CVE count: {products_str}."
    )


def format_glossary_block(entries: list[dict]) -> str:
    if not entries:
        return "(none found)"
    return "\n".join(f"- {e['term']} [{e['scope']}]: {e['definition']}" for e in entries)


def format_mitre_block(chunks: list[dict]) -> str:
    if not chunks:
        return "(none found)"
    return "\n".join(f"- {c['id']} ({c['name']}): {c['text']}" for c in chunks)
