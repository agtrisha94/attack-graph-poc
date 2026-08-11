"""Builds a grounded, deterministic explanation string for an AttackPath --
a template stand-in for a live LLM call (see
docs/superpowers/specs/2026-08-11-reasoning-agent-design.md, LLM deviation
and Explanation template). Never states a fact not present in `path` or
`resolved_facts`."""


def _format_list(names: list[str], cap: int = 3) -> str:
    if len(names) <= cap:
        return ", ".join(names)
    shown = ", ".join(names[:cap])
    remaining = len(names) - cap
    return f"{shown}, and {remaining} other(s)"


def build_explanation(path: dict, resolved_facts: dict) -> str:
    base = (
        f"{path['source_cve']} (CVSS {path['base_score']}, EPSS {path['epss_score']}) "
        f"exploits {path['source_asset_id']} and reaches {path['target_asset_id']} "
        f"({path['target_criticality_tier']}) via {path['hop_count']} hop(s)."
    )

    technique_ids = path.get("technique_ids") or []
    if not technique_ids:
        return base

    threat_actors = resolved_facts.get("threat_actors", [])
    mitigations = resolved_facts.get("mitigations", [])

    actor_sentence = (
        f" Used by {_format_list(threat_actors)}."
        if threat_actors else " No known threat-actor group on record."
    )
    mitigation_sentence = (
        f" Mitigations: {_format_list(mitigations)}."
        if mitigations else " No known mitigation on record."
    )

    return (
        f"{base} Maps to ATT&CK technique(s) {', '.join(technique_ids)}."
        f"{actor_sentence}{mitigation_sentence}"
    )
