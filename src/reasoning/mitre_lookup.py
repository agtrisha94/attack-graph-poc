"""Grounds ATT&CK technique IDs in real threat-actor and mitigation facts
from the MITRE CTI STIX bundle -- no invented names (see
docs/superpowers/specs/2026-08-11-reasoning-agent-design.md, MITRE
grounding)."""
import json
import pathlib

STIX_PATH = pathlib.Path("data/raw/mitre-cti/enterprise-attack/enterprise-attack.json")


def _technique_id_of(attack_pattern: dict) -> str | None:
    return next(
        (r["external_id"] for r in attack_pattern.get("external_references", [])
         if r.get("source_name") == "mitre-attack"),
        None,
    )


def build_technique_facts(stix_path: pathlib.Path = STIX_PATH) -> dict[str, dict[str, list[str]]]:
    objects = json.loads(stix_path.read_text())["objects"]

    id_to_name = {o["id"]: o["name"] for o in objects if "id" in o and "name" in o}
    technique_id_by_ap_id = {
        o["id"]: _technique_id_of(o) for o in objects if o.get("type") == "attack-pattern"
    }

    facts: dict[str, dict[str, set[str]]] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel_type = obj.get("relationship_type")
        source_ref = obj.get("source_ref", "")
        technique_id = technique_id_by_ap_id.get(obj.get("target_ref"))
        if not technique_id:
            continue

        if rel_type == "uses" and source_ref.startswith("intrusion-set--"):
            key = "threat_actors"
        elif rel_type == "mitigates" and source_ref.startswith("course-of-action--"):
            key = "mitigations"
        else:
            continue

        name = id_to_name.get(source_ref)
        if not name:
            continue
        entry = facts.setdefault(technique_id, {"threat_actors": set(), "mitigations": set()})
        entry[key].add(name)

    return {
        technique_id: {
            "threat_actors": sorted(entry["threat_actors"]),
            "mitigations": sorted(entry["mitigations"]),
        }
        for technique_id, entry in facts.items()
    }


def resolve_facts_for_techniques(
    technique_ids: list[str], technique_facts: dict[str, dict[str, list[str]]]
) -> dict[str, list[str]]:
    threat_actors: set[str] = set()
    mitigations: set[str] = set()
    for technique_id in technique_ids:
        entry = technique_facts.get(technique_id, {"threat_actors": [], "mitigations": []})
        threat_actors.update(entry["threat_actors"])
        mitigations.update(entry["mitigations"])
    return {"threat_actors": sorted(threat_actors), "mitigations": sorted(mitigations)}
