"""Extracts ATT&CK Enterprise techniques from the MITRE CTI STIX bundle."""
import json
import pathlib

import pandas as pd

STIX_PATH = pathlib.Path("data/raw/mitre-cti/enterprise-attack/enterprise-attack.json")
CAPEC_PATH = pathlib.Path("data/raw/mitre-cti/capec/2.1/stix-capec.json")
OUT_PATH = pathlib.Path("data/processed/technique_map.csv")


def build_technique_cwe_map(capec_path: pathlib.Path) -> dict[str, list[str]]:
    """Bridges CWE -> ATT&CK technique via CAPEC attack-pattern entries that
    carry both a `cwe` and an `ATTACK` external_reference (real cross-refs
    embedded in the cloned CAPEC STIX bundle, not fabricated)."""
    bundle = json.loads(capec_path.read_text())
    result: dict[str, set[str]] = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        refs = obj.get("external_references", [])
        technique_id = next((r["external_id"] for r in refs if r.get("source_name") == "ATTACK"), None)
        if not technique_id:
            continue
        cwe_ids = [r["external_id"] for r in refs if r.get("source_name") == "cwe"]
        result.setdefault(technique_id, set()).update(cwe_ids)
    return {technique_id: sorted(cwe_ids) for technique_id, cwe_ids in result.items()}


def extract_techniques(stix_path: pathlib.Path, capec_path: pathlib.Path | None = None) -> pd.DataFrame:
    technique_cwe_map = build_technique_cwe_map(capec_path) if capec_path and capec_path.exists() else {}
    bundle = json.loads(stix_path.read_text())
    rows = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        technique_id = next(
            (r["external_id"] for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not technique_id:
            continue
        tactic = ", ".join(
            p["phase_name"] for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        )
        rows.append({
            "technique_id": technique_id,
            "technique_name": obj.get("name", ""),
            "tactic": tactic,
            "cwe_ids": ";".join(technique_cwe_map.get(technique_id, [])),
        })
    return pd.DataFrame(rows)


def main() -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df = extract_techniques(STIX_PATH, CAPEC_PATH)
    df.to_csv(OUT_PATH, index=False)
    print(f"Wrote {len(df)} rows to {OUT_PATH}")


if __name__ == "__main__":
    main()
