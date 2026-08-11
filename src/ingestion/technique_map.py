"""Extracts ATT&CK Enterprise techniques from the MITRE CTI STIX bundle."""
import json
import pathlib

import pandas as pd

STIX_PATH = pathlib.Path("data/raw/mitre-cti/enterprise-attack/enterprise-attack.json")
OUT_PATH = pathlib.Path("data/processed/technique_map.csv")


def extract_techniques(stix_path: pathlib.Path) -> pd.DataFrame:
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
            # ponytail: cwe_ids left empty — no CWE<->ATT&CK bridge exists in the
            # cloned MITRE data (see plan Global Constraints). Populate when a
            # CAPEC<->ATT&CK<->CWE cross-reference file is added to data/raw/.
            "cwe_ids": "",
        })
    return pd.DataFrame(rows)


def main() -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df = extract_techniques(STIX_PATH)
    df.to_csv(OUT_PATH, index=False)
    print(f"Wrote {len(df)} rows to {OUT_PATH}")


if __name__ == "__main__":
    main()
