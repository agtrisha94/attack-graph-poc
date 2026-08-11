# Data Engineer Ingestion Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Agent 2 (Data Engineer) scripts that turn the raw sources in `data/raw/` into the four processed datasets defined in `schemas/data_schema.yaml` (`microsoft_cve_master.csv`, `technique_map.csv`, `nodes_topology.csv`, `edges_topology.csv`), and a validator that enforces `contracts/01_requirements_to_data.yaml`'s `consumer_must_validate` checklist.

**Architecture:** Four small, independently-testable modules (`src/ingestion/cve_merge.py`, `src/ingestion/technique_map.py`, `src/generator/topology.py`, `src/ingestion/validate.py`), each with a `main()` that reads from `data/raw/` and writes one output file, plus a thin orchestrator (`scripts/build_dataset.py`) that runs them in order and validates the result. No new dependencies — pandas, PyYAML, and the stdlib (`ast`, `json`, `csv`, `random`, `glob`) are already installed and sufficient.

**Tech Stack:** Python 3.11, pandas, PyYAML, pytest (all already installed — verified via `python3 -c "import pandas, yaml, pytest"`).

## Global Constraints

- Every output field must match `schemas/data_schema.yaml` exactly (name, type, enum, range) — this is the file Agent 3 (Graph Architect) will import against.
- Microsoft-scope filter uses the alias list in `schemas/data_schema.yaml` → `microsoft_scope_filter.vendor_aliases`, applied as case-insensitive substring match, applied **after** the enriched+corpus+KEV+EPSS merge (per `requirements.md` FR2).
- No network calls: EPSS refresh uses the existing local snapshot `data/raw/epss_scores-*.csv.gz`, not a live API call (`requirements.md` FR2 explicitly allows "or latest `epss_scores-*.csv.gz` snapshot"; no `requests` library is installed and none should be added for this).
- `technique_map.cwe_ids` ships **empty** for this pass: the cloned `data/raw/mitre-cti/enterprise-attack/enterprise-attack.json` STIX bundle does not embed CWE references on `attack-pattern` objects (verified — only 2 stray non-CWE hits across 858 techniques), and the CAPEC bundle at `data/raw/mitre-cti/capec/` has CWE references but no ATT&CK technique cross-reference field. Populating `cwe_ids` would require fabricating a mapping not grounded in any file in this repo, which violates `requirements.md` NFR2 (no fabricated facts). Document this as a `ponytail:` comment in code — upgrade path is importing MITRE's published CAPEC↔ATT&CK↔CWE cross-reference if/when it's added to `data/raw/`.
- Synthetic topology's `management_group` values are grounded in the real Enterprise-Scale hierarchy described in `data/raw/azure-enterprise-scale/docs/reference/contoso/Readme.md` (Platform → Management/Connectivity/Identity, Landing Zones → Corp/Online) — no other management groups invented.
- All generation is deterministic (fixed `random.seed`) per `requirements.md` NFR1 (reproducibility).
- Follow TDD: write the failing test, confirm it fails, implement, confirm it passes, commit.

---

## File Structure

- `src/ingestion/cve_merge.py` — merges Kaggle enriched + corpus + KEV + EPSS snapshot into `data/processed/microsoft_cve_master.csv`.
- `src/ingestion/technique_map.py` — extracts ATT&CK techniques from the STIX bundle into `data/processed/technique_map.csv`.
- `src/generator/topology.py` — generates synthetic AzureHound-shaped topology into `data/synthetic/nodes_topology.csv` and `data/synthetic/edges_topology.csv`.
- `src/ingestion/validate.py` — runs contract 01's `consumer_must_validate` checklist against the four output files.
- `scripts/build_dataset.py` — orchestrator CLI: runs the three builders then the validator, exits non-zero on any violation.
- `tests/test_cve_merge.py`, `tests/test_technique_map.py`, `tests/test_topology.py`, `tests/test_validate.py` — unit tests against small in-memory/tmp_path fixtures (not the full raw files, so tests stay fast and deterministic).

---

### Task 1: CVE master merge (`src/ingestion/cve_merge.py`)

**Files:**
- Create: `src/ingestion/__init__.py` (empty)
- Create: `src/ingestion/cve_merge.py`
- Test: `tests/test_cve_merge.py`

**Interfaces:**
- Produces: `parse_list_field(raw: str) -> list[str]`, `cpe_vendor_product(cpe_uri: str) -> tuple[str, str]`, `MICROSOFT_ALIASES: list[str]`, `is_microsoft_scope(fields: list[str]) -> bool`, `load_epss_snapshot(epss_glob: str) -> pandas.DataFrame` (columns `cve_id, epss_score, epss_percentile`), `build_microsoft_cve_master(kaggle_dir: pathlib.Path, kev_path: pathlib.Path, epss_glob: str) -> pandas.DataFrame` (columns match `schemas/data_schema.yaml` → `microsoft_cve_master`), `main() -> None`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cve_merge.py
import pandas as pd
from src.ingestion.cve_merge import (
    parse_list_field,
    cpe_vendor_product,
    is_microsoft_scope,
    build_microsoft_cve_master,
)


def test_parse_list_field_parses_python_list_string():
    assert parse_list_field("['CWE-79']") == ["CWE-79"]


def test_parse_list_field_handles_missing():
    assert parse_list_field(float("nan")) == []
    assert parse_list_field("") == []


def test_cpe_vendor_product_extracts_vendor_and_product():
    assert cpe_vendor_product("cpe:2.3:a:microsoft:sql_server:2019:*:*:*:*:*:*:*") == (
        "microsoft",
        "sql server",
    )


def test_is_microsoft_scope_matches_alias_substring():
    assert is_microsoft_scope(["microsoft", "sql server"]) is True
    assert is_microsoft_scope(["windows_10"]) is True
    assert is_microsoft_scope(["eric_allman", "sendmail"]) is False


def test_build_microsoft_cve_master_filters_and_merges(tmp_path):
    kaggle_dir = tmp_path / "kaggle merged dataset"
    kaggle_dir.mkdir()
    (kaggle_dir / "cve_cisa_epss_enriched_dataset.csv").write_text(
        "cve_id,base_severity,base_score,epss_score,epss_perc,cisa_kev,"
        "attack_vector,published_date\n"
        "CVE-2026-0001,HIGH,8.8,0.1,0.5,False,NETWORK,2026-01-01\n"
        "CVE-2026-0002,LOW,2.0,0.01,0.1,False,LOCAL,2026-01-02\n"
    )
    (kaggle_dir / "cve_corpus.csv").write_text(
        "cve_id,description_data,cwe_data,cpe_data\n"
        'CVE-2026-0001,["RCE in Exchange"],["CWE-502"],'
        '["cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*"]\n'
        'CVE-2026-0002,["local bug in sendmail"],["CWE-20"],'
        '["cpe:2.3:a:eric_allman:sendmail:8.15:*:*:*:*:*:*:*"]\n'
    )
    kev_path = tmp_path / "kev_catalog.csv"
    kev_path.write_text(
        "cveID,vendorProject,product,dateAdded,knownRansomwareCampaignUse\n"
        "CVE-2026-0001,Microsoft,Exchange Server,2026-01-05,Known\n"
    )
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir()
    epss_path = epss_dir / "epss_scores-2026-08-10.csv.gz"
    epss_path.write_bytes(
        pd.DataFrame(
            [
                {"cve": "CVE-2026-0001", "epss": 0.42, "percentile": 0.9},
                {"cve": "CVE-2026-0002", "epss": 0.02, "percentile": 0.2},
            ]
        ).to_csv(index=False).encode()
    )

    result = build_microsoft_cve_master(kaggle_dir, kev_path, str(epss_dir / "epss_scores-*.csv.gz"))

    assert list(result["cve_id"]) == ["CVE-2026-0001"]
    row = result.iloc[0]
    assert row["vendor"] == "Microsoft"
    assert row["kev_flag"] is True or row["kev_flag"] == True  # noqa: E712
    assert row["epss_score"] == 0.42
    assert row["epss_percentile"] == 0.9
    assert row["cwe_id"] == "CWE-502"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_cve_merge.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.ingestion.cve_merge'`

- [ ] **Step 3: Write the implementation**

```python
# src/ingestion/cve_merge.py
"""Merges Kaggle CVE data + CISA KEV + EPSS snapshot into microsoft_cve_master.csv."""
import ast
import glob
import pathlib

import pandas as pd

MICROSOFT_ALIASES = [
    "microsoft", "windows", "azure", "office", "exchange", "sql server",
    ".net", "edge", "sharepoint", "active directory",
]

RAW_DIR = pathlib.Path("data/raw")
OUT_PATH = pathlib.Path("data/processed/microsoft_cve_master.csv")


def parse_list_field(raw) -> list[str]:
    if not isinstance(raw, str) or not raw.strip():
        return []
    try:
        parsed = ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return []
    return [str(item) for item in parsed] if isinstance(parsed, list) else []


def cpe_vendor_product(cpe_uri: str) -> tuple[str, str]:
    parts = cpe_uri.split(":")
    vendor = parts[3].replace("_", " ") if len(parts) > 3 else ""
    product = parts[4].replace("_", " ") if len(parts) > 4 else ""
    return vendor, product


def is_microsoft_scope(fields: list[str]) -> bool:
    haystack = " ".join(f.lower() for f in fields if f)
    return any(alias in haystack for alias in MICROSOFT_ALIASES)


def load_epss_snapshot(epss_glob: str) -> pd.DataFrame:
    matches = sorted(glob.glob(epss_glob))
    if not matches:
        raise FileNotFoundError(f"No EPSS snapshot matching {epss_glob}")
    df = pd.read_csv(matches[-1], comment="#")
    return df.rename(columns={"cve": "cve_id", "epss": "epss_score", "percentile": "epss_percentile"})


def build_microsoft_cve_master(kaggle_dir: pathlib.Path, kev_path: pathlib.Path, epss_glob: str) -> pd.DataFrame:
    enriched = pd.read_csv(kaggle_dir / "cve_cisa_epss_enriched_dataset.csv")
    corpus = pd.read_csv(kaggle_dir / "cve_corpus.csv")
    merged = enriched.merge(corpus, on="cve_id", how="inner")

    merged["description"] = merged["description_data"].apply(
        lambda v: (parse_list_field(v) or [""])[0]
    )
    merged["cwe_id"] = merged["cwe_data"].apply(
        lambda v: next((c for c in parse_list_field(v) if c.startswith("CWE-")), None)
    )
    cpe_vp = merged["cpe_data"].apply(
        lambda v: cpe_vendor_product(parse_list_field(v)[0]) if parse_list_field(v) else ("", "")
    )
    merged["cpe_vendor"] = cpe_vp.apply(lambda t: t[0])
    merged["cpe_product"] = cpe_vp.apply(lambda t: t[1])

    kev = pd.read_csv(kev_path).rename(columns={"cveID": "cve_id"})
    kev_cols = ["cve_id", "vendorProject", "product", "dateAdded", "knownRansomwareCampaignUse"]
    merged = merged.merge(kev[kev_cols], on="cve_id", how="left")

    merged["kev_flag"] = merged["vendorProject"].notna()
    merged["vendor"] = merged["vendorProject"].fillna(merged["cpe_vendor"])
    merged["product"] = merged["product"].fillna(merged["cpe_product"])

    scope_mask = merged.apply(
        lambda r: r["kev_flag"] or is_microsoft_scope([r["vendor"], r["product"], r["description"]]),
        axis=1,
    )
    merged = merged[scope_mask].copy()

    epss = load_epss_snapshot(epss_glob)
    merged = merged.merge(epss, on="cve_id", how="left", suffixes=("_old", ""))
    merged["epss_score"] = merged["epss_score"].fillna(merged["epss_score_old"])
    merged["epss_percentile"] = merged["epss_percentile"].fillna(merged["epss_perc"])

    merged = merged.rename(columns={
        "dateAdded": "kev_date_added",
        "knownRansomwareCampaignUse": "ransomware_used",
    })

    result = merged[[
        "cve_id", "vendor", "product", "description", "cwe_id", "base_severity",
        "base_score", "attack_vector", "epss_score", "epss_percentile", "kev_flag",
        "kev_date_added", "ransomware_used", "published_date",
    ]].drop_duplicates(subset="cve_id").reset_index(drop=True)
    return result


def main() -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df = build_microsoft_cve_master(
        RAW_DIR / "kaggle merged dataset",
        RAW_DIR / "kev_catalog.csv",
        str(RAW_DIR / "epss_scores-*.csv.gz"),
    )
    df.to_csv(OUT_PATH, index=False)
    print(f"Wrote {len(df)} rows to {OUT_PATH}")


if __name__ == "__main__":
    main()
```

```python
# src/ingestion/__init__.py
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_cve_merge.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/ingestion/__init__.py src/ingestion/cve_merge.py tests/test_cve_merge.py
git commit -m "feat: add CVE master merge pipeline (Agent 2)"
```

---

### Task 2: ATT&CK technique map (`src/ingestion/technique_map.py`)

**Files:**
- Create: `src/ingestion/technique_map.py`
- Test: `tests/test_technique_map.py`

**Interfaces:**
- Produces: `extract_techniques(stix_path: pathlib.Path) -> pandas.DataFrame` (columns `technique_id, technique_name, tactic, cwe_ids`), `main() -> None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_technique_map.py
import json
from src.ingestion.technique_map import extract_techniques


def test_extract_techniques_reads_stix_attack_patterns(tmp_path):
    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Exploit Public-Facing Application",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1190"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            },
            {
                "type": "course-of-action",
                "name": "not a technique",
            },
        ]
    }
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))

    result = extract_techniques(stix_path)

    assert len(result) == 1
    row = result.iloc[0]
    assert row["technique_id"] == "T1190"
    assert row["technique_name"] == "Exploit Public-Facing Application"
    assert row["tactic"] == "initial-access"
    assert row["cwe_ids"] == ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_technique_map.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.ingestion.technique_map'`

- [ ] **Step 3: Write the implementation**

```python
# src/ingestion/technique_map.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_technique_map.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ingestion/technique_map.py tests/test_technique_map.py
git commit -m "feat: add ATT&CK technique extraction (Agent 2)"
```

---

### Task 3: Synthetic topology generator (`src/generator/topology.py`)

**Files:**
- Create: `src/generator/__init__.py` (empty)
- Create: `src/generator/topology.py`
- Test: `tests/test_topology.py`

**Interfaces:**
- Consumes: nothing from earlier tasks at runtime (takes a plain `list[str]` of product names, produced by Task 1's output column `product`).
- Produces: `MANAGEMENT_GROUPS: list[str]`, `CRITICALITY_BY_MG: dict[str, str]`, `generate_topology(products: list[str], seed: int = 42) -> tuple[pandas.DataFrame, pandas.DataFrame]` (nodes_df columns `node_id, node_type, display_name, criticality_tier, installed_software, management_group`; edges_df columns `source_id, target_id, edge_type, properties`), `main() -> None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_topology.py
from src.generator.topology import generate_topology, MANAGEMENT_GROUPS

VALID_NODE_TYPES = {"User", "Group", "Computer", "Application", "Device"}
VALID_EDGE_TYPES = {"RUNS", "CONNECTS_TO", "MEMBER_OF", "HAS_SESSION", "CONTROLS"}
VALID_CRITICALITY = {"Crown Jewel", "High", "Medium", "Low"}


def test_generate_topology_is_deterministic():
    nodes_a, edges_a = generate_topology(["Exchange Server", "SQL Server"], seed=42)
    nodes_b, edges_b = generate_topology(["Exchange Server", "SQL Server"], seed=42)
    assert nodes_a.equals(nodes_b)
    assert edges_a.equals(edges_b)


def test_generate_topology_produces_valid_nodes_and_edges():
    nodes, edges = generate_topology(["Exchange Server", "SQL Server"], seed=1)

    assert len(nodes) > 0
    assert set(nodes["node_type"]).issubset(VALID_NODE_TYPES)
    assert set(nodes["criticality_tier"]).issubset(VALID_CRITICALITY)
    assert set(nodes["management_group"]).issubset(set(MANAGEMENT_GROUPS))
    assert nodes["node_id"].is_unique

    assert len(edges) > 0
    assert set(edges["edge_type"]).issubset(VALID_EDGE_TYPES)
    node_ids = set(nodes["node_id"])
    assert set(edges["source_id"]).issubset(node_ids)
    assert set(edges["target_id"]).issubset(node_ids)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_topology.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.generator.topology'`

- [ ] **Step 3: Write the implementation**

```python
# src/generator/topology.py
"""Generates a synthetic enterprise topology shaped after AzureHound's object
model, grounded in the Enterprise-Scale management group hierarchy documented
in data/raw/azure-enterprise-scale/docs/reference/contoso/Readme.md.
"""
import pathlib
import random

import pandas as pd

MANAGEMENT_GROUPS = [
    "Platform/Management",
    "Platform/Connectivity",
    "Platform/Identity",
    "LandingZones/Corp",
    "LandingZones/Online",
]

CRITICALITY_BY_MG = {
    "Platform/Identity": "Crown Jewel",
    "Platform/Management": "High",
    "Platform/Connectivity": "High",
    "LandingZones/Corp": "Medium",
    "LandingZones/Online": "Medium",
}

COMPUTERS_PER_MG = 4
USERS_PER_MG = 3

CVE_MASTER_PATH = pathlib.Path("data/processed/microsoft_cve_master.csv")
NODES_OUT = pathlib.Path("data/synthetic/nodes_topology.csv")
EDGES_OUT = pathlib.Path("data/synthetic/edges_topology.csv")


def generate_topology(products: list[str], seed: int = 42) -> tuple[pd.DataFrame, pd.DataFrame]:
    rng = random.Random(seed)
    nodes: list[dict] = []
    edges: list[dict] = []
    counter = 0

    def next_id(prefix: str) -> str:
        nonlocal counter
        counter += 1
        return f"{prefix}-{counter:04d}"

    for mg in MANAGEMENT_GROUPS:
        tier = CRITICALITY_BY_MG[mg]

        group_id = next_id("group")
        nodes.append({
            "node_id": group_id, "node_type": "Group",
            "display_name": f"{mg.split('/')[-1]}-Admins",
            "criticality_tier": tier, "installed_software": "",
            "management_group": mg,
        })

        computer_ids = []
        for _ in range(COMPUTERS_PER_MG):
            cid = next_id("computer")
            software = rng.sample(products, k=min(2, len(products))) if products else []
            nodes.append({
                "node_id": cid, "node_type": "Computer",
                "display_name": f"{mg.split('/')[-1]}-Host-{cid}",
                "criticality_tier": tier,
                "installed_software": ";".join(software),
                "management_group": mg,
            })
            computer_ids.append(cid)
            for app in software:
                app_id = next_id("app")
                nodes.append({
                    "node_id": app_id, "node_type": "Application",
                    "display_name": app, "criticality_tier": tier,
                    "installed_software": "", "management_group": mg,
                })
                edges.append({"source_id": cid, "target_id": app_id, "edge_type": "RUNS", "properties": ""})

        for _ in range(USERS_PER_MG):
            uid = next_id("user")
            nodes.append({
                "node_id": uid, "node_type": "User",
                "display_name": f"{mg.split('/')[-1]}-User-{uid}",
                "criticality_tier": tier, "installed_software": "",
                "management_group": mg,
            })
            edges.append({"source_id": uid, "target_id": group_id, "edge_type": "MEMBER_OF", "properties": ""})
            edges.append({
                "source_id": uid, "target_id": rng.choice(computer_ids),
                "edge_type": "HAS_SESSION", "properties": "",
            })

        edges.append({
            "source_id": group_id, "target_id": rng.choice(computer_ids),
            "edge_type": "CONTROLS", "properties": "",
        })

    # Hub-and-spoke connectivity per the Enterprise-Scale VWAN model: every
    # landing zone connects through Connectivity, which connects through Identity.
    connectivity_computer = next(n["node_id"] for n in nodes if n["management_group"] == "Platform/Connectivity" and n["node_type"] == "Computer")
    identity_computer = next(n["node_id"] for n in nodes if n["management_group"] == "Platform/Identity" and n["node_type"] == "Computer")
    edges.append({"source_id": connectivity_computer, "target_id": identity_computer, "edge_type": "CONNECTS_TO", "properties": ""})
    for mg in ["LandingZones/Corp", "LandingZones/Online", "Platform/Management"]:
        first_computer = next(n["node_id"] for n in nodes if n["management_group"] == mg and n["node_type"] == "Computer")
        edges.append({"source_id": first_computer, "target_id": connectivity_computer, "edge_type": "CONNECTS_TO", "properties": ""})

    return pd.DataFrame(nodes), pd.DataFrame(edges)


def main() -> None:
    NODES_OUT.parent.mkdir(parents=True, exist_ok=True)
    products = pd.read_csv(CVE_MASTER_PATH)["product"].dropna().unique().tolist()
    nodes_df, edges_df = generate_topology(products)
    nodes_df.to_csv(NODES_OUT, index=False)
    edges_df.to_csv(EDGES_OUT, index=False)
    print(f"Wrote {len(nodes_df)} nodes to {NODES_OUT}, {len(edges_df)} edges to {EDGES_OUT}")


if __name__ == "__main__":
    main()
```

```python
# src/generator/__init__.py
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_topology.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/generator/__init__.py src/generator/topology.py tests/test_topology.py
git commit -m "feat: add synthetic AzureHound-shaped topology generator (Agent 2)"
```

---

### Task 4: Contract validator (`src/ingestion/validate.py`)

**Files:**
- Create: `src/ingestion/validate.py`
- Test: `tests/test_validate.py`

**Interfaces:**
- Consumes: the four CSV files written by Tasks 1-3 (`microsoft_cve_master.csv`, `technique_map.csv`, `nodes_topology.csv`, `edges_topology.csv`).
- Produces: `validate_outputs(processed_dir: pathlib.Path, synthetic_dir: pathlib.Path) -> list[str]` (empty list = pass), `main() -> None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_validate.py
import pandas as pd
from src.ingestion.validate import validate_outputs


def _write(dir_, name, df):
    dir_.mkdir(parents=True, exist_ok=True)
    df.to_csv(dir_ / name, index=False)


def test_validate_outputs_passes_on_clean_data(tmp_path):
    processed = tmp_path / "processed"
    synthetic = tmp_path / "synthetic"
    _write(processed, "microsoft_cve_master.csv", pd.DataFrame([
        {"cve_id": "CVE-2026-0001", "vendor": "Microsoft", "product": "Exchange Server",
         "epss_score": 0.5, "epss_percentile": 0.9,
         "base_score": 8.8, "kev_flag": True, "kev_date_added": "2026-01-05",
         "ransomware_used": "Known"},
    ]))
    _write(processed, "technique_map.csv", pd.DataFrame([
        {"technique_id": "T1190", "technique_name": "x", "tactic": "y", "cwe_ids": ""},
    ]))
    _write(synthetic, "nodes_topology.csv", pd.DataFrame([
        {"node_id": "n1", "node_type": "Computer"},
        {"node_id": "n2", "node_type": "User"},
    ]))
    _write(synthetic, "edges_topology.csv", pd.DataFrame([
        {"source_id": "n1", "target_id": "n2", "edge_type": "HAS_SESSION"},
    ]))

    assert validate_outputs(processed, synthetic) == []


def test_validate_outputs_flags_null_cve_id_and_bad_ranges(tmp_path):
    processed = tmp_path / "processed"
    synthetic = tmp_path / "synthetic"
    _write(processed, "microsoft_cve_master.csv", pd.DataFrame([
        {"cve_id": None, "vendor": "Eric Allman", "product": "Sendmail",
         "epss_score": 1.5, "epss_percentile": 0.9,
         "base_score": 12.0, "kev_flag": False, "kev_date_added": "2026-01-05",
         "ransomware_used": None},
    ]))
    _write(processed, "technique_map.csv", pd.DataFrame([]))
    _write(synthetic, "nodes_topology.csv", pd.DataFrame([{"node_id": "n1", "node_type": "Computer"}]))
    _write(synthetic, "edges_topology.csv", pd.DataFrame([
        {"source_id": "n1", "target_id": "missing", "edge_type": "HAS_SESSION"},
    ]))

    violations = validate_outputs(processed, synthetic)

    assert any("null cve_id" in v for v in violations)
    assert any("epss_score" in v for v in violations)
    assert any("base_score" in v for v in violations)
    assert any("kev_date_added" in v for v in violations)
    assert any("Microsoft-scope filter" in v for v in violations)
    assert any("technique_map.csv is empty" in v for v in violations)
    assert any("dangling" in v for v in violations)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_validate.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.ingestion.validate'`

- [ ] **Step 3: Write the implementation**

```python
# src/ingestion/validate.py
"""Validates Agent 2 outputs against contracts/01_requirements_to_data.yaml's
consumer_must_validate checklist."""
import pathlib

import pandas as pd

from src.ingestion.cve_merge import is_microsoft_scope

DEFAULT_PROCESSED = pathlib.Path("data/processed")
DEFAULT_SYNTHETIC = pathlib.Path("data/synthetic")


def validate_outputs(processed_dir: pathlib.Path, synthetic_dir: pathlib.Path) -> list[str]:
    violations: list[str] = []

    cve_master = pd.read_csv(processed_dir / "microsoft_cve_master.csv")
    if len(cve_master) == 0:
        violations.append("microsoft_cve_master.csv is empty")
    if cve_master["cve_id"].isna().any():
        violations.append("microsoft_cve_master.csv has null cve_id")
    if cve_master["epss_score"].isna().any() or not cve_master["epss_score"].between(0, 1).all():
        violations.append("microsoft_cve_master.csv has epss_score outside [0, 1] or null")
    if not cve_master["epss_percentile"].between(0, 1).all():
        violations.append("microsoft_cve_master.csv has epss_percentile outside [0, 1]")
    if not cve_master["base_score"].between(0, 10).all():
        violations.append("microsoft_cve_master.csv has base_score outside [0, 10]")
    kev_rows = cve_master[cve_master["kev_flag"] == True]  # noqa: E712
    non_kev_rows = cve_master[cve_master["kev_flag"] == False]  # noqa: E712
    for col in ("kev_date_added", "ransomware_used"):
        if kev_rows[col].isna().any():
            violations.append(f"microsoft_cve_master.csv has kev_flag=True with null {col}")
        if non_kev_rows[col].notna().any():
            violations.append(f"microsoft_cve_master.csv has kev_flag=False with non-null {col}")
    out_of_scope = cve_master[~cve_master.apply(
        lambda r: bool(r["kev_flag"]) or is_microsoft_scope([str(r["vendor"]), str(r["product"])]),
        axis=1,
    )]
    if len(out_of_scope) > 0:
        violations.append(f"microsoft_cve_master.csv has {len(out_of_scope)} row(s) outside the Microsoft-scope filter")

    technique_map = pd.read_csv(processed_dir / "technique_map.csv")
    if len(technique_map) == 0:
        violations.append("technique_map.csv is empty")

    nodes = pd.read_csv(synthetic_dir / "nodes_topology.csv")
    edges = pd.read_csv(synthetic_dir / "edges_topology.csv")
    if len(nodes) == 0:
        violations.append("nodes_topology.csv is empty")
    if len(edges) == 0:
        violations.append("edges_topology.csv is empty")
    node_ids = set(nodes["node_id"])
    dangling = set(edges["source_id"]) - node_ids | set(edges["target_id"]) - node_ids
    if dangling:
        violations.append(f"edges_topology.csv has dangling node references: {sorted(dangling)[:5]}")

    return violations


def main() -> None:
    violations = validate_outputs(DEFAULT_PROCESSED, DEFAULT_SYNTHETIC)
    if violations:
        print(f"FAILED: {len(violations)} violation(s)")
        for v in violations:
            print(f"  - {v}")
        raise SystemExit(1)
    print("PASSED: all contract 01 checks satisfied")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_validate.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ingestion/validate.py tests/test_validate.py
git commit -m "feat: add contract 01 output validator (Agent 2)"
```

---

### Task 5: Orchestrator and end-to-end run (`scripts/build_dataset.py`)

**Files:**
- Create: `scripts/build_dataset.py`

**Interfaces:**
- Consumes: `src.ingestion.cve_merge.main`, `src.ingestion.technique_map.main`, `src.generator.topology.main`, `src.ingestion.validate.main` (all from Tasks 1-4, no new signatures).

- [ ] **Step 1: Write the orchestrator**

```python
# scripts/build_dataset.py
"""Runs the full Agent 2 (Data Engineer) pipeline: merge -> technique map ->
topology -> validate. Exits non-zero if validation fails."""
import sys

sys.path.insert(0, ".")

from src.ingestion import cve_merge, technique_map, validate  # noqa: E402
from src.generator import topology  # noqa: E402


def main() -> None:
    cve_merge.main()
    technique_map.main()
    topology.main()
    validate.main()


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the full pipeline against the real raw data**

Run: `python3 scripts/build_dataset.py`
Expected: prints row counts for each output file, then `PASSED: all contract 01 checks satisfied`, exit code 0.

- [ ] **Step 3: Spot-check the outputs**

Run: `python3 -c "import pandas as pd; df = pd.read_csv('data/processed/microsoft_cve_master.csv'); print(len(df)); print(df.head()); print(df['vendor'].str.lower().str.contains('microsoft|windows|azure|office|exchange').all())"`
Expected: row count > 0, all vendors match the Microsoft scope filter.

- [ ] **Step 4: Run the full test suite**

Run: `python3 -m pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/build_dataset.py data/processed data/synthetic
git commit -m "feat: add Agent 2 pipeline orchestrator and generated datasets"
```
