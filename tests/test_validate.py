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
