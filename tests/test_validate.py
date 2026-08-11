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
         "description": "Remote code execution in Exchange Server.",
         "base_severity": "HIGH", "published_date": "2026-01-01",
         "epss_score": 0.5, "epss_percentile": 0.9,
         "base_score": 8.8, "kev_flag": True, "kev_date_added": "2026-01-05",
         "ransomware_used": "Known"},
    ]))
    _write(processed, "technique_map.csv", pd.DataFrame([
        {"technique_id": "T1190", "technique_name": "x", "tactic": "y", "cwe_ids": ""},
    ]))
    _write(synthetic, "nodes_topology.csv", pd.DataFrame([
        {"node_id": "n1", "node_type": "Computer", "display_name": "Node One", "criticality_tier": "Medium"},
        {"node_id": "n2", "node_type": "User", "display_name": "Node Two", "criticality_tier": "Low"},
    ]))
    _write(synthetic, "edges_topology.csv", pd.DataFrame([
        {"source_id": "n1", "target_id": "n2", "edge_type": "HAS_SESSION"},
    ]))

    assert validate_outputs(processed, synthetic) == []


def test_validate_outputs_flags_missing_required_column(tmp_path):
    processed = tmp_path / "processed"
    synthetic = tmp_path / "synthetic"
    _write(processed, "microsoft_cve_master.csv", pd.DataFrame([
        {"cve_id": "CVE-2026-0001", "vendor": "Microsoft", "product": "Exchange Server",
         "description": "Remote code execution in Exchange Server.",
         "base_severity": "HIGH", "published_date": "2026-01-01",
         "epss_score": 0.5, "epss_percentile": 0.9,
         "base_score": 8.8, "kev_flag": True, "kev_date_added": "2026-01-05",
         "ransomware_used": "Known"},
    ]))
    # regression: producer drops the required technique_name column
    _write(processed, "technique_map.csv", pd.DataFrame([
        {"technique_id": "T1190", "tactic": "y", "cwe_ids": ""},
    ]))
    _write(synthetic, "nodes_topology.csv", pd.DataFrame([
        {"node_id": "n1", "node_type": "Computer", "display_name": "Node One", "criticality_tier": "Medium"},
        {"node_id": "n2", "node_type": "User", "display_name": "Node Two", "criticality_tier": "Low"},
    ]))
    _write(synthetic, "edges_topology.csv", pd.DataFrame([
        {"source_id": "n1", "target_id": "n2", "edge_type": "HAS_SESSION"},
    ]))

    violations = validate_outputs(processed, synthetic)

    assert any("technique_map.csv missing required columns" in v and "technique_name" in v for v in violations)


def test_validate_outputs_flags_kev_row_with_non_microsoft_vendor(tmp_path):
    # KEV membership alone must not exempt a row from the Microsoft-scope filter
    # (KEV covers all vendors, not just Microsoft) — regression test for the bug
    # fixed in cve_merge.py commit eb32d0c.
    processed = tmp_path / "processed"
    synthetic = tmp_path / "synthetic"
    _write(processed, "microsoft_cve_master.csv", pd.DataFrame([
        {"cve_id": "CVE-2026-9999", "vendor": "Cisco", "product": "IOS XE",
         "description": "Cisco IOS XE vulnerability.",
         "base_severity": "HIGH", "published_date": "2026-01-01",
         "epss_score": 0.5, "epss_percentile": 0.9,
         "base_score": 8.8, "kev_flag": True, "kev_date_added": "2026-01-05",
         "ransomware_used": "Known"},
    ]))
    _write(processed, "technique_map.csv", pd.DataFrame([
        {"technique_id": "T1190", "technique_name": "x", "tactic": "y", "cwe_ids": ""},
    ]))
    _write(synthetic, "nodes_topology.csv", pd.DataFrame([
        {"node_id": "n1", "node_type": "Computer", "display_name": "Node One", "criticality_tier": "Medium"},
        {"node_id": "n2", "node_type": "User", "display_name": "Node Two", "criticality_tier": "Low"},
    ]))
    _write(synthetic, "edges_topology.csv", pd.DataFrame([
        {"source_id": "n1", "target_id": "n2", "edge_type": "HAS_SESSION"},
    ]))

    violations = validate_outputs(processed, synthetic)

    assert any("Microsoft-scope filter" in v for v in violations)


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
