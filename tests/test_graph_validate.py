from unittest.mock import MagicMock

import pandas as pd

from src.graph.validate import validate_graph


def _write(dir_, name, df):
    dir_.mkdir(parents=True, exist_ok=True)
    df.to_csv(dir_ / name, index=False)


def _fake_session(records_by_call):
    """records_by_call: list of single-record dicts, one per expected session.run() call, in order."""
    session = MagicMock()
    results = []
    for record in records_by_call:
        result = MagicMock()
        result.single.return_value = record
        results.append(result)
    session.run.side_effect = results
    return session


def _setup_csvs(tmp_path):
    processed, synthetic = tmp_path / "processed", tmp_path / "synthetic"
    _write(processed, "microsoft_cve_master.csv", pd.DataFrame([
        {"cve_id": "CVE-1", "product": "exchange server", "cwe_id": "CWE-79"},
    ]))
    _write(processed, "technique_map.csv", pd.DataFrame([
        {"technique_id": "T1", "cwe_ids": "CWE-79"},
    ]))
    _write(synthetic, "nodes_topology.csv", pd.DataFrame([
        {"node_id": "n1", "installed_software": "exchange server"},
    ]))
    _write(synthetic, "edges_topology.csv", pd.DataFrame([{"source_id": "n1", "target_id": "n1"}]))
    return processed, synthetic


def test_validate_graph_passes_when_counts_and_coverage_match(tmp_path):
    processed, synthetic = _setup_csvs(tmp_path)
    session = _fake_session([
        {"n": 1},  # CVE count
        {"n": 1},  # Technique count
        {"n": 1},  # Asset count
        {"n": 1},  # topology edge count
        {"n": 1},  # AFFECTS count (expected 1: exchange server -> CVE-1 -> n1)
        {"n": 1},  # MAPS_TO count (expected 1: CWE-79 -> T1)
        {"n": 0},  # CVE nodes with a null required field
        {"n": 0},  # Assets with installed_software but zero AFFECTS edges
    ])
    assert validate_graph(session, processed, synthetic) == []


def test_validate_graph_flags_count_mismatch_and_missing_coverage(tmp_path):
    processed, synthetic = _setup_csvs(tmp_path)
    session = _fake_session([
        {"n": 0},  # CVE count mismatch (expected 1)
        {"n": 1},
        {"n": 1},
        {"n": 1},
        {"n": 1},  # AFFECTS count matches expected
        {"n": 1},  # MAPS_TO count matches expected
        {"n": 2},  # 2 CVE nodes missing a required field
        {"n": 3},  # 3 assets with software but no AFFECTS edge
    ])
    violations = validate_graph(session, processed, synthetic)
    assert any("CVE node count" in v for v in violations)
    assert any("missing a required field" in v for v in violations)
    assert any("no AFFECTS relationship" in v for v in violations)


def test_validate_graph_flags_affects_and_maps_to_count_mismatch(tmp_path):
    processed, synthetic = _setup_csvs(tmp_path)
    session = _fake_session([
        {"n": 1},  # CVE count
        {"n": 1},  # Technique count
        {"n": 1},  # Asset count
        {"n": 1},  # topology edge count
        {"n": 0},  # AFFECTS count mismatch (expected 1)
        {"n": 0},  # MAPS_TO count mismatch (expected 1)
        {"n": 0},  # CVE nodes with a null required field
        {"n": 1},  # Assets with installed_software but zero AFFECTS edges
    ])
    violations = validate_graph(session, processed, synthetic)
    assert any("AFFECTS relationship count 0 != expected 1" in v for v in violations)
    assert any("MAPS_TO relationship count 0 != expected 1" in v for v in violations)
