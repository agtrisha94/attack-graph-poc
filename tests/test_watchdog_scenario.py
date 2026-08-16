from unittest.mock import MagicMock

from src.watchdog.scenario import (
    apply_epss_spike,
    apply_kev_disclosure,
    apply_new_topology_edge,
)


def _fake_session(record):
    session = MagicMock()
    result = MagicMock()
    result.single.return_value = record
    session.run.return_value = result
    return session


def test_apply_kev_disclosure_sets_kev_flag_true_and_returns_before_after():
    session = _fake_session({"cve_id": "CVE-2009-0133", "before": False, "after": True})

    result = apply_kev_disclosure(session, cve_id="CVE-2009-0133")

    assert result == {"cve_id": "CVE-2009-0133", "before": False, "after": True}
    query, kwargs = session.run.call_args
    assert "MATCH (c:CVE {cve_id: $cve_id})" in query[0]
    assert "SET c.kev_flag = true" in query[0]
    assert kwargs["cve_id"] == "CVE-2009-0133"


def test_apply_epss_spike_sets_epss_score_and_returns_before_after():
    session = _fake_session({"cve_id": "CVE-2024-29988", "before": 0.45151, "after": 0.95})

    result = apply_epss_spike(session, cve_id="CVE-2024-29988", new_epss=0.95)

    assert result == {"cve_id": "CVE-2024-29988", "before": 0.45151, "after": 0.95}
    query, kwargs = session.run.call_args
    assert "SET c.epss_score = $new_epss" in query[0]
    assert kwargs == {"cve_id": "CVE-2024-29988", "new_epss": 0.95}


def test_apply_new_topology_edge_merges_connects_to():
    session = _fake_session({"source_asset_id": "computer-0078", "target_asset_id": "computer-0160"})

    result = apply_new_topology_edge(session, source_asset_id="computer-0078", target_asset_id="computer-0160")

    assert result == {"source_asset_id": "computer-0078", "target_asset_id": "computer-0160"}
    query, kwargs = session.run.call_args
    assert "MERGE (a)-[:CONNECTS_TO]->(b)" in query[0]
    assert kwargs == {"source_asset_id": "computer-0078", "target_asset_id": "computer-0160"}


def test_scenario_defaults_target_real_baseline_ids():
    from src.watchdog.scenario import (
        EPSS_SPIKE_CVE,
        KEV_DISCLOSURE_CVE,
        NEW_EDGE_SOURCE_ASSET,
        NEW_EDGE_TARGET_ASSET,
    )

    assert KEV_DISCLOSURE_CVE == "CVE-2009-0133"
    assert EPSS_SPIKE_CVE == "CVE-2024-29988"
    assert NEW_EDGE_SOURCE_ASSET == "computer-0078"
    assert NEW_EDGE_TARGET_ASSET == "computer-0160"
