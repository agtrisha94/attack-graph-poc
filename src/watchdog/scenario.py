"""Deterministic synthetic scenario injector standing in for a live
threat-intel/topology feed -- this is a static synthetic dataset with no
live feed to watch (see docs/superpowers/specs/2026-08-16-watchdog-design.md,
Scope). Every mutation targets a real, already-existing CVE/Asset node id in
the live graph -- no fabricated entities (NFR2/NFR3). Idempotent: re-running
any of these is a no-op past the first call."""

KEV_DISCLOSURE_CVE = "CVE-2009-0133"
EPSS_SPIKE_CVE = "CVE-2024-29988"
EPSS_SPIKE_NEW_VALUE = 0.95
NEW_EDGE_SOURCE_ASSET = "computer-0078"
NEW_EDGE_TARGET_ASSET = "computer-0160"


def apply_kev_disclosure(session, cve_id: str = KEV_DISCLOSURE_CVE) -> dict:
    return dict(session.run(
        "MATCH (c:CVE {cve_id: $cve_id}) "
        "WITH c, c.kev_flag AS before "
        "SET c.kev_flag = true "
        "RETURN c.cve_id AS cve_id, before, c.kev_flag AS after",
        cve_id=cve_id,
    ).single())


def apply_epss_spike(session, cve_id: str = EPSS_SPIKE_CVE, new_epss: float = EPSS_SPIKE_NEW_VALUE) -> dict:
    return dict(session.run(
        "MATCH (c:CVE {cve_id: $cve_id}) "
        "WITH c, c.epss_score AS before "
        "SET c.epss_score = $new_epss "
        "RETURN c.cve_id AS cve_id, before, c.epss_score AS after",
        cve_id=cve_id, new_epss=new_epss,
    ).single())


def apply_new_topology_edge(
    session, source_asset_id: str = NEW_EDGE_SOURCE_ASSET, target_asset_id: str = NEW_EDGE_TARGET_ASSET
) -> dict:
    return dict(session.run(
        "MATCH (a:Asset {node_id: $source_asset_id}), (b:Asset {node_id: $target_asset_id}) "
        "MERGE (a)-[:CONNECTS_TO]->(b) "
        "RETURN a.node_id AS source_asset_id, b.node_id AS target_asset_id",
        source_asset_id=source_asset_id, target_asset_id=target_asset_id,
    ).single())
