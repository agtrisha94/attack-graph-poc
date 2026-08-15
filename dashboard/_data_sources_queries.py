"""Cypher queries for the Data Sources page: a presentation-oriented
explainer of the CVE ingestion pipeline and how synthetic assets get wired
to real CVEs -- see
docs/superpowers/plans/since-assets-are-synthetic-lexical-gizmo.md, Part 2,
Page 4."""

_CVE_FIELDS = """
       c.cve_id AS cve_id, c.vendor AS vendor, c.product AS product,
       c.description AS description, c.cwe_id AS cwe_id,
       c.base_severity AS base_severity, c.base_score AS base_score,
       c.attack_vector AS attack_vector, c.epss_score AS epss_score,
       c.epss_percentile AS epss_percentile, c.kev_flag AS kev_flag,
       c.kev_date_added AS kev_date_added, c.ransomware_used AS ransomware_used,
       c.published_date AS published_date
""".strip()

# UNION of a guaranteed KEV=true row with 4 KEV=false rows -- guarantees the
# sample always shows at least one of each, rather than leaving it to
# chance with a plain `LIMIT 5`.
SAMPLE_CVE_ROWS_QUERY = f"""
MATCH (c:CVE) WHERE c.kev_flag = true
WITH c LIMIT 1
RETURN {_CVE_FIELDS}
UNION
MATCH (c:CVE) WHERE c.kev_flag = false
WITH c LIMIT 4
RETURN {_CVE_FIELDS}
""".strip()

TOTAL_CVE_COUNT_QUERY = "MATCH (c:CVE) RETURN count(c) AS n"
KEV_COUNT_QUERY = "MATCH (c:CVE) WHERE c.kev_flag = true RETURN count(c) AS n"

SEVERITY_BREAKDOWN_QUERY = """
MATCH (c:CVE)
RETURN c.base_severity AS severity, count(c) AS count
""".strip()

TOP_PRODUCTS_QUERY = """
MATCH (c:CVE)
RETURN c.product AS product, count(c) AS count
ORDER BY count DESC
LIMIT 10
""".strip()

INSTALLED_SOFTWARE_EXAMPLE_QUERY = """
MATCH (c:CVE)-[:AFFECTS]->(a:Asset)
RETURN a.node_id AS asset_id, a.display_name AS display_name,
       a.installed_software AS installed_software, c.cve_id AS cve_id, c.product AS product
LIMIT 1
""".strip()


def read_sample_cve_rows(session) -> list[dict]:
    return [dict(record) for record in session.run(SAMPLE_CVE_ROWS_QUERY)]


def read_cve_stats(session) -> dict:
    total = session.run(TOTAL_CVE_COUNT_QUERY).single()["n"]
    kev_count = session.run(KEV_COUNT_QUERY).single()["n"]
    return {"total": total, "kev_count": kev_count}


def read_severity_breakdown(session) -> list[dict]:
    return [dict(record) for record in session.run(SEVERITY_BREAKDOWN_QUERY)]


def read_top_products(session) -> list[dict]:
    return [dict(record) for record in session.run(TOP_PRODUCTS_QUERY)]


def read_installed_software_example(session) -> dict | None:
    rows = [dict(record) for record in session.run(INSTALLED_SOFTWARE_EXAMPLE_QUERY)]
    return rows[0] if rows else None
