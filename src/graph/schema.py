"""Neo4j constraints/indexes derived from schemas/data_schema.yaml primary
keys. Community Edition has no property-existence constraints; required-field
enforcement lives in src/graph/validate.py instead."""

SCHEMA_STATEMENTS: list[str] = [
    "CREATE CONSTRAINT cve_id_unique IF NOT EXISTS "
    "FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE",
    "CREATE CONSTRAINT technique_id_unique IF NOT EXISTS "
    "FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE",
    "CREATE CONSTRAINT asset_node_id_unique IF NOT EXISTS "
    "FOR (a:Asset) REQUIRE a.node_id IS UNIQUE",
    "CREATE INDEX cve_product_index IF NOT EXISTS "
    "FOR (c:CVE) ON (c.product)",
]


def apply_schema(session) -> None:
    for statement in SCHEMA_STATEMENTS:
        session.run(statement)
