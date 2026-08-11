from unittest.mock import MagicMock

from src.graph.schema import SCHEMA_STATEMENTS, apply_schema


def test_schema_statements_cover_unique_keys_and_product_index():
    joined = " ".join(SCHEMA_STATEMENTS)
    assert "FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE" in joined
    assert "FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE" in joined
    assert "FOR (a:Asset) REQUIRE a.node_id IS UNIQUE" in joined
    assert "FOR (c:CVE) ON (c.product)" in joined
    assert all("IF NOT EXISTS" in s for s in SCHEMA_STATEMENTS)


def test_apply_schema_runs_every_statement():
    session = MagicMock()
    apply_schema(session)
    executed = [call.args[0] for call in session.run.call_args_list]
    assert executed == SCHEMA_STATEMENTS
