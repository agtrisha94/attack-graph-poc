from unittest.mock import MagicMock

from src.reasoning.writeback import clear_previous_results, write_reasoning


def test_clear_previous_results_detach_deletes_reasoning_nodes():
    session = MagicMock()

    clear_previous_results(session)

    query = session.run.call_args[0][0]
    assert "MATCH (r:Reasoning)" in query
    assert "DETACH DELETE r" in query


def test_write_reasoning_merges_on_path_id_and_links_explained_by():
    session = MagicMock()
    rows = [{
        "path_id": "abc123", "explanation": "CVE-... exploits ... reaches ...",
        "technique_ids": ["T1190"], "threat_actors": ["APT38"], "mitigations": ["Vulnerability Scanning"],
    }]

    written = write_reasoning(session, rows)

    assert written == 1
    query, kwargs = session.run.call_args
    assert "MATCH (p:AttackPath {path_id: row.path_id})" in query[0]
    assert "MERGE (r:Reasoning {path_id: row.path_id})" in query[0]
    assert "MERGE (p)-[:EXPLAINED_BY]->(r)" in query[0]
    [row] = kwargs["rows"]
    assert row["path_id"] == "abc123"
    assert row["threat_actors"] == ["APT38"]


def test_write_reasoning_noop_on_empty_rows():
    session = MagicMock()

    assert write_reasoning(session, []) == 0
    session.run.assert_not_called()
