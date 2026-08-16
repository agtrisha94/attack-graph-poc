from unittest.mock import MagicMock

from src.watchdog.writeback import clear_previous_alerts, write_alerts


def test_clear_previous_alerts_detach_deletes_alert_nodes():
    session = MagicMock()

    clear_previous_alerts(session)

    query = session.run.call_args[0][0]
    assert "MATCH (a:Alert)" in query
    assert "DETACH DELETE a" in query


def test_write_alerts_merges_on_alert_id():
    session = MagicMock()
    alerts = [{
        "alert_id": "score_change:abc123", "alert_type": "score_change", "path_id": "abc123",
        "old_score": 10.0, "new_score": 20.0, "old_rank": 10, "new_rank": 3,
        "source_cve": "CVE-X", "source_asset_id": "computer-0001", "target_asset_id": "computer-0002",
    }]

    written = write_alerts(session, alerts)

    assert written == 1
    query, kwargs = session.run.call_args
    assert "MERGE (a:Alert {alert_id: row.alert_id})" in query[0]
    assert "SET a += row" in query[0]
    [row] = kwargs["rows"]
    assert row["alert_id"] == "score_change:abc123"


def test_write_alerts_noop_on_empty_alerts():
    session = MagicMock()

    assert write_alerts(session, []) == 0
    session.run.assert_not_called()
