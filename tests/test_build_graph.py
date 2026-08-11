from unittest.mock import MagicMock, patch

import pytest


def test_main_exits_nonzero_when_validation_fails(monkeypatch):
    monkeypatch.setenv("NEO4J_PASSWORD", "test-password")
    fake_session = MagicMock()
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = fake_session

    with patch("scripts.build_graph.GraphDatabase") as fake_gdb, \
         patch("scripts.build_graph.apply_schema") as fake_apply, \
         patch("scripts.build_graph.import_graph") as fake_import, \
         patch("scripts.build_graph.validate_graph", return_value=["bad thing"]) as fake_validate:
        fake_gdb.driver.return_value = fake_driver

        from scripts.build_graph import main
        with pytest.raises(SystemExit) as exc:
            main()

        assert exc.value.code == 1
        fake_apply.assert_called_once_with(fake_session)
        fake_import.assert_called_once()
        fake_validate.assert_called_once()


def test_main_exits_zero_when_validation_passes(monkeypatch):
    monkeypatch.setenv("NEO4J_PASSWORD", "test-password")
    fake_session = MagicMock()
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = fake_session

    with patch("scripts.build_graph.GraphDatabase") as fake_gdb, \
         patch("scripts.build_graph.apply_schema"), \
         patch("scripts.build_graph.import_graph"), \
         patch("scripts.build_graph.validate_graph", return_value=[]):
        fake_gdb.driver.return_value = fake_driver

        from scripts.build_graph import main
        main()  # should not raise
