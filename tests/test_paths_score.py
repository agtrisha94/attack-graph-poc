import pytest

from src.paths.score import CRITICALITY_WEIGHT, score_path


def test_criticality_weight_covers_all_four_tiers():
    assert CRITICALITY_WEIGHT == {"Crown Jewel": 4, "High": 3, "Medium": 2, "Low": 1}


def test_score_path_multiplies_cvss_epss_and_criticality_weight():
    assert score_path(9.8, 0.94, "Crown Jewel") == pytest.approx(9.8 * 0.94 * 4)
    assert score_path(9.8, 0.94, "High") == pytest.approx(9.8 * 0.94 * 3)
    assert score_path(9.8, 0.94, "Medium") == pytest.approx(9.8 * 0.94 * 2)
    assert score_path(9.8, 0.94, "Low") == pytest.approx(9.8 * 0.94 * 1)


def test_score_path_zero_cvss_yields_zero_score():
    assert score_path(0.0, 0.94, "Crown Jewel") == 0.0
