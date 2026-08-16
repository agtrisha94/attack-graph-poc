import pytest

from src.paths.score import ATTACK_VECTOR_WEIGHT, CRITICALITY_WEIGHT, score_path

BASE_KWARGS = dict(kev_flag=False, hop_count=0, internet_facing=False, attack_vector=None)


def test_criticality_weight_covers_all_four_tiers():
    assert CRITICALITY_WEIGHT == {"Crown Jewel": 4, "High": 3, "Medium": 2, "Low": 1}


def test_score_path_multiplies_cvss_epss_and_criticality_weight():
    assert score_path(9.8, 0.94, "Crown Jewel", **BASE_KWARGS) == pytest.approx(9.8 * 0.94 * 4)
    assert score_path(9.8, 0.94, "High", **BASE_KWARGS) == pytest.approx(9.8 * 0.94 * 3)
    assert score_path(9.8, 0.94, "Medium", **BASE_KWARGS) == pytest.approx(9.8 * 0.94 * 2)
    assert score_path(9.8, 0.94, "Low", **BASE_KWARGS) == pytest.approx(9.8 * 0.94 * 1)


def test_score_path_zero_cvss_yields_zero_score():
    assert score_path(0.0, 0.94, "Crown Jewel", **BASE_KWARGS) == 0.0


def test_score_path_kev_doubles_score():
    plain = score_path(9.8, 0.94, "Crown Jewel", **BASE_KWARGS)
    kev = score_path(9.8, 0.94, "Crown Jewel", **{**BASE_KWARGS, "kev_flag": True})
    assert kev == pytest.approx(plain * 2.0)


def test_score_path_internet_facing_multiplies_score():
    plain = score_path(9.8, 0.94, "Crown Jewel", **BASE_KWARGS)
    exposed = score_path(9.8, 0.94, "Crown Jewel", **{**BASE_KWARGS, "internet_facing": True})
    assert exposed == pytest.approx(plain * 1.5)


def test_score_path_attack_vector_weight():
    for vector, weight in ATTACK_VECTOR_WEIGHT.items():
        expected = 9.8 * 0.94 * 4 * weight
        got = score_path(9.8, 0.94, "Crown Jewel", **{**BASE_KWARGS, "attack_vector": vector})
        assert got == pytest.approx(expected)


def test_score_path_unknown_attack_vector_defaults_to_neutral_weight():
    known = score_path(9.8, 0.94, "Crown Jewel", **BASE_KWARGS)
    unknown = score_path(9.8, 0.94, "Crown Jewel", **{**BASE_KWARGS, "attack_vector": "SOMETHING_NEW"})
    assert unknown == pytest.approx(known)


def test_score_path_decays_with_hop_count():
    scores = [
        score_path(9.8, 0.94, "Crown Jewel", **{**BASE_KWARGS, "hop_count": h})
        for h in range(4)
    ]
    assert all(a > b for a, b in zip(scores, scores[1:]))
    # hop_count 0 (exploitable asset is the crown jewel) is undiscounted
    assert scores[0] == pytest.approx(9.8 * 0.94 * 4)
