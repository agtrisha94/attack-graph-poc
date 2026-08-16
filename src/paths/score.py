"""CVSS x EPSS x criticality x KEV x exposure x attack-vector, decayed by hop
count, scoring formula for attack-path ranking (see
docs/superpowers/specs/2026-08-11-path-engine-design.md, Scoring)."""

CRITICALITY_WEIGHT: dict[str, int] = {
    "Crown Jewel": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}
KEV_MULTIPLIER = 2.0
EXPOSURE_MULTIPLIER = 1.5
ATTACK_VECTOR_WEIGHT: dict[str, float] = {
    "NETWORK": 1.5,
    "ADJACENT_NETWORK": 1.25,
    "LOCAL": 1.0,
    "PHYSICAL": 0.75,
}


def score_path(
    base_score: float,
    epss_score: float,
    criticality_tier: str,
    *,
    kev_flag: bool,
    hop_count: int,
    internet_facing: bool,
    attack_vector: str | None,
) -> float:
    return (
        base_score
        * epss_score
        * CRITICALITY_WEIGHT[criticality_tier]
        * (KEV_MULTIPLIER if kev_flag else 1.0)
        * (EXPOSURE_MULTIPLIER if internet_facing else 1.0)
        * ATTACK_VECTOR_WEIGHT.get(attack_vector, 1.0)
        / (hop_count + 1)
    )
