"""CVSS x EPSS x criticality scoring formula for attack-path ranking (see
docs/superpowers/specs/2026-08-11-path-engine-design.md, Scoring)."""

CRITICALITY_WEIGHT: dict[str, int] = {
    "Crown Jewel": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}


def score_path(base_score: float, epss_score: float, criticality_tier: str) -> float:
    return base_score * epss_score * CRITICALITY_WEIGHT[criticality_tier]
