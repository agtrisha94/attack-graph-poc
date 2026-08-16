"""Diffs a freshly re-scored candidate route set against the persisted
:AttackPath baseline Agent 5 left, classifying exactly three fixed alert
types -- new_top50_entry, score_change, dropped_from_top50 (see
docs/superpowers/specs/2026-08-16-watchdog-design.md, Re-score + diff
logic). Reuses src.paths.writeback.path_id_for so rescored routes match
baseline path_ids the same way Agent 4 assigned them."""
from src.paths.writeback import path_id_for

# 20%: clearly above float noise, comfortably below the ~2x/~2.1x swings the
# scenario injector's own mutations produce. Fixed, not configurable (YAGNI).
SCORE_CHANGE_THRESHOLD = 0.20

READ_BASELINE_QUERY = """
MATCH (p:AttackPath)
RETURN p.path_id AS path_id, p.score AS score, p.rank AS rank,
       p.source_cve AS source_cve, p.source_asset_id AS source_asset_id,
       p.target_asset_id AS target_asset_id
""".strip()


def read_baseline_paths(session) -> dict[str, dict]:
    return {row["path_id"]: dict(row) for row in session.run(READ_BASELINE_QUERY)}


def _alert(alert_type: str, path_id: str, *, old, new, source_cve, source_asset_id, target_asset_id) -> dict:
    return {
        "alert_id": f"{alert_type}:{path_id}",
        "alert_type": alert_type,
        "path_id": path_id,
        "old_score": old["score"] if old else None,
        "new_score": new["score"] if new else None,
        "old_rank": old["rank"] if old else None,
        "new_rank": new["rank"] if new else None,
        "source_cve": source_cve,
        "source_asset_id": source_asset_id,
        "target_asset_id": target_asset_id,
    }


def diff_paths(baseline: dict[str, dict], rescored_routes: list[dict]) -> list[dict]:
    rescored_by_id = {path_id_for(r["node_ids"]): r for r in rescored_routes}
    alerts = []

    for path_id, new in rescored_by_id.items():
        old = baseline.get(path_id)
        if old is None:
            alerts.append(_alert(
                "new_top50_entry", path_id, old=None, new=new,
                source_cve=new["source_cve"], source_asset_id=new["source_asset_id"],
                target_asset_id=new["target_asset_id"],
            ))
            continue
        old_score = old["score"]
        pct_change = abs(new["score"] - old_score) / old_score if old_score else float("inf")
        if pct_change > SCORE_CHANGE_THRESHOLD:
            alerts.append(_alert(
                "score_change", path_id, old=old, new=new,
                source_cve=new["source_cve"], source_asset_id=new["source_asset_id"],
                target_asset_id=new["target_asset_id"],
            ))

    for path_id, old in baseline.items():
        if path_id not in rescored_by_id:
            alerts.append(_alert(
                "dropped_from_top50", path_id, old=old, new=None,
                source_cve=old["source_cve"], source_asset_id=old["source_asset_id"],
                target_asset_id=old["target_asset_id"],
            ))

    return alerts
