# scripts/build_dataset.py
"""Runs the full Agent 2 (Data Engineer) pipeline: merge -> technique map ->
topology -> validate. Exits non-zero if validation fails."""
import sys

sys.path.insert(0, ".")

from src.ingestion import cve_merge, technique_map, validate  # noqa: E402
from src.generator import topology  # noqa: E402


def main() -> None:
    cve_merge.main()
    technique_map.main()
    topology.main()
    validate.main()


if __name__ == "__main__":
    main()
