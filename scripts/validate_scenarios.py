#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "backend" / "src"))

from socwerk.detection import validate_expected_matches
from socwerk.scenarios import ScenarioRepository


def main() -> int:
    repository = ScenarioRepository(REPOSITORY_ROOT / "scenarios")
    repository.load()
    errors: list[str] = []
    for pack in repository.list():
        errors.extend(
            f"{pack.metadata.id}: {error}"
            for error in validate_expected_matches(pack.events, pack.detections)
        )
    if errors:
        print("Scenario validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(
        f"Validated {len(repository.list())} scenario packs and their deterministic detections."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
