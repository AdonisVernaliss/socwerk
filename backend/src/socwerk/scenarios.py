from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from .models import ScenarioPack


class ScenarioError(RuntimeError):
    """Raised when scenario content cannot be loaded safely."""


def reject_non_finite(value: str) -> None:
    raise ValueError(f"Non-finite JSON number is not allowed: {value}")


class ScenarioRepository:
    maximum_pack_bytes = 10 * 1024 * 1024

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir.resolve()
        self._scenarios: dict[str, ScenarioPack] = {}

    def load(self) -> None:
        if not self.data_dir.is_dir():
            raise ScenarioError(f"Scenario directory does not exist: {self.data_dir}")
        loaded: dict[str, ScenarioPack] = {}
        for path in sorted(self.data_dir.glob("*/scenario.json")):
            resolved = path.resolve()
            if not resolved.is_relative_to(self.data_dir):
                raise ScenarioError(f"Scenario path escapes data directory: {path}")
            try:
                if path.stat().st_size > self.maximum_pack_bytes:
                    raise ScenarioError(
                        f"Scenario pack exceeds {self.maximum_pack_bytes} bytes: {path}"
                    )
                payload = json.loads(
                    path.read_text(encoding="utf-8"), parse_constant=reject_non_finite
                )
                pack = ScenarioPack.model_validate(payload)
            except (OSError, ValueError, RecursionError, ValidationError) as exc:
                raise ScenarioError(f"Invalid scenario pack at {path}: {exc}") from exc
            expected_parent = self.data_dir / pack.metadata.id
            if path.parent.resolve() != expected_parent.resolve():
                raise ScenarioError(
                    f"Scenario id {pack.metadata.id!r} does not match directory "
                    f"{path.parent.name!r}"
                )
            if pack.metadata.id in loaded:
                raise ScenarioError(f"Duplicate scenario id: {pack.metadata.id}")
            loaded[pack.metadata.id] = pack
        if not loaded:
            raise ScenarioError("No scenario packs found")
        self._scenarios = loaded

    def list(self) -> list[ScenarioPack]:
        return list(self._scenarios.values())

    def get(self, scenario_id: str) -> ScenarioPack:
        try:
            return self._scenarios[scenario_id]
        except KeyError as exc:
            raise KeyError(f"Unknown scenario: {scenario_id}") from exc
