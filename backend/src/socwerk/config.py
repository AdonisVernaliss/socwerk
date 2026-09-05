from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_path: Path
    allowed_origins: tuple[str, ...]

    @classmethod
    def from_environment(cls) -> Settings:
        repository_root = Path(__file__).resolve().parents[3]
        data_dir = Path(os.getenv("SOCWERK_DATA_DIR", repository_root / "scenarios"))
        database_path = Path(
            os.getenv("SOCWERK_DATABASE_PATH", repository_root / "data" / "socwerk.db")
        )
        origin_value = os.getenv(
            "SOCWERK_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        )
        origins = tuple(item.strip() for item in origin_value.split(",") if item.strip())
        return cls(data_dir=data_dir, database_path=database_path, allowed_origins=origins)
