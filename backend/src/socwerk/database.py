from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class Database:
    def __init__(self, path: Path):
        self.path = path

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'submitted')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    decision_json TEXT,
                    assessment_json TEXT
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    event_id TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(session_id, event_id)
                );
                CREATE TABLE IF NOT EXISTS investigation_items (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL CHECK(kind IN ('note', 'hypothesis', 'finding')),
                    text TEXT NOT NULL,
                    evidence_event_ids_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alert_states (
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    alert_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(session_id, alert_id)
                );
                """
            )

    @staticmethod
    def now() -> str:
        return datetime.now(UTC).isoformat()

    def create_session(self, scenario_id: str) -> dict[str, Any]:
        session_id = str(uuid.uuid4())
        now = self.now()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO sessions(id, scenario_id, status, created_at, updated_at) "
                "VALUES (?, ?, 'active', ?, ?)",
                (session_id, scenario_id, now, now),
            )
        return self.get_session(session_id)

    def get_session(self, session_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
            if row is None:
                raise KeyError("Session not found")
            evidence = [
                dict(item)
                for item in connection.execute(
                    "SELECT id, event_id, note, created_at FROM evidence "
                    "WHERE session_id = ? ORDER BY created_at",
                    (session_id,),
                )
            ]
            items = []
            for item in connection.execute(
                "SELECT id, kind, text, evidence_event_ids_json, created_at "
                "FROM investigation_items WHERE session_id = ? ORDER BY created_at",
                (session_id,),
            ):
                value = dict(item)
                value["evidence_event_ids"] = json.loads(value.pop("evidence_event_ids_json"))
                items.append(value)
            alerts = {
                item["alert_id"]: {
                    "state": item["state"],
                    "rationale": item["rationale"],
                    "updated_at": item["updated_at"],
                }
                for item in connection.execute(
                    "SELECT alert_id, state, rationale, updated_at "
                    "FROM alert_states WHERE session_id = ?",
                    (session_id,),
                )
            }
        result = dict(row)
        result["decision"] = (
            json.loads(result.pop("decision_json")) if row["decision_json"] else None
        )
        result["assessment"] = (
            json.loads(result.pop("assessment_json")) if row["assessment_json"] else None
        )
        result["evidence"] = evidence
        result["items"] = items
        result["alert_states"] = alerts
        return result

    def require_active(self, session_id: str) -> dict[str, Any]:
        session = self.get_session(session_id)
        if session["status"] != "active":
            raise ValueError("Submitted investigations are read-only")
        return session

    def touch(self, connection: sqlite3.Connection, session_id: str) -> None:
        connection.execute(
            "UPDATE sessions SET updated_at = ? WHERE id = ?", (self.now(), session_id)
        )

    def add_evidence(self, session_id: str, event_id: str, note: str) -> dict[str, Any]:
        self.require_active(session_id)
        item_id = str(uuid.uuid4())
        now = self.now()
        try:
            with self.connect() as connection:
                connection.execute(
                    "INSERT INTO evidence(id, session_id, event_id, note, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (item_id, session_id, event_id, note, now),
                )
                self.touch(connection, session_id)
        except sqlite3.IntegrityError as exc:
            raise ValueError("Event is already in evidence") from exc
        return {"id": item_id, "event_id": event_id, "note": note, "created_at": now}

    def remove_evidence(self, session_id: str, evidence_id: str) -> None:
        self.require_active(session_id)
        with self.connect() as connection:
            cursor = connection.execute(
                "DELETE FROM evidence WHERE id = ? AND session_id = ?", (evidence_id, session_id)
            )
            if cursor.rowcount == 0:
                raise KeyError("Evidence not found")
            self.touch(connection, session_id)

    def add_item(
        self, session_id: str, kind: str, text: str, evidence_event_ids: list[str]
    ) -> dict[str, Any]:
        self.require_active(session_id)
        item_id = str(uuid.uuid4())
        now = self.now()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO investigation_items"
                "(id, session_id, kind, text, evidence_event_ids_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (item_id, session_id, kind, text, json.dumps(evidence_event_ids), now),
            )
            self.touch(connection, session_id)
        return {
            "id": item_id,
            "kind": kind,
            "text": text,
            "evidence_event_ids": evidence_event_ids,
            "created_at": now,
        }

    def update_alert(
        self, session_id: str, alert_id: str, state: str, rationale: str
    ) -> dict[str, str]:
        self.require_active(session_id)
        now = self.now()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO alert_states(session_id, alert_id, state, rationale, updated_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(session_id, alert_id) DO UPDATE SET "
                "state=excluded.state, rationale=excluded.rationale, "
                "updated_at=excluded.updated_at",
                (session_id, alert_id, state, rationale, now),
            )
            self.touch(connection, session_id)
        return {"state": state, "rationale": rationale, "updated_at": now}

    def save_decision(self, session_id: str, decision: dict[str, Any]) -> dict[str, Any]:
        self.require_active(session_id)
        with self.connect() as connection:
            connection.execute(
                "UPDATE sessions SET decision_json = ?, updated_at = ? WHERE id = ?",
                (json.dumps(decision), self.now(), session_id),
            )
        return decision

    def submit(self, session_id: str, assessment: dict[str, Any]) -> dict[str, Any]:
        self.require_active(session_id)
        with self.connect() as connection:
            connection.execute(
                "UPDATE sessions SET status='submitted', assessment_json=?, "
                "updated_at=? WHERE id=?",
                (json.dumps(assessment), self.now(), session_id),
            )
        return self.get_session(session_id)
