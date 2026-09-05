from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LocalizedText(StrictModel):
    en: str = Field(min_length=1, max_length=5000)
    de: str = Field(min_length=1, max_length=5000)


class ScenarioMetadata(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    version: int = Field(ge=1)
    difficulty: Literal["foundation", "intermediate", "advanced"]
    estimated_minutes: int = Field(ge=10, le=240)
    title: LocalizedText
    description: LocalizedText
    learning_objectives: list[LocalizedText] = Field(min_length=2, max_length=10)


class UserEntity(StrictModel):
    id: str
    display_name: str
    department: str
    role: str
    baseline: LocalizedText


class AssetEntity(StrictModel):
    id: str
    hostname: str
    asset_type: Literal["workstation", "server", "identity", "network", "cloud"]
    owner_user_id: str | None = None
    operating_system: str | None = None
    criticality: Literal["low", "medium", "high", "critical"]


class NormalizedEvent(StrictModel):
    timestamp: datetime
    source: str
    event_type: str
    severity: Literal["informational", "low", "medium", "high", "critical"]
    summary: str
    user_id: str | None = None
    asset_id: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    domain: str | None = None
    process_name: str | None = None
    parent_process_name: str | None = None
    process_id: str | None = None
    parent_process_id: str | None = None
    session_id: str | None = None
    file_name: str | None = None
    bytes_out: int | None = Field(default=None, ge=0)
    outcome: str | None = None
    mitre: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_include_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value


class ScenarioEvent(StrictModel):
    id: str
    raw: dict[str, Any] | str
    normalized: NormalizedEvent
    related_event_ids: list[str] = Field(default_factory=list)


class DetectionCondition(StrictModel):
    field: str = Field(pattern=r"^[a-zA-Z0-9_.]+$")
    operator: Literal["equals", "not_equals", "contains", "in", "greater_than", "exists"]
    value: Any = None


class DetectionRule(StrictModel):
    id: str
    title: LocalizedText
    description: LocalizedText
    severity: Literal["low", "medium", "high", "critical"]
    mitre: list[str]
    false_positive_context: LocalizedText
    match: Literal["all", "any"]
    conditions: list[DetectionCondition] = Field(min_length=1, max_length=12)
    sigma: str = Field(min_length=20, max_length=12000)
    expected_event_ids: list[str] = Field(default_factory=list)


class ExpectedOutcome(StrictModel):
    classification: Literal["benign", "false_positive", "confirmed_incident"]
    severity: Literal["low", "medium", "high", "critical"]
    affected_user_ids: list[str]
    affected_asset_ids: list[str]
    critical_event_ids: list[str] = Field(min_length=1)
    mitre: list[str]
    containment_action_ids: list[str]
    false_positive_event_ids: list[str]
    explanation: LocalizedText
    lessons: list[LocalizedText]


class ContainmentOption(StrictModel):
    id: str
    label: LocalizedText
    description: LocalizedText


class ScenarioPack(StrictModel):
    schema_version: Literal[1]
    metadata: ScenarioMetadata
    users: list[UserEntity] = Field(min_length=1, max_length=200)
    assets: list[AssetEntity] = Field(min_length=1, max_length=200)
    events: list[ScenarioEvent] = Field(min_length=8, max_length=1000)
    detections: list[DetectionRule] = Field(min_length=1, max_length=100)
    containment_options: list[ContainmentOption] = Field(min_length=1, max_length=50)
    expected_outcome: ExpectedOutcome

    @field_validator("events")
    @classmethod
    def events_must_be_chronological(cls, events: list[ScenarioEvent]) -> list[ScenarioEvent]:
        timestamps = [event.normalized.timestamp for event in events]
        if timestamps != sorted(timestamps):
            raise ValueError("events must be ordered by normalized timestamp")
        return events

    @model_validator(mode="after")
    def validate_references(self) -> ScenarioPack:
        def ensure_unique(name: str, values: list[str]) -> set[str]:
            known = set(values)
            if len(known) != len(values):
                raise ValueError(f"duplicate {name} id")
            return known

        user_ids = ensure_unique("user", [item.id for item in self.users])
        asset_ids = ensure_unique("asset", [item.id for item in self.assets])
        event_ids = ensure_unique("event", [item.id for item in self.events])
        ensure_unique("detection", [item.id for item in self.detections])
        option_ids = ensure_unique(
            "containment option", [item.id for item in self.containment_options]
        )

        for asset in self.assets:
            if asset.owner_user_id and asset.owner_user_id not in user_ids:
                raise ValueError(f"asset {asset.id} references unknown owner {asset.owner_user_id}")
        for event in self.events:
            normalized = event.normalized
            if normalized.user_id and normalized.user_id not in user_ids:
                raise ValueError(f"event {event.id} references unknown user {normalized.user_id}")
            if normalized.asset_id and normalized.asset_id not in asset_ids:
                raise ValueError(f"event {event.id} references unknown asset {normalized.asset_id}")
            unknown_related = set(event.related_event_ids) - event_ids
            if unknown_related:
                raise ValueError(
                    f"event {event.id} has unknown relations {sorted(unknown_related)}"
                )
            if event.id in event.related_event_ids:
                raise ValueError(f"event {event.id} cannot relate to itself")
        for detection in self.detections:
            unknown_matches = set(detection.expected_event_ids) - event_ids
            if unknown_matches:
                raise ValueError(
                    f"detection {detection.id} has unknown expected events "
                    f"{sorted(unknown_matches)}"
                )
        outcome = self.expected_outcome
        available_mitre = {
            technique for detection in self.detections for technique in detection.mitre
        }
        available_mitre.update(
            technique for event in self.events for technique in event.normalized.mitre
        )
        if unavailable_mitre := set(outcome.mitre) - available_mitre:
            raise ValueError(
                "expected MITRE techniques are not available in events or detections "
                f"{sorted(unavailable_mitre)}"
            )
        checks = [
            ("affected users", set(outcome.affected_user_ids), user_ids),
            ("affected assets", set(outcome.affected_asset_ids), asset_ids),
            ("critical events", set(outcome.critical_event_ids), event_ids),
            ("false-positive events", set(outcome.false_positive_event_ids), event_ids),
            ("containment actions", set(outcome.containment_action_ids), option_ids),
        ]
        for label, referenced, known in checks:
            if unknown := referenced - known:
                raise ValueError(f"expected {label} reference unknown ids {sorted(unknown)}")
        return self


class SessionCreate(StrictModel):
    scenario_id: str


class AlertAction(StrictModel):
    action: Literal["begin_triage", "escalate", "mark_benign", "mark_false_positive", "confirm"]
    rationale: str = Field(min_length=3, max_length=2000)


class EvidenceCreate(StrictModel):
    event_id: str
    note: str = Field(default="", max_length=2000)


class InvestigationItemCreate(StrictModel):
    text: str = Field(min_length=2, max_length=5000)
    evidence_event_ids: list[str] = Field(default_factory=list, max_length=50)


class DecisionCreate(StrictModel):
    classification: Literal["benign", "false_positive", "confirmed_incident"]
    severity: Literal["low", "medium", "high", "critical"]
    affected_user_ids: list[str] = Field(default_factory=list)
    affected_asset_ids: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    containment_action_ids: list[str] = Field(default_factory=list)
    rationale: str = Field(min_length=10, max_length=5000)
