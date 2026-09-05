from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from socwerk.detection import build_alerts, validate_expected_matches
from socwerk.models import ScenarioPack
from socwerk.scenarios import ScenarioRepository


def scenario_repository() -> ScenarioRepository:
    repository = ScenarioRepository(Path(__file__).resolve().parents[2] / "scenarios")
    repository.load()
    return repository


def test_all_scenarios_are_valid_and_detections_are_deterministic() -> None:
    repository = scenario_repository()
    assert {pack.metadata.id for pack in repository.list()} == {
        "converging-signals",
        "suspicious-login",
        "phishing-investigation",
        "suspicious-powershell",
        "suspicious-file-transfer",
    }
    for pack in repository.list():
        assert validate_expected_matches(pack.events, pack.detections) == []
        assert build_alerts(pack.events, pack.detections) == build_alerts(
            pack.events, pack.detections
        )
        assert all(alert["match_details"] for alert in build_alerts(pack.events, pack.detections))


def test_advanced_scenario_has_investigative_depth() -> None:
    pack = scenario_repository().get("converging-signals")
    alerts = build_alerts(pack.events, pack.detections)
    sources = {event.normalized.source for event in pack.events}
    exposed_mitre = {technique for rule in pack.detections for technique in rule.mitre}

    assert pack.metadata.difficulty == "advanced"
    assert 150 <= len(pack.events) <= 250
    assert pack.metadata.estimated_minutes == 40
    assert len(pack.expected_outcome.critical_event_ids) < len(pack.events) // 10
    assert len(pack.expected_outcome.false_positive_event_ids) >= 4
    assert len(alerts) >= 12
    assert not any(alert["severity"] == "critical" for alert in alerts)
    assert set(pack.expected_outcome.mitre) <= exposed_mitre
    assert {
        "email",
        "windows_security",
        "sysmon",
        "powershell",
        "vpn",
        "mfa",
        "dns",
        "proxy",
        "endpoint_file",
        "endpoint_network",
        "zeek",
    } <= sources


def test_invalid_reference_is_rejected() -> None:
    path = Path(__file__).resolve().parents[2] / "scenarios" / "suspicious-login" / "scenario.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["events"][0]["normalized"]["asset_id"] = "unknown-asset"
    with pytest.raises(ValidationError, match="unknown asset"):
        ScenarioPack.model_validate(payload)


def test_duplicate_ids_are_rejected() -> None:
    pack = scenario_repository().get("phishing-investigation")
    payload = pack.model_dump(mode="json")
    payload["events"][1]["id"] = payload["events"][0]["id"]
    with pytest.raises(ValidationError, match="duplicate event id"):
        ScenarioPack.model_validate(payload)


def test_timezone_is_required_for_normalized_events() -> None:
    pack = scenario_repository().get("suspicious-login")
    payload = pack.model_dump(mode="json")
    payload["events"][0]["normalized"]["timestamp"] = "2026-02-17T07:52:11"
    with pytest.raises(ValidationError, match="timezone"):
        ScenarioPack.model_validate(payload)


def test_expected_mitre_must_be_available_to_the_analyst() -> None:
    pack = scenario_repository().get("converging-signals")
    payload = pack.model_dump(mode="json")
    payload["expected_outcome"]["mitre"].append("T9999")
    with pytest.raises(ValidationError, match="not available in events or detections"):
        ScenarioPack.model_validate(payload)
