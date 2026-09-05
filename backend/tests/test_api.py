from __future__ import annotations

from fastapi.testclient import TestClient

from .conftest import start


def test_health_and_scenario_discovery_hide_expected_solutions(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok", "service": "socwerk-api"}
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    assert len(response.json()) == 5
    detail = client.get("/api/scenarios/suspicious-login")
    assert detail.status_code == 200
    serialized = detail.text
    assert "expected_outcome" not in serialized
    assert "critical_event_ids" not in serialized
    assert "expected_event_ids" not in serialized


def test_active_session_endpoints_do_not_disclose_solution(client: TestClient) -> None:
    session_id = start(client, "suspicious-login")
    for path in [
        f"/api/sessions/{session_id}",
        f"/api/sessions/{session_id}/events",
        f"/api/sessions/{session_id}/events/login-007",
        f"/api/sessions/{session_id}/detections",
        f"/api/sessions/{session_id}/alerts",
    ]:
        response = client.get(path)
        assert response.status_code == 200
        assert "expected_outcome" not in response.text
        assert "expected_event_ids" not in response.text
        assert "critical_event_ids" not in response.text
    assert client.get(f"/api/sessions/{session_id}").json()["assessment"] is None


def test_session_event_filters_detail_and_correlation(client: TestClient) -> None:
    session_id = start(client, "suspicious-powershell")
    response = client.get(
        f"/api/sessions/{session_id}/events",
        params={"query": "source = sysmon and severity = high", "limit": 2},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 3
    assert len(response.json()["items"]) == 2

    detection_filtered = client.get(
        f"/api/sessions/{session_id}/events",
        params={"detection": "det-powershell-process", "sort_by": "severity", "sort": "desc"},
    )
    assert [item["id"] for item in detection_filtered.json()["items"]] == ["ps-004", "ps-010"]

    time_filtered = client.get(
        f"/api/sessions/{session_id}/events",
        params={"time_from": "2026-04-14T09:00:00Z", "user": "usr-admin-050"},
    )
    assert time_filtered.json()["total"] == 4
    invalid_time = client.get(
        f"/api/sessions/{session_id}/events",
        params={"time_from": "2026-04-14T10:00:00", "time_to": "2026-04-14T09:00:00Z"},
    )
    assert invalid_time.status_code == 422

    detail = client.get(f"/api/sessions/{session_id}/events/ps-004")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["raw"]["EventID"] == 1
    assert payload["normalized"]["event_type"] == "process_created"
    assert any(item["event_id"] == "ps-003" for item in payload["related"])
    assert payload["alerts"][0]["match_details"]


def test_malformed_query_is_a_safe_client_error(client: TestClient) -> None:
    session_id = start(client)
    response = client.get(
        f"/api/sessions/{session_id}/events", params={"query": "source ~~ sysmon"}
    )
    assert response.status_code == 422
    assert "Unexpected token" in response.json()["detail"]


def test_evidence_items_and_state_survive_api_reload(client: TestClient) -> None:
    session_id = start(client)
    evidence = client.post(
        f"/api/sessions/{session_id}/evidence",
        json={"event_id": "login-005", "note": "Success follows the failure burst."},
    )
    assert evidence.status_code == 201
    finding = client.post(
        f"/api/sessions/{session_id}/items/finding",
        json={"text": "Credentials were successfully used.", "evidence_event_ids": ["login-005"]},
    )
    assert finding.status_code == 201
    reloaded = client.get(f"/api/sessions/{session_id}").json()
    assert reloaded["evidence"][0]["event_id"] == "login-005"
    assert reloaded["items"][0]["kind"] == "finding"

    duplicate = client.post(
        f"/api/sessions/{session_id}/evidence",
        json={"event_id": "login-005", "note": "duplicate"},
    )
    assert duplicate.status_code == 409


def test_alert_lifecycle_enforces_analyst_actions(client: TestClient) -> None:
    session_id = start(client)
    alerts = client.get(f"/api/sessions/{session_id}/alerts").json()
    alert_id = next(item["id"] for item in alerts if item["event_ids"] == ["login-011"])

    invalid = client.post(
        f"/api/sessions/{session_id}/alerts/{alert_id}/actions",
        json={"action": "mark_false_positive", "rationale": "Approved travel context."},
    )
    assert invalid.status_code == 409

    started = client.post(
        f"/api/sessions/{session_id}/alerts/{alert_id}/actions",
        json={"action": "begin_triage", "rationale": "Review device and travel context."},
    )
    assert started.json()["state"] == "in_progress"
    completed = client.post(
        f"/api/sessions/{session_id}/alerts/{alert_id}/actions",
        json={"action": "mark_false_positive", "rationale": "Managed device and approved travel."},
    )
    assert completed.json()["state"] == "false_positive"


def test_submission_scores_and_unlocks_all_report_formats(client: TestClient) -> None:
    session_id = start(client)
    locked = client.get(f"/api/sessions/{session_id}/report")
    assert locked.status_code == 409

    for event_id in ["login-004", "login-005", "login-006", "login-007", "login-009"]:
        note = (
            "<script>alert(1)</script> remains inert evidence text."
            if event_id == "login-004"
            else "Correlated identity evidence."
        )
        assert (
            client.post(
                f"/api/sessions/{session_id}/evidence",
                json={"event_id": event_id, "note": note},
            ).status_code
            == 201
        )
    alert_id = next(
        item["id"]
        for item in client.get(f"/api/sessions/{session_id}/alerts").json()
        if item["event_ids"] == ["login-011"]
    )
    for action in ["begin_triage", "mark_false_positive"]:
        response = client.post(
            f"/api/sessions/{session_id}/alerts/{alert_id}/actions",
            json={"action": action, "rationale": "Approved travel on a managed device."},
        )
        assert response.status_code == 200
    decision = {
        "classification": "confirmed_incident",
        "severity": "high",
        "affected_user_ids": ["usr-fin-104"],
        "affected_asset_ids": ["asset-idp", "asset-vpn"],
        "mitre": ["T1078", "T1110"],
        "containment_action_ids": ["revoke-identity-sessions", "reset-credentials"],
        "rationale": (
            "The correlated failure, success, MFA, VPN, and fraud-report sequence "
            "confirms compromise."
        ),
    }
    assert client.put(f"/api/sessions/{session_id}/decision", json=decision).status_code == 200
    submitted = client.post(f"/api/sessions/{session_id}/submit")
    assert submitted.status_code == 200
    assert submitted.json()["assessment"]["score"] == 100

    for format_name, content_type in [
        ("json", "application/json"),
        ("markdown", "text/markdown"),
        ("html", "text/html"),
    ]:
        report = client.get(f"/api/sessions/{session_id}/report", params={"format": format_name})
        assert report.status_code == 200
        assert content_type in report.headers["content-type"]
        assert "SOCWerk" in report.text or format_name == "json"
        if format_name == "html":
            assert "<script>" not in report.text
            assert "&lt;script&gt;" in report.text
        if format_name == "markdown":
            assert "<script>" not in report.text
            assert "\\<script\\>" in report.text

    frozen = client.post(
        f"/api/sessions/{session_id}/evidence",
        json={"event_id": "login-003", "note": "late edit"},
    )
    assert frozen.status_code == 409


def test_unknown_references_are_rejected(client: TestClient) -> None:
    session_id = start(client)
    unknown_event = client.post(
        f"/api/sessions/{session_id}/evidence", json={"event_id": "missing", "note": "x"}
    )
    assert unknown_event.status_code == 404
    unknown_scenario = client.post("/api/sessions", json={"scenario_id": "missing"})
    assert unknown_scenario.status_code == 404
