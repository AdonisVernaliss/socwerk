#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def request(base: str, path: str, method: str = "GET", payload: Any = None) -> Any:
    body = json.dumps(payload).encode() if payload is not None else None
    operation = urllib.request.Request(
        base + path,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(operation, timeout=10) as response:
        content = response.read()
        if "application/json" in response.headers.get("Content-Type", ""):
            return json.loads(content)
        return content.decode()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Exercise a running local SOCWerk stack"
    )
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--web", default="http://localhost:5173")
    parser.add_argument("--scenario", default="converging-signals")
    arguments = parser.parse_args()

    pack_path = ROOT / "scenarios" / arguments.scenario / "scenario.json"
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    expected = pack["expected_outcome"]

    health = request(arguments.api, "/health")
    assert health["status"] == "ok"
    web = request(arguments.web, "/")
    assert "SOCWerk" in web

    scenarios = request(arguments.api, "/api/scenarios")
    assert len(scenarios) >= 5
    assert "expected_outcome" not in json.dumps(scenarios)
    scenario_detail = request(arguments.api, f"/api/scenarios/{arguments.scenario}")
    assert scenario_detail["event_count"] == len(pack["events"])
    assert "expected_outcome" not in json.dumps(scenario_detail)

    session = request(
        arguments.api,
        "/api/sessions",
        "POST",
        {"scenario_id": arguments.scenario},
    )
    session_id = session["id"]
    events = request(arguments.api, f"/api/sessions/{session_id}/events?limit=25")
    assert events["total"] == len(pack["events"]) and len(events["items"]) == 25

    query = urllib.parse.urlencode(
        {
            "query": 'contains(summary, "PowerShell") and asset = asset-ws-610',
            "sort_by": "severity",
            "sort": "desc",
        }
    )
    queried = request(arguments.api, f"/api/sessions/{session_id}/events?{query}")
    assert queried["total"] >= 4
    filtered = request(
        arguments.api,
        f"/api/sessions/{session_id}/events?source=proxy&user=usr-fin-610",
    )
    assert filtered["total"] >= 3

    alerts = request(arguments.api, f"/api/sessions/{session_id}/alerts")
    focus_alert = next(item for item in alerts if item["severity"] == "high")
    focus_event_id = focus_alert["event_ids"][0]
    detail = request(
        arguments.api, f"/api/sessions/{session_id}/events/{focus_event_id}"
    )
    assert (
        detail["raw"]
        and detail["normalized"]
        and detail["related"]
        and detail["alerts"]
    )

    detections = request(arguments.api, f"/api/sessions/{session_id}/detections")
    assert detections and all("expected_event_ids" not in item for item in detections)
    detection_query = urllib.parse.urlencode({"detection": focus_alert["rule_id"]})
    by_detection = request(
        arguments.api, f"/api/sessions/{session_id}/events?{detection_query}"
    )
    assert by_detection["total"] >= 1
    alert_query = urllib.parse.urlencode({"alert": focus_alert["id"]})
    by_alert = request(
        arguments.api, f"/api/sessions/{session_id}/events?{alert_query}"
    )
    assert by_alert["total"] == 1

    critical = expected["critical_event_ids"]
    for event_id in critical:
        request(
            arguments.api,
            f"/api/sessions/{session_id}/evidence",
            "POST",
            {
                "event_id": event_id,
                "note": "Correlated evidence in the incident chronology.",
            },
        )
    for kind, text in [
        ("note", "The document and process ancestry share the same user and endpoint."),
        (
            "hypothesis",
            "Initial user interaction led to execution and later data access.",
        ),
        (
            "finding",
            "Archive creation and matching egress establish a completed transfer.",
        ),
    ]:
        request(
            arguments.api,
            f"/api/sessions/{session_id}/items/{kind}",
            "POST",
            {"text": text, "evidence_event_ids": critical[:2]},
        )

    false_positive_ids = set(expected["false_positive_event_ids"])
    false_positive_alerts = [
        item for item in alerts if set(item["event_ids"]) & false_positive_ids
    ]
    assert {
        item["event_ids"][0] for item in false_positive_alerts
    } == false_positive_ids
    for alert in false_positive_alerts:
        for action in ("begin_triage", "mark_false_positive"):
            request(
                arguments.api,
                f"/api/sessions/{session_id}/alerts/{alert['id']}/actions",
                "POST",
                {
                    "action": action,
                    "rationale": "Related operational context establishes legitimate activity.",
                },
            )

    decision = {
        "classification": expected["classification"],
        "severity": expected["severity"],
        "affected_user_ids": expected["affected_user_ids"],
        "affected_asset_ids": expected["affected_asset_ids"],
        "mitre": expected["mitre"],
        "containment_action_ids": expected["containment_action_ids"],
        "rationale": "Cross-source chronology confirms user execution, discovery, restricted data access, staging, and external transfer.",
    }
    request(arguments.api, f"/api/sessions/{session_id}/decision", "PUT", decision)
    submitted = request(arguments.api, f"/api/sessions/{session_id}/submit", "POST")
    assert submitted["assessment"]["score"] == 100
    report_json = request(
        arguments.api, f"/api/sessions/{session_id}/report?format=json"
    )
    report_markdown = request(
        arguments.api, f"/api/sessions/{session_id}/report?format=markdown"
    )
    report_html = request(
        arguments.api, f"/api/sessions/{session_id}/report?format=html"
    )
    assert report_json["classification"] == expected["classification"]
    assert "# SOCWerk Incident Report" in report_markdown
    assert "<!doctype html>" in report_html.lower()
    restored = request(arguments.api, f"/api/sessions/{session_id}")
    assert restored["status"] == "submitted" and len(restored["evidence"]) == len(
        critical
    )
    print(
        f"Live smoke test passed: scenario={arguments.scenario} "
        f"session={session_id} score=100"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
