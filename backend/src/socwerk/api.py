from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Response, status

from .correlation import related_events
from .database import Database
from .detection import build_alerts
from .models import (
    AlertAction,
    DecisionCreate,
    EvidenceCreate,
    InvestigationItemCreate,
    SessionCreate,
)
from .query import QueryError, compile_query
from .reporting import html_report, json_report, markdown_report, report_payload
from .scenarios import ScenarioRepository

ALERT_TRANSITIONS = {
    "new": {"begin_triage": "in_progress"},
    "in_progress": {
        "escalate": "escalated",
        "mark_benign": "benign",
        "mark_false_positive": "false_positive",
        "confirm": "confirmed_incident",
    },
    "escalated": {
        "mark_benign": "benign",
        "mark_false_positive": "false_positive",
        "confirm": "confirmed_incident",
    },
}


def create_router(repository: ScenarioRepository, database: Database) -> APIRouter:
    router = APIRouter(prefix="/api")

    def pack_for_session(session_id: str) -> tuple[dict[str, Any], Any]:
        try:
            session = database.get_session(session_id)
            return session, repository.get(session["scenario_id"])
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    def ensure_event(pack: Any, event_id: str) -> None:
        if not any(event.id == event_id for event in pack.events):
            raise HTTPException(status_code=404, detail="Event not found")

    @router.get("/scenarios")
    def scenarios() -> list[dict[str, Any]]:
        return [
            {
                **pack.metadata.model_dump(mode="json"),
                "event_count": len(pack.events),
                "detection_count": len(pack.detections),
                "asset_count": len(pack.assets),
            }
            for pack in repository.list()
        ]

    @router.get("/scenarios/{scenario_id}")
    def scenario(scenario_id: str) -> dict[str, Any]:
        try:
            pack = repository.get(scenario_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {
            "metadata": pack.metadata.model_dump(mode="json"),
            "users": [item.model_dump(mode="json") for item in pack.users],
            "assets": [item.model_dump(mode="json") for item in pack.assets],
            "containment_options": [
                item.model_dump(mode="json") for item in pack.containment_options
            ],
            "event_count": len(pack.events),
            "detection_count": len(pack.detections),
        }

    @router.post("/sessions", status_code=status.HTTP_201_CREATED)
    def create_session(payload: SessionCreate) -> dict[str, Any]:
        try:
            repository.get(payload.scenario_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return database.create_session(payload.scenario_id)

    @router.get("/sessions/{session_id}")
    def get_session(session_id: str) -> dict[str, Any]:
        session, _pack = pack_for_session(session_id)
        return session

    @router.get("/sessions/{session_id}/events")
    def events(
        session_id: str,
        query: str = "",
        search: str = "",
        source: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        asset: str | None = None,
        user: str | None = None,
        mitre: str | None = None,
        detection: str | None = None,
        alert: str | None = None,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
        sort_by: Literal["timestamp", "severity", "source", "event_type"] = "timestamp",
        sort: Literal["asc", "desc"] = "asc",
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> dict[str, Any]:
        _session, pack = pack_for_session(session_id)
        try:
            predicate = compile_query(query)
        except QueryError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        for label, value in (("time_from", time_from), ("time_to", time_to)):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise HTTPException(status_code=422, detail=f"{label} must include a timezone")
        if time_from and time_to and time_from > time_to:
            raise HTTPException(status_code=422, detail="time_from must not be after time_to")
        generated_alerts = build_alerts(pack.events, pack.detections)
        alerts_by_event: dict[str, list[dict[str, Any]]] = {}
        for generated_alert in generated_alerts:
            for matched_event_id in generated_alert["event_ids"]:
                alerts_by_event.setdefault(matched_event_id, []).append(generated_alert)
        selected = []
        for event in pack.events:
            normalized = event.normalized
            haystack = " ".join(
                str(value)
                for value in (
                    event.id,
                    normalized.summary,
                    normalized.user_id,
                    normalized.asset_id,
                    normalized.source_ip,
                    normalized.destination_ip,
                    normalized.domain,
                    normalized.process_name,
                )
                if value
            ).casefold()
            if search and search.casefold() not in haystack:
                continue
            if source and normalized.source != source:
                continue
            if event_type and normalized.event_type != event_type:
                continue
            if severity and normalized.severity != severity:
                continue
            if asset and normalized.asset_id != asset:
                continue
            if user and normalized.user_id != user:
                continue
            if mitre and mitre not in normalized.mitre:
                continue
            event_alerts = alerts_by_event.get(event.id, [])
            if detection and not any(item["rule_id"] == detection for item in event_alerts):
                continue
            if alert and not any(item["id"] == alert for item in event_alerts):
                continue
            if time_from and normalized.timestamp < time_from:
                continue
            if time_to and normalized.timestamp > time_to:
                continue
            if predicate(event):
                selected.append(event)
        severity_order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        def event_sort_key(item: Any) -> Any:
            if sort_by == "severity":
                return severity_order[item.normalized.severity]
            return getattr(item.normalized, sort_by)

        selected.sort(key=event_sort_key, reverse=sort == "desc")
        facets = {
            "sources": sorted({item.normalized.source for item in pack.events}),
            "event_types": sorted({item.normalized.event_type for item in pack.events}),
            "severities": sorted({item.normalized.severity for item in pack.events}),
            "mitre": sorted({value for item in pack.events for value in item.normalized.mitre}),
        }
        return {
            "items": [
                {"id": item.id, **item.normalized.model_dump(mode="json")}
                for item in selected[offset : offset + limit]
            ],
            "total": len(selected),
            "offset": offset,
            "limit": limit,
            "facets": facets,
        }

    @router.get("/sessions/{session_id}/events/{event_id}")
    def event_detail(session_id: str, event_id: str) -> dict[str, Any]:
        _session, pack = pack_for_session(session_id)
        try:
            event = next(item for item in pack.events if item.id == event_id)
        except StopIteration as exc:
            raise HTTPException(status_code=404, detail="Event not found") from exc
        alerts = [
            alert
            for alert in build_alerts(pack.events, pack.detections)
            if event_id in alert["event_ids"]
        ]
        return {
            "id": event.id,
            "raw": event.raw,
            "normalized": event.normalized.model_dump(mode="json"),
            "related": related_events(event, pack.events),
            "alerts": alerts,
        }

    @router.get("/sessions/{session_id}/detections")
    def detections(session_id: str) -> list[dict[str, Any]]:
        _session, pack = pack_for_session(session_id)
        return [
            rule.model_dump(mode="json", exclude={"expected_event_ids"}) for rule in pack.detections
        ]

    @router.get("/sessions/{session_id}/alerts")
    def alerts(session_id: str) -> list[dict[str, Any]]:
        session, pack = pack_for_session(session_id)
        result = build_alerts(pack.events, pack.detections)
        for alert in result:
            state = session["alert_states"].get(alert["id"])
            alert["state"] = state["state"] if state else "new"
            alert["rationale"] = state["rationale"] if state else ""
        return result

    @router.post("/sessions/{session_id}/alerts/{alert_id}/actions")
    def alert_action(session_id: str, alert_id: str, payload: AlertAction) -> dict[str, str]:
        session, pack = pack_for_session(session_id)
        known = {item["id"] for item in build_alerts(pack.events, pack.detections)}
        if alert_id not in known:
            raise HTTPException(status_code=404, detail="Alert not found")
        current = session["alert_states"].get(alert_id, {}).get("state", "new")
        target = ALERT_TRANSITIONS.get(current, {}).get(payload.action)
        if target is None:
            raise HTTPException(
                status_code=409,
                detail=f"Action {payload.action!r} is not valid for alert state {current!r}",
            )
        try:
            return database.update_alert(session_id, alert_id, target, payload.rationale)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.post("/sessions/{session_id}/evidence", status_code=status.HTTP_201_CREATED)
    def add_evidence(session_id: str, payload: EvidenceCreate) -> dict[str, Any]:
        _session, pack = pack_for_session(session_id)
        ensure_event(pack, payload.event_id)
        try:
            return database.add_evidence(session_id, payload.event_id, payload.note)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.delete("/sessions/{session_id}/evidence/{evidence_id}", status_code=204)
    def remove_evidence(session_id: str, evidence_id: str) -> Response:
        pack_for_session(session_id)
        try:
            database.remove_evidence(session_id, evidence_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return Response(status_code=204)

    @router.post("/sessions/{session_id}/items/{kind}", status_code=status.HTTP_201_CREATED)
    def add_item(
        session_id: str,
        kind: Literal["note", "hypothesis", "finding"],
        payload: InvestigationItemCreate,
    ) -> dict[str, Any]:
        _session, pack = pack_for_session(session_id)
        for event_id in payload.evidence_event_ids:
            ensure_event(pack, event_id)
        try:
            return database.add_item(session_id, kind, payload.text, payload.evidence_event_ids)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.put("/sessions/{session_id}/decision")
    def save_decision(session_id: str, payload: DecisionCreate) -> dict[str, Any]:
        _session, pack = pack_for_session(session_id)
        user_ids = {item.id for item in pack.users}
        asset_ids = {item.id for item in pack.assets}
        option_ids = {item.id for item in pack.containment_options}
        invalid = (
            set(payload.affected_user_ids) - user_ids
            or set(payload.affected_asset_ids) - asset_ids
            or set(payload.containment_action_ids) - option_ids
        )
        if invalid:
            raise HTTPException(
                status_code=422, detail=f"Unknown referenced ids: {sorted(invalid)}"
            )
        try:
            return database.save_decision(session_id, payload.model_dump(mode="json"))
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    def set_score(selected: set[str], expected: set[str], points: int) -> float:
        if not selected and not expected:
            return float(points)
        if not selected or not expected:
            return 0.0
        precision = len(selected & expected) / len(selected)
        recall = len(selected & expected) / len(expected)
        return round(points * (2 * precision * recall / (precision + recall)), 1)

    @router.post("/sessions/{session_id}/submit")
    def submit(session_id: str) -> dict[str, Any]:
        session, pack = pack_for_session(session_id)
        decision = session["decision"]
        if decision is None:
            raise HTTPException(status_code=409, detail="An incident decision is required")
        expected = pack.expected_outcome
        breakdown = {
            "classification": 20.0
            if decision["classification"] == expected.classification
            else 0.0,
            "severity": 10.0 if decision["severity"] == expected.severity else 0.0,
            "affected_users": set_score(
                set(decision["affected_user_ids"]), set(expected.affected_user_ids), 10
            ),
            "affected_assets": set_score(
                set(decision["affected_asset_ids"]), set(expected.affected_asset_ids), 10
            ),
            "critical_evidence": set_score(
                {item["event_id"] for item in session["evidence"]},
                set(expected.critical_event_ids),
                20,
            ),
            "mitre_mapping": set_score(set(decision["mitre"]), set(expected.mitre), 10),
            "containment": set_score(
                set(decision["containment_action_ids"]),
                set(expected.containment_action_ids),
                10,
            ),
            "false_positive_handling": set_score(
                {
                    event_id
                    for alert in build_alerts(pack.events, pack.detections)
                    if session["alert_states"].get(alert["id"], {}).get("state")
                    in {"benign", "false_positive"}
                    for event_id in alert["event_ids"]
                },
                set(expected.false_positive_event_ids),
                10,
            ),
        }
        score = round(sum(breakdown.values()), 1)
        assessment = {
            "score": score,
            "maximum_score": 100,
            "breakdown": breakdown,
            "expected": expected.model_dump(mode="json"),
            "feedback": {
                "missed_critical_evidence": sorted(
                    set(expected.critical_event_ids)
                    - {item["event_id"] for item in session["evidence"]}
                ),
                "incorrectly_selected_evidence": sorted(
                    {item["event_id"] for item in session["evidence"]}
                    - set(expected.critical_event_ids)
                ),
            },
        }
        submitted = database.submit(session_id, assessment)
        return {"session": submitted, "assessment": assessment}

    @router.get("/sessions/{session_id}/report")
    def report(session_id: str, format: Literal["json", "markdown", "html"] = "json") -> Response:
        session, pack = pack_for_session(session_id)
        if session["status"] != "submitted" or session["assessment"] is None:
            raise HTTPException(status_code=409, detail="Report is available after submission")
        value = report_payload(session, pack)
        if format == "markdown":
            return Response(
                markdown_report(value),
                media_type="text/markdown; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="socwerk-report.md"'},
            )
        if format == "html":
            return Response(
                html_report(value),
                media_type="text/html; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="socwerk-report.html"'},
            )
        return Response(
            json_report(value),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="socwerk-report.json"'},
        )

    return router
