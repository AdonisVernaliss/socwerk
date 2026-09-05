from __future__ import annotations

from typing import Any

from .models import DetectionCondition, DetectionRule, ScenarioEvent


def field_value(event: ScenarioEvent, path: str) -> Any:
    path = {"user": "user_id", "asset": "asset_id", "type": "event_type"}.get(path, path)
    current: Any = event.normalized.model_dump(mode="json")
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def condition_matches(event: ScenarioEvent, condition: DetectionCondition) -> bool:
    actual = field_value(event, condition.field)
    expected = condition.value
    if condition.operator == "exists":
        return (actual is not None) is bool(expected)
    if condition.operator == "equals":
        return actual == expected
    if condition.operator == "not_equals":
        return actual != expected
    if condition.operator == "contains":
        if isinstance(actual, list):
            return expected in actual
        return str(expected).casefold() in str(actual or "").casefold()
    if condition.operator == "in":
        return actual in expected if isinstance(expected, list) else False
    if condition.operator == "greater_than":
        try:
            return float(actual) > float(expected)
        except (TypeError, ValueError):
            return False
    return False


def evaluate_rule(event: ScenarioEvent, rule: DetectionRule) -> tuple[bool, list[dict[str, Any]]]:
    outcomes = [condition_matches(event, condition) for condition in rule.conditions]
    matched = all(outcomes) if rule.match == "all" else any(outcomes)
    details = [
        {
            "field": condition.field,
            "operator": condition.operator,
            "expected": condition.value,
            "actual": field_value(event, condition.field),
            "matched": outcome,
        }
        for condition, outcome in zip(rule.conditions, outcomes, strict=True)
    ]
    return matched, details


def build_alerts(events: list[ScenarioEvent], rules: list[DetectionRule]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for rule in rules:
        for event in events:
            matched, details = evaluate_rule(event, rule)
            if matched:
                alerts.append(
                    {
                        "id": f"alert-{rule.id}-{event.id}",
                        "rule_id": rule.id,
                        "event_ids": [event.id],
                        "timestamp": event.normalized.timestamp.isoformat(),
                        "severity": rule.severity,
                        "title": rule.title.model_dump(),
                        "mitre": rule.mitre,
                        "match_details": details,
                        "false_positive_context": rule.false_positive_context.model_dump(),
                    }
                )
    return alerts


def validate_expected_matches(events: list[ScenarioEvent], rules: list[DetectionRule]) -> list[str]:
    errors: list[str] = []
    for rule in rules:
        actual = {event.id for event in events if evaluate_rule(event, rule)[0]}
        expected = set(rule.expected_event_ids)
        if actual != expected:
            errors.append(f"{rule.id}: expected {sorted(expected)}, evaluated {sorted(actual)}")
    return errors
