from __future__ import annotations

from .models import ScenarioEvent


def related_events(target: ScenarioEvent, events: list[ScenarioEvent]) -> list[dict[str, object]]:
    related: list[dict[str, object]] = []
    left = target.normalized
    for candidate in events:
        if candidate.id == target.id:
            continue
        right = candidate.normalized
        reasons: list[str] = []
        if candidate.id in target.related_event_ids or target.id in candidate.related_event_ids:
            reasons.append("explicit scenario relationship")
        comparisons = [
            ("user_id", "same user"),
            ("asset_id", "same asset"),
            ("source_ip", "same source IP"),
            ("destination_ip", "same destination IP"),
            ("domain", "same domain"),
            ("session_id", "same authentication session"),
        ]
        for field, label in comparisons:
            first, second = getattr(left, field), getattr(right, field)
            if first is not None and first == second:
                reasons.append(label)
        process_link = (
            left.process_id
            and right.parent_process_id
            and left.process_id == right.parent_process_id
        ) or (
            right.process_id
            and left.parent_process_id
            and right.process_id == left.parent_process_id
        )
        if process_link:
            reasons.append("parent/child process")
        delta = abs((left.timestamp - right.timestamp).total_seconds())
        if reasons and delta <= 300:
            reasons.append(f"within {max(1, round(delta / 60))} minute(s)")
        meaningful = "explicit scenario relationship" in reasons or len(reasons) >= 2
        if meaningful:
            related.append(
                {
                    "event_id": candidate.id,
                    "timestamp": right.timestamp.isoformat(),
                    "summary": right.summary,
                    "reasons": reasons,
                    "strength": min(100, 25 * len(reasons)),
                }
            )
    return sorted(related, key=lambda item: (-int(item["strength"]), str(item["timestamp"])))[:20]
