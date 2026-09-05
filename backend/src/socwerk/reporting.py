from __future__ import annotations

import html
import json
from typing import Any

from .models import ScenarioPack


def markdown_text(value: object) -> str:
    """Render untrusted text as one inert Markdown line."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    for character in ("\\", "`", "*", "_", "{", "}", "[", "]", "<", ">", "#"):
        text = text.replace(character, f"\\{character}")
    return text


def html_text(value: object) -> str:
    return html.escape(str(value), quote=True)


def report_payload(session: dict[str, Any], pack: ScenarioPack) -> dict[str, Any]:
    decision = session["decision"]
    event_lookup = {event.id: event for event in pack.events}
    evidence = [
        {
            "event_id": item["event_id"],
            "timestamp": event_lookup[item["event_id"]].normalized.timestamp.isoformat(),
            "summary": event_lookup[item["event_id"]].normalized.summary,
            "analyst_note": item["note"],
        }
        for item in session["evidence"]
        if item["event_id"] in event_lookup
    ]
    evidence.sort(key=lambda item: item["timestamp"])
    items_by_kind = {
        kind: [item for item in session["items"] if item["kind"] == kind]
        for kind in ("note", "hypothesis", "finding")
    }
    return {
        "report_version": 1,
        "scenario": {
            "id": pack.metadata.id,
            "title": pack.metadata.title.model_dump(),
            "version": pack.metadata.version,
        },
        "session_id": session["id"],
        "generated_at": session["updated_at"],
        "classification": decision["classification"],
        "severity": decision["severity"],
        "summary": decision["rationale"],
        "affected_users": decision["affected_user_ids"],
        "affected_assets": decision["affected_asset_ids"],
        "timeline": evidence,
        "evidence": evidence,
        "detections": [
            {"alert_id": alert_id, **state} for alert_id, state in session["alert_states"].items()
        ],
        "mitre": decision["mitre"],
        "findings": items_by_kind["finding"],
        "hypotheses": items_by_kind["hypothesis"],
        "analyst_notes": items_by_kind["note"],
        "containment_decisions": decision["containment_action_ids"],
        "assessment": session["assessment"],
        "lessons_learned": [item.model_dump() for item in pack.expected_outcome.lessons],
    }


def markdown_report(report: dict[str, Any]) -> str:
    title = markdown_text(report["scenario"]["title"]["en"])
    lines = [
        f"# SOCWerk Incident Report — {title}",
        "",
        f"**Classification:** {report['classification'].replace('_', ' ').title()}  ",
        f"**Severity:** {report['severity'].title()}  ",
        f"**Scenario:** `{report['scenario']['id']}` v{report['scenario']['version']}  ",
        f"**Investigation ID:** `{report['session_id']}`",
        "",
        "## Executive / Incident Summary",
        "",
        markdown_text(report["summary"]),
        "",
        "## Affected Users and Assets",
        "",
        f"- Users: {', '.join(report['affected_users']) or 'None identified'}",
        f"- Assets: {', '.join(report['affected_assets']) or 'None identified'}",
        "",
        "## Timeline and Evidence",
        "",
    ]
    for item in report["timeline"]:
        note = f" — {markdown_text(item['analyst_note'])}" if item["analyst_note"] else ""
        lines.append(
            f"- {item['timestamp']} — `{item['event_id']}`: {markdown_text(item['summary'])}{note}"
        )
    if not report["timeline"]:
        lines.append("- No telemetry was preserved as evidence.")
    lines.extend(["", "## Findings", ""])
    lines.extend(f"- {markdown_text(item['text'])}" for item in report["findings"])
    if not report["findings"]:
        lines.append("- No formal findings recorded.")
    lines.extend(["", "## Detections and Alert Decisions", ""])
    lines.extend(
        f"- `{item['alert_id']}` — {item['state'].replace('_', ' ').title()}: "
        f"{markdown_text(item['rationale'])}"
        for item in report["detections"]
    )
    if not report["detections"]:
        lines.append("- No alert triage decisions recorded.")
    lines.extend(
        [
            "",
            "## MITRE ATT&CK Mapping",
            "",
            *(f"- {technique}" for technique in report["mitre"]),
            "",
            "## Containment Decisions",
            "",
            *(f"- {action}" for action in report["containment_decisions"]),
            "",
            "## Analyst Notes",
            "",
            *(f"- {markdown_text(item['text'])}" for item in report["analyst_notes"]),
            "",
            "## Lessons Learned",
            "",
            *(f"- {markdown_text(item['en'])}" for item in report["lessons_learned"]),
            "",
            "---",
            "Generated locally by SOCWerk. Containment actions are simulated.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def html_report(report: dict[str, Any]) -> str:
    def list_section(values: list[object]) -> str:
        return "<ul>" + "".join(f"<li>{html_text(value)}</li>" for value in values) + "</ul>"

    timeline = "".join(
        f"<li><time>{html_text(item['timestamp'])}</time> — "
        f"<code>{html_text(item['event_id'])}</code>: {html_text(item['summary'])}"
        f"{' — ' + html_text(item['analyst_note']) if item['analyst_note'] else ''}</li>"
        for item in report["timeline"]
    )
    detections = "".join(
        f"<li><code>{html_text(item['alert_id'])}</code> — "
        f"{html_text(item['state'].replace('_', ' ').title())}: "
        f"{html_text(item['rationale'])}</li>"
        for item in report["detections"]
    )
    body = "".join(
        [
            f"<h1>SOCWerk Incident Report — {html_text(report['scenario']['title']['en'])}</h1>",
            f"<dl><dt>Classification</dt><dd>{html_text(report['classification'])}</dd>",
            f"<dt>Severity</dt><dd>{html_text(report['severity'])}</dd>",
            "<dt>Investigation ID</dt><dd><code>"
            f"{html_text(report['session_id'])}</code></dd></dl>",
            "<h2>Executive / Incident Summary</h2>",
            f"<p>{html_text(report['summary'])}</p>",
            "<h2>Affected Users</h2>",
            list_section(report["affected_users"] or ["None identified"]),
            "<h2>Affected Assets</h2>",
            list_section(report["affected_assets"] or ["None identified"]),
            "<h2>Timeline and Evidence</h2>",
            f"<ul>{timeline}</ul>"
            if timeline
            else "<p>No telemetry was preserved as evidence.</p>",
            "<h2>Findings</h2>",
            list_section([item["text"] for item in report["findings"]] or ["None recorded"]),
            "<h2>Detections and Alert Decisions</h2>",
            f"<ul>{detections}</ul>" if detections else "<p>No alert decisions recorded.</p>",
            "<h2>MITRE ATT&amp;CK Mapping</h2>",
            list_section(report["mitre"]),
            "<h2>Containment Decisions</h2>",
            list_section(report["containment_decisions"]),
            "<h2>Analyst Notes</h2>",
            list_section([item["text"] for item in report["analyst_notes"]] or ["None recorded"]),
            "<h2>Lessons Learned</h2>",
            list_section([item["en"] for item in report["lessons_learned"]]),
            "<footer>Generated locally by SOCWerk. Containment actions are simulated.</footer>",
        ]
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>SOCWerk Incident Report</title><style>body{font:16px/1.55 system-ui;"
        "max-width:900px;margin:3rem auto;padding:0 1.5rem;color:#172033}"
        "h1,h2{color:#0d3b66}h2{margin-top:2rem}code{background:#eef2f7;"
        "padding:.1rem .3rem}dt{font-weight:700;float:left;clear:left;width:10rem}"
        "dd{margin-left:11rem}li{margin:.35rem 0}footer{margin-top:3rem;"
        "border-top:1px solid #ccd5df;"
        "padding-top:1rem;color:#546273;font-size:.85rem}"
        "</style></head><body>" + body + "</body></html>"
    )


def json_report(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)
