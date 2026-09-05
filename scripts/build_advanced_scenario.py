#!/usr/bin/env python3
"""Build the deterministic Converging Signals scenario pack."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "scenarios" / "converging-signals" / "scenario.json"
DAY = "2026-06-16"


def localized(en: str, de: str) -> dict[str, str]:
    return {"en": en, "de": de}


def moment(value: str) -> datetime:
    return datetime.fromisoformat(f"{DAY}T{value}+00:00")


def iso(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_pack() -> dict[str, Any]:
    events: list[dict[str, Any]] = []

    def add(
        key: str,
        timestamp: datetime,
        raw: dict[str, Any] | str,
        *,
        source: str,
        event_type: str,
        severity: str,
        summary: str,
        related: tuple[str, ...] = (),
        **fields: Any,
    ) -> None:
        normalized = {
            "timestamp": iso(timestamp),
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "summary": summary,
            "mitre": fields.pop("mitre", []),
            "attributes": fields.pop("attributes", {}),
            **fields,
        }
        events.append(
            {
                "_key": key,
                "raw": raw,
                "normalized": normalized,
                "_related": list(related),
            }
        )

    users = [
        {
            "id": "usr-fin-610",
            "display_name": "Finance Analyst 610",
            "department": "Finance",
            "role": "Planning analyst",
            "baseline": localized(
                "Works weekdays from WS-610, uses Office and the finance share, and does not run administration tools.",
                "Arbeitet werktags an WS-610, nutzt Office und die Finanzfreigabe und verwendet keine Administrationswerkzeuge.",
            ),
        },
        {
            "id": "usr-admin-030",
            "display_name": "Endpoint Admin 030",
            "department": "IT Operations",
            "role": "Endpoint administrator",
            "baseline": localized(
                "Uses MGMT-030 for signed PowerShell maintenance tied to approved change windows.",
                "Nutzt MGMT-030 für signierte PowerShell-Wartung in genehmigten Änderungsfenstern.",
            ),
        },
        {
            "id": "usr-sales-241",
            "display_name": "Sales Manager 241",
            "department": "Sales",
            "role": "Regional sales manager",
            "baseline": localized(
                "Frequently travels with LT-241; itinerary exceptions are recorded before unusual VPN access.",
                "Reist häufig mit LT-241; Reiseausnahmen werden vor ungewöhnlichen VPN-Zugriffen dokumentiert.",
            ),
        },
        {
            "id": "usr-media-088",
            "display_name": "Media Specialist 088",
            "department": "Communications",
            "role": "Media producer",
            "baseline": localized(
                "Uploads large approved media packages from WS-088 to the corporate collaboration tenant.",
                "Lädt große genehmigte Medienpakete von WS-088 in den unternehmenseigenen Kollaborationstenant hoch.",
            ),
        },
        {
            "id": "usr-eng-455",
            "display_name": "Platform Engineer 455",
            "department": "Engineering",
            "role": "Platform engineer",
            "baseline": localized(
                "Runs documented validation traffic from WS-455 during platform maintenance windows.",
                "Erzeugt während dokumentierter Plattformwartungen Validierungsverkehr von WS-455.",
            ),
        },
        {
            "id": "svc-backup-020",
            "display_name": "Backup Service 020",
            "department": "IT Operations",
            "role": "Managed service identity",
            "baseline": localized(
                "Authenticates only from BACKUP-01 and transfers scheduled encrypted backup sets to the approved vault.",
                "Authentifiziert sich nur von BACKUP-01 und überträgt planmäßig verschlüsselte Sicherungen in den genehmigten Tresor.",
            ),
        },
    ]
    assets = [
        {
            "id": "asset-ws-610",
            "hostname": "WS-610",
            "asset_type": "workstation",
            "owner_user_id": "usr-fin-610",
            "operating_system": "Windows 11",
            "criticality": "high",
        },
        {
            "id": "asset-files-02",
            "hostname": "FILES-02",
            "asset_type": "server",
            "owner_user_id": None,
            "operating_system": "Windows Server 2025",
            "criticality": "critical",
        },
        {
            "id": "asset-idp-01",
            "hostname": "IDP-01",
            "asset_type": "identity",
            "owner_user_id": None,
            "operating_system": None,
            "criticality": "critical",
        },
        {
            "id": "asset-mail-01",
            "hostname": "MAIL-01",
            "asset_type": "cloud",
            "owner_user_id": None,
            "operating_system": None,
            "criticality": "high",
        },
        {
            "id": "asset-proxy-01",
            "hostname": "WEB-PROXY-01",
            "asset_type": "network",
            "owner_user_id": None,
            "operating_system": None,
            "criticality": "high",
        },
        {
            "id": "asset-mgmt-030",
            "hostname": "MGMT-030",
            "asset_type": "workstation",
            "owner_user_id": "usr-admin-030",
            "operating_system": "Windows 11",
            "criticality": "critical",
        },
        {
            "id": "asset-lt-241",
            "hostname": "LT-241",
            "asset_type": "workstation",
            "owner_user_id": "usr-sales-241",
            "operating_system": "Windows 11",
            "criticality": "medium",
        },
        {
            "id": "asset-ws-088",
            "hostname": "WS-088",
            "asset_type": "workstation",
            "owner_user_id": "usr-media-088",
            "operating_system": "Windows 11",
            "criticality": "medium",
        },
        {
            "id": "asset-ws-455",
            "hostname": "WS-455",
            "asset_type": "workstation",
            "owner_user_id": "usr-eng-455",
            "operating_system": "Windows 11",
            "criticality": "high",
        },
        {
            "id": "asset-backup-01",
            "hostname": "BACKUP-01",
            "asset_type": "server",
            "owner_user_id": "svc-backup-020",
            "operating_system": "Linux",
            "criticality": "critical",
        },
    ]

    # Routine business activity is deterministic and source-shaped. It provides enough
    # overlap for useful filtering without producing arbitrary unrelated noise.
    identities = [
        ("usr-fin-610", "asset-ws-610", "198.51.100.61", "WS-610"),
        ("usr-admin-030", "asset-mgmt-030", "198.51.100.30", "MGMT-030"),
        ("usr-sales-241", "asset-lt-241", "198.51.100.41", "LT-241"),
        ("usr-media-088", "asset-ws-088", "198.51.100.88", "WS-088"),
        ("usr-eng-455", "asset-ws-455", "198.51.100.55", "WS-455"),
    ]
    domains = [
        ("portal.corp.example", "192.0.2.20", "business"),
        ("collaboration.corp.example", "192.0.2.24", "collaboration"),
        ("updates.vendor.example", "203.0.113.24", "software-updates"),
        ("knowledge.corp.example", "192.0.2.26", "business"),
        ("calendar.corp.example", "192.0.2.28", "collaboration"),
    ]
    noise_start = moment("07:28:00")
    for index in range(158):
        timestamp = noise_start + timedelta(seconds=88 * index)
        user_id, asset_id, source_ip, hostname = identities[index % len(identities)]
        domain, destination_ip, category = domains[(index * 3) % len(domains)]
        key = f"routine-{index:03d}"
        pattern = index % 10
        if pattern == 0:
            session = f"interactive-{index // 10:03d}"
            add(
                key,
                timestamp,
                {
                    "TimeCreated": iso(timestamp),
                    "Provider": "Microsoft-Windows-Security-Auditing",
                    "EventID": 4624,
                    "Computer": hostname,
                    "TargetUserName": user_id,
                    "IpAddress": source_ip,
                    "LogonType": 2,
                    "LogonId": session,
                },
                source="windows_security",
                event_type="authentication_success",
                severity="informational",
                summary="Interactive workstation sign-in matched the user baseline",
                user_id=user_id,
                asset_id=asset_id,
                source_ip=source_ip,
                session_id=session,
                outcome="success",
                attributes={"logon_type": 2, "baseline_match": True},
            )
        elif pattern == 1:
            add(
                key,
                timestamp,
                {
                    "ts": iso(timestamp),
                    "query": domain,
                    "qtype_name": "A",
                    "answers": [destination_ip],
                    "client": source_ip,
                    "rcode_name": "NOERROR",
                },
                source="dns",
                event_type="dns_query",
                severity="informational",
                summary="Endpoint resolved a normal business service",
                user_id=user_id,
                asset_id=asset_id,
                source_ip=source_ip,
                destination_ip=destination_ip,
                domain=domain,
                outcome="resolved",
                attributes={
                    "record_type": "A",
                    "category": category,
                    "baseline_match": True,
                },
            )
        elif pattern == 2:
            path = ["/home", "/api/calendar", "/document/view", "/health"][index % 4]
            add(
                key,
                timestamp,
                f"{iso(timestamp)} uid={user_id} src={source_ip} dst={destination_ip} method=GET host={domain} uri={path} status=200 bytes_out={380 + index} category={category}",
                source="proxy",
                event_type="http_request",
                severity="informational",
                summary="Browser request to a categorized enterprise service completed",
                user_id=user_id,
                asset_id=asset_id,
                source_ip=source_ip,
                destination_ip=destination_ip,
                domain=domain,
                process_name="browser.exe",
                bytes_out=380 + index,
                outcome="allowed",
                attributes={
                    "method": "GET",
                    "path": path,
                    "status": 200,
                    "category": category,
                },
            )
        elif pattern == 3:
            file_name = ["Forecast.xlsx", "Notes.docx", "Agenda.docx", "Status.xlsx"][
                index % 4
            ]
            add(
                key,
                timestamp,
                {
                    "event_time": iso(timestamp),
                    "sensor": "EndpointFileMonitor",
                    "host": hostname,
                    "user": user_id,
                    "action": "open",
                    "path": f"C:\\Users\\Shared\\Work\\{file_name}",
                    "classification": "internal",
                },
                source="endpoint_file",
                event_type="file_opened",
                severity="informational",
                summary="User opened an internal work document",
                user_id=user_id,
                asset_id=asset_id,
                file_name=file_name,
                outcome="opened",
                attributes={
                    "directory_category": "work_documents",
                    "classification": "internal",
                },
            )
        elif pattern == 4:
            process = "wordprocessor.exe" if index % 4 else "spreadsheet.exe"
            pid = str(4000 + index)
            add(
                key,
                timestamp,
                {
                    "UtcTime": iso(timestamp),
                    "EventID": 1,
                    "Computer": hostname,
                    "User": user_id,
                    "Image": f"C:\\Program Files\\Office\\{process}",
                    "ParentImage": "C:\\Windows\\explorer.exe",
                    "CommandLine": f"{process} [local business document]",
                    "ProcessId": pid,
                    "ParentProcessId": 1280,
                },
                source="sysmon",
                event_type="process_created",
                severity="informational",
                summary="Signed Office application started from the desktop shell",
                user_id=user_id,
                asset_id=asset_id,
                process_name=process,
                parent_process_name="explorer.exe",
                process_id=pid,
                parent_process_id="1280",
                outcome="started",
                attributes={"signed": True, "baseline_match": True},
            )
        elif pattern == 5:
            add(
                key,
                timestamp,
                {
                    "UtcTime": iso(timestamp),
                    "EventID": 3,
                    "Computer": hostname,
                    "Image": "C:\\Program Files\\Browser\\browser.exe",
                    "SourceIp": source_ip,
                    "DestinationIp": destination_ip,
                    "DestinationPort": 443,
                    "Protocol": "tcp",
                    "Initiated": True,
                },
                source="endpoint_network",
                event_type="network_connection",
                severity="informational",
                summary="Browser opened a TLS connection to a known service",
                user_id=user_id,
                asset_id=asset_id,
                source_ip=source_ip,
                destination_ip=destination_ip,
                domain=domain,
                process_name="browser.exe",
                outcome="connected",
                attributes={
                    "destination_port": 443,
                    "protocol": "tcp",
                    "category": category,
                },
            )
        elif pattern == 6:
            uid = f"C{index:06d}"
            add(
                key,
                timestamp,
                {
                    "ts": iso(timestamp),
                    "uid": uid,
                    "id.orig_h": source_ip,
                    "id.orig_p": 51000 + index,
                    "id.resp_h": destination_ip,
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "service": "ssl",
                    "duration": 1.2,
                    "orig_bytes": 520 + index,
                    "resp_bytes": 4800 + index * 4,
                    "conn_state": "SF",
                },
                source="zeek",
                event_type="network_session",
                severity="informational",
                summary="TLS session completed with an established business destination",
                user_id=user_id,
                asset_id=asset_id,
                source_ip=source_ip,
                destination_ip=destination_ip,
                domain=domain,
                session_id=uid,
                bytes_out=520 + index,
                outcome="completed",
                attributes={
                    "destination_port": 443,
                    "service": "ssl",
                    "category": category,
                },
            )
        elif pattern == 7:
            session = f"mfa-{index:03d}"
            add(
                key,
                timestamp,
                {
                    "createdDateTime": iso(timestamp),
                    "userId": user_id,
                    "authenticationMethod": "managed_application",
                    "result": "success",
                    "correlationId": session,
                    "deviceCompliant": True,
                },
                source="mfa",
                event_type="mfa_challenge",
                severity="informational",
                summary="MFA challenge succeeded from a compliant managed device",
                user_id=user_id,
                asset_id="asset-idp-01",
                source_ip=source_ip,
                session_id=session,
                outcome="success",
                attributes={"method": "managed_application", "device_compliant": True},
            )
        elif pattern == 8:
            session = f"backup-{index // 10:03d}"
            add(
                key,
                timestamp,
                {
                    "TimeCreated": iso(timestamp),
                    "Provider": "Microsoft-Windows-Security-Auditing",
                    "EventID": 4624,
                    "Computer": "FILES-02",
                    "TargetUserName": "svc-backup-020",
                    "IpAddress": "198.51.100.120",
                    "LogonType": 5,
                    "LogonId": session,
                },
                source="windows_security",
                event_type="service_authentication",
                severity="informational",
                summary="Backup service authenticated from its assigned server",
                user_id="svc-backup-020",
                asset_id="asset-files-02",
                source_ip="198.51.100.120",
                session_id=session,
                outcome="success",
                attributes={
                    "logon_type": 5,
                    "source_host": "BACKUP-01",
                    "baseline_match": True,
                },
            )
        else:
            message_id = f"routine-{index:04d}@mail.corp.example"
            add(
                key,
                timestamp,
                {
                    "timestamp": iso(timestamp),
                    "message_id": message_id,
                    "sender": "notifications@corp.example",
                    "recipient": f"{user_id}@corp.example",
                    "subject": "Daily workflow notification",
                    "spf": "pass",
                    "dkim": "pass",
                    "dmarc": "pass",
                    "direction": "inbound",
                },
                source="email",
                event_type="email_received",
                severity="informational",
                summary="Authenticated internal workflow message was delivered",
                user_id=user_id,
                asset_id="asset-mail-01",
                session_id=message_id,
                outcome="delivered",
                attributes={
                    "spf": "pass",
                    "dkim": "pass",
                    "dmarc": "pass",
                    "sender_scope": "internal",
                },
            )

    # Incident chain: all commands and content are intentionally non-executable summaries.
    add(
        "incident-email",
        moment("08:36:12.114"),
        {
            "timestamp": iso(moment("08:36:12.114")),
            "message_id": "case-8841@partner-notice.example",
            "envelope_from": "review@partner-notice.example",
            "header_from": "billing@northbridge-vendor.example",
            "reply_to": "review@document-review.example",
            "recipient": "usr-fin-610@corp.example",
            "subject": "Updated planning assumptions for review",
            "url_domains": ["document-review.example"],
            "spf": "pass",
            "dkim": "none",
            "dmarc": "fail",
            "direction": "inbound",
        },
        source="email",
        event_type="email_received",
        severity="medium",
        summary="External planning message failed DMARC alignment and used a separate reply domain",
        user_id="usr-fin-610",
        asset_id="asset-mail-01",
        domain="document-review.example",
        session_id="mail-case-8841",
        outcome="delivered",
        mitre=["T1566.002"],
        attributes={
            "spf": "pass",
            "dkim": "none",
            "dmarc": "fail",
            "reply_domain_mismatch": True,
            "attachment_count": 0,
            "sender_first_seen_days": 0,
        },
        related=("incident-link",),
    )
    add(
        "incident-link",
        moment("08:43:51.006"),
        {
            "timestamp": iso(moment("08:43:51.006")),
            "provider": "MailClientTelemetry",
            "user": "usr-fin-610",
            "host": "WS-610",
            "message_id": "case-8841@partner-notice.example",
            "action": "link_opened",
            "target": "https://document-review.example/case/610",
        },
        source="email",
        event_type="link_opened",
        severity="medium",
        summary="User opened the external review link from the delivered message",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        domain="document-review.example",
        process_name="mailclient.exe",
        session_id="mail-case-8841",
        outcome="opened",
        mitre=["T1204.001"],
        attributes={
            "source": "mail_message",
            "message_id": "case-8841@partner-notice.example",
            "domain_first_seen_days": 1,
        },
        related=("incident-email", "incident-dns-review"),
    )
    add(
        "incident-dns-review",
        moment("08:43:51.118"),
        {
            "ts": iso(moment("08:43:51.118")),
            "query": "document-review.example",
            "qtype_name": "A",
            "answers": ["203.0.113.84"],
            "client": "198.51.100.61",
            "rcode_name": "NOERROR",
        },
        source="dns",
        event_type="dns_query",
        severity="low",
        summary="WS-610 resolved a newly observed document service",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        source_ip="198.51.100.61",
        destination_ip="203.0.113.84",
        domain="document-review.example",
        outcome="resolved",
        attributes={
            "record_type": "A",
            "first_seen_days": 1,
            "category": "uncategorized",
        },
        related=("incident-link", "incident-http-review"),
    )
    add(
        "incident-http-review",
        moment("08:43:52.407"),
        f"{iso(moment('08:43:52.407'))} uid=usr-fin-610 src=198.51.100.61 dst=203.0.113.84 method=GET host=document-review.example uri=/case/610 status=200 bytes_in=18644 category=uncategorized referrer=mailclient",
        source="proxy",
        event_type="http_request",
        severity="medium",
        summary="Browser retrieved a review page from the newly observed domain",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        source_ip="198.51.100.61",
        destination_ip="203.0.113.84",
        domain="document-review.example",
        process_name="browser.exe",
        session_id="web-case-610",
        bytes_out=614,
        outcome="allowed",
        attributes={
            "method": "GET",
            "path": "/case/610",
            "status": 200,
            "category": "uncategorized",
            "referrer": "mailclient",
        },
        related=("incident-dns-review", "incident-download"),
    )
    add(
        "incident-download",
        moment("08:44:09.552"),
        {
            "event_time": iso(moment("08:44:09.552")),
            "sensor": "EndpointFileMonitor",
            "host": "WS-610",
            "user": "usr-fin-610",
            "action": "create",
            "path": "C:\\Users\\Finance\\Downloads\\Planning_Review.docm",
            "origin_url": "https://document-review.example/case/610/file",
            "zone_identifier": 3,
            "sha256": "SYNTHETIC-NON-EXECUTABLE-DOCUMENT",
        },
        source="endpoint_file",
        event_type="file_created",
        severity="medium",
        summary="Macro-enabled planning document was saved from the review site",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        domain="document-review.example",
        process_name="browser.exe",
        process_id="7310",
        file_name="Planning_Review.docm",
        outcome="created",
        mitre=["T1204.002"],
        attributes={
            "directory_category": "downloads",
            "zone_identifier": 3,
            "content_safe": True,
        },
        related=("incident-http-review", "incident-office-open"),
    )
    add(
        "incident-office-open",
        moment("08:45:06.902"),
        {
            "TimeCreated": iso(moment("08:45:06.902")),
            "Provider": "OfficeTelemetry",
            "EventID": 3001,
            "Computer": "WS-610",
            "User": "usr-fin-610",
            "Document": "Planning_Review.docm",
            "Action": "protected_view_exit",
            "Zone": "Internet",
            "ProcessId": 7448,
        },
        source="office",
        event_type="document_activity",
        severity="medium",
        summary="Internet-zone document left Protected View after user interaction",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        process_name="wordprocessor.exe",
        process_id="7448",
        file_name="Planning_Review.docm",
        outcome="content_enabled",
        mitre=["T1204.002"],
        attributes={
            "zone": "Internet",
            "protected_view": False,
            "active_content": "enabled",
        },
        related=("incident-download", "incident-cmd"),
    )
    add(
        "incident-cmd",
        moment("08:45:17.140"),
        {
            "UtcTime": iso(moment("08:45:17.140")),
            "EventID": 1,
            "Computer": "WS-610",
            "User": "usr-fin-610",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "ParentImage": "C:\\Program Files\\Office\\wordprocessor.exe",
            "CommandLine": "cmd.exe /c [SANITIZED DOCUMENT ACTION]",
            "ProcessId": 7481,
            "ParentProcessId": 7448,
        },
        source="sysmon",
        event_type="process_created",
        severity="high",
        summary="Office application created a command interpreter",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        process_name="cmd.exe",
        parent_process_name="wordprocessor.exe",
        process_id="7481",
        parent_process_id="7448",
        outcome="started",
        mitre=["T1204.002", "T1059.003"],
        attributes={
            "command_line": "cmd.exe /c [SANITIZED DOCUMENT ACTION]",
            "signed": True,
        },
        related=("incident-office-open", "incident-powershell"),
    )
    add(
        "incident-powershell",
        moment("08:45:17.331"),
        {
            "UtcTime": iso(moment("08:45:17.331")),
            "EventID": 1,
            "Computer": "WS-610",
            "User": "usr-fin-610",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "powershell.exe -NoProfile -EncodedCommand [SANITIZED]",
            "ProcessId": 7490,
            "ParentProcessId": 7481,
            "Hashes": "SHA256=SYSTEM-BINARY",
        },
        source="sysmon",
        event_type="process_created",
        severity="high",
        summary="Command interpreter started PowerShell with encoded arguments",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        process_name="powershell.exe",
        parent_process_name="cmd.exe",
        process_id="7490",
        parent_process_id="7481",
        outcome="started",
        mitre=["T1059.001"],
        attributes={
            "command_line": "powershell.exe -NoProfile -EncodedCommand [SANITIZED]",
            "execution_style": "encoded",
            "script_signed": False,
            "content_safe": True,
        },
        related=("incident-cmd", "incident-script-block"),
    )
    add(
        "incident-script-block",
        moment("08:45:17.604"),
        {
            "TimeCreated": iso(moment("08:45:17.604")),
            "Provider": "Microsoft-Windows-PowerShell",
            "EventID": 4104,
            "Computer": "WS-610",
            "User": "usr-fin-610",
            "ScriptBlockId": "sb-610-8841",
            "MessageNumber": 1,
            "MessageTotal": 1,
            "ScriptBlockText": "[SANITIZED: host inventory, network inventory, and transfer preparation; no executable content retained]",
        },
        source="powershell",
        event_type="script_block",
        severity="high",
        summary="PowerShell recorded an obfuscated host and network inventory routine",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        process_name="powershell.exe",
        process_id="7490",
        session_id="sb-610-8841",
        outcome="executed",
        mitre=["T1059.001", "T1082", "T1016"],
        attributes={
            "script_block_id": "sb-610-8841",
            "obfuscation": True,
            "discovery_terms": 6,
            "script_signed": False,
            "content": "[SANITIZED INVENTORY ROUTINE]",
        },
        related=("incident-powershell", "incident-systeminfo", "incident-ipconfig"),
    )
    add(
        "incident-systeminfo",
        moment("08:45:18.048"),
        {
            "UtcTime": iso(moment("08:45:18.048")),
            "EventID": 1,
            "Computer": "WS-610",
            "User": "usr-fin-610",
            "Image": "C:\\Windows\\System32\\systeminfo.exe",
            "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "systeminfo.exe [SANITIZED OUTPUT REDIRECTION]",
            "ProcessId": 7501,
            "ParentProcessId": 7490,
        },
        source="sysmon",
        event_type="process_created",
        severity="medium",
        summary="PowerShell started the system information utility",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        process_name="systeminfo.exe",
        parent_process_name="powershell.exe",
        process_id="7501",
        parent_process_id="7490",
        outcome="started",
        mitre=["T1082"],
        attributes={
            "discovery_family": "host",
            "command_line": "[SANITIZED SYSTEM INVENTORY]",
        },
        related=("incident-script-block", "incident-ipconfig"),
    )
    add(
        "incident-ipconfig",
        moment("08:45:18.920"),
        {
            "UtcTime": iso(moment("08:45:18.920")),
            "EventID": 1,
            "Computer": "WS-610",
            "User": "usr-fin-610",
            "Image": "C:\\Windows\\System32\\ipconfig.exe",
            "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "ipconfig.exe [SANITIZED ARGUMENTS]",
            "ProcessId": 7508,
            "ParentProcessId": 7490,
        },
        source="sysmon",
        event_type="process_created",
        severity="medium",
        summary="PowerShell started the network configuration utility",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        process_name="ipconfig.exe",
        parent_process_name="powershell.exe",
        process_id="7508",
        parent_process_id="7490",
        outcome="started",
        mitre=["T1016"],
        attributes={
            "discovery_family": "network",
            "command_line": "[SANITIZED NETWORK INVENTORY]",
        },
        related=(
            "incident-script-block",
            "incident-systeminfo",
            "incident-dns-control",
        ),
    )
    add(
        "incident-dns-control",
        moment("08:45:24.781"),
        {
            "ts": iso(moment("08:45:24.781")),
            "query": "content-gateway.example",
            "qtype_name": "A",
            "answers": ["203.0.113.146"],
            "client": "198.51.100.61",
            "rcode_name": "NOERROR",
        },
        source="dns",
        event_type="dns_query",
        severity="medium",
        summary="WS-610 resolved an uncategorized content gateway",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        source_ip="198.51.100.61",
        destination_ip="203.0.113.146",
        domain="content-gateway.example",
        process_name="powershell.exe",
        process_id="7490",
        outcome="resolved",
        attributes={
            "record_type": "A",
            "first_seen_days": 0,
            "category": "uncategorized",
        },
        related=("incident-ipconfig", "incident-network-control"),
    )
    add(
        "incident-network-control",
        moment("08:45:25.203"),
        {
            "UtcTime": iso(moment("08:45:25.203")),
            "EventID": 3,
            "Computer": "WS-610",
            "User": "usr-fin-610",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "SourceIp": "198.51.100.61",
            "DestinationIp": "203.0.113.146",
            "DestinationPort": 443,
            "Protocol": "tcp",
            "Initiated": True,
        },
        source="endpoint_network",
        event_type="network_connection",
        severity="high",
        summary="PowerShell connected to the uncategorized content gateway",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        source_ip="198.51.100.61",
        destination_ip="203.0.113.146",
        domain="content-gateway.example",
        process_name="powershell.exe",
        process_id="7490",
        outcome="connected",
        mitre=["T1105"],
        attributes={
            "destination_port": 443,
            "protocol": "tcp",
            "initiated": True,
            "category": "uncategorized",
        },
        related=("incident-dns-control", "incident-control-http"),
    )
    add(
        "incident-control-http",
        moment("08:45:25.650"),
        f"{iso(moment('08:45:25.650'))} uid=usr-fin-610 src=198.51.100.61 dst=203.0.113.146 method=GET host=content-gateway.example uri=/api/policy status=200 bytes_in=24610 bytes_out=496 user_agent=PowerShell/5.1 category=uncategorized",
        source="proxy",
        event_type="http_request",
        severity="high",
        summary="PowerShell retrieved a small response from the content gateway",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        source_ip="198.51.100.61",
        destination_ip="203.0.113.146",
        domain="content-gateway.example",
        process_name="powershell.exe",
        process_id="7490",
        bytes_out=496,
        outcome="allowed",
        mitre=["T1105"],
        attributes={
            "method": "GET",
            "path": "/api/policy",
            "status": 200,
            "bytes_in": 24610,
            "user_agent": "PowerShell/5.1",
            "category": "uncategorized",
        },
        related=("incident-network-control", "incident-share-auth"),
    )
    add(
        "incident-share-auth",
        moment("09:09:40.041"),
        {
            "TimeCreated": iso(moment("09:09:40.041")),
            "Provider": "Microsoft-Windows-Security-Auditing",
            "EventID": 4624,
            "Computer": "FILES-02",
            "TargetUserName": "usr-fin-610",
            "IpAddress": "198.51.100.61",
            "WorkstationName": "WS-610",
            "LogonType": 3,
            "AuthenticationPackageName": "Kerberos",
            "LogonId": "share-610-8841",
        },
        source="windows_security",
        event_type="authentication_success",
        severity="medium",
        summary="Finance identity opened a network logon from a source not previously seen for this share",
        user_id="usr-fin-610",
        asset_id="asset-files-02",
        source_ip="198.51.100.61",
        session_id="share-610-8841",
        outcome="success",
        mitre=["T1078"],
        attributes={
            "logon_type": 3,
            "source_host": "WS-610",
            "new_source_for_user": True,
            "authentication_package": "Kerberos",
        },
        related=(
            "incident-control-http",
            "incident-file-read-one",
            "incident-file-read-two",
        ),
    )
    for key, stamp, file_name, size in [
        ("incident-file-read-one", "09:10:12.184", "Board_Forecast_Q3.xlsx", 6814420),
        ("incident-file-read-two", "09:10:27.830", "Acquisition_Model.xlsx", 19442108),
    ]:
        add(
            key,
            moment(stamp),
            {
                "TimeCreated": iso(moment(stamp)),
                "Provider": "Microsoft-Windows-Security-Auditing",
                "EventID": 5145,
                "Computer": "FILES-02",
                "SubjectUserName": "usr-fin-610",
                "SourceAddress": "198.51.100.61",
                "ShareName": "Finance-Restricted",
                "RelativeTargetName": file_name,
                "AccessMask": "0x1",
                "LogonId": "share-610-8841",
            },
            source="windows_security",
            event_type="file_accessed",
            severity="medium",
            summary="Finance identity read a restricted planning file through the new network logon",
            user_id="usr-fin-610",
            asset_id="asset-files-02",
            source_ip="198.51.100.61",
            session_id="share-610-8841",
            file_name=file_name,
            outcome="read",
            mitre=["T1039"],
            attributes={
                "share": "Finance-Restricted",
                "size": size,
                "access_mask": "0x1",
                "source_host": "WS-610",
            },
            related=("incident-share-auth", "incident-archive-process"),
        )
    add(
        "incident-archive-process",
        moment("09:14:39.004"),
        {
            "UtcTime": iso(moment("09:14:39.004")),
            "EventID": 1,
            "Computer": "WS-610",
            "User": "usr-fin-610",
            "Image": "C:\\Windows\\System32\\tar.exe",
            "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "tar.exe [SANITIZED ARCHIVE ARGUMENTS]",
            "ProcessId": 8124,
            "ParentProcessId": 7490,
        },
        source="sysmon",
        event_type="process_created",
        severity="medium",
        summary="PowerShell started an archive utility against recently accessed material",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        process_name="tar.exe",
        parent_process_name="powershell.exe",
        process_id="8124",
        parent_process_id="7490",
        outcome="started",
        mitre=["T1560.001"],
        attributes={
            "archive_operation": True,
            "command_line": "[SANITIZED ARCHIVE ARGUMENTS]",
            "content_safe": True,
        },
        related=(
            "incident-file-read-one",
            "incident-file-read-two",
            "incident-archive-file",
        ),
    )
    add(
        "incident-archive-file",
        moment("09:14:44.662"),
        {
            "event_time": iso(moment("09:14:44.662")),
            "sensor": "EndpointFileMonitor",
            "host": "WS-610",
            "user": "usr-fin-610",
            "action": "create",
            "path": "C:\\Users\\Finance\\AppData\\Local\\BrowserCache\\review-cache.zip",
            "size": 61824412,
            "process_id": 8124,
        },
        source="endpoint_file",
        event_type="file_created",
        severity="high",
        summary="Archive was written beneath the browser cache path",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        process_name="tar.exe",
        process_id="8124",
        file_name="review-cache.zip",
        outcome="created",
        mitre=["T1560.001"],
        attributes={
            "archive": True,
            "directory_category": "browser_cache",
            "size": 61824412,
            "source_file_count": 2,
        },
        related=("incident-archive-process", "incident-upload-dns", "incident-upload"),
    )
    add(
        "incident-upload-dns",
        moment("09:15:01.301"),
        {
            "ts": iso(moment("09:15:01.301")),
            "query": "files-gateway.example",
            "qtype_name": "A",
            "answers": ["203.0.113.188"],
            "client": "198.51.100.61",
            "rcode_name": "NOERROR",
        },
        source="dns",
        event_type="dns_query",
        severity="medium",
        summary="WS-610 resolved an uncategorized file gateway",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        source_ip="198.51.100.61",
        destination_ip="203.0.113.188",
        domain="files-gateway.example",
        outcome="resolved",
        attributes={
            "record_type": "A",
            "first_seen_days": 0,
            "category": "uncategorized",
        },
        related=("incident-archive-file", "incident-upload"),
    )
    add(
        "incident-upload",
        moment("09:15:05.244"),
        f"{iso(moment('09:15:05.244'))} uid=usr-fin-610 src=198.51.100.61 dst=203.0.113.188 method=PUT host=files-gateway.example uri=/storage/session/8841 status=201 bytes_out=61824412 file=review-cache.zip category=uncategorized tenant=unknown",
        source="proxy",
        event_type="file_upload",
        severity="high",
        summary="Archive upload to an uncategorized external storage tenant completed",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        source_ip="198.51.100.61",
        destination_ip="203.0.113.188",
        domain="files-gateway.example",
        process_name="browser.exe",
        file_name="review-cache.zip",
        bytes_out=61824412,
        outcome="allowed",
        mitre=["T1567.002"],
        attributes={
            "method": "PUT",
            "path": "/storage/session/8841",
            "status": 201,
            "category": "uncategorized",
            "tenant": "unknown",
            "approved_service": False,
            "tls": True,
        },
        related=(
            "incident-archive-file",
            "incident-upload-dns",
            "incident-upload-zeek",
        ),
    )
    add(
        "incident-upload-zeek",
        moment("09:15:08.930"),
        {
            "ts": iso(moment("09:15:08.930")),
            "uid": "CX6108841",
            "id.orig_h": "198.51.100.61",
            "id.orig_p": 52482,
            "id.resp_h": "203.0.113.188",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 3.686,
            "orig_bytes": 61829108,
            "resp_bytes": 2841,
            "conn_state": "SF",
        },
        source="zeek",
        event_type="network_session",
        severity="high",
        summary="Network sensor observed a matching high-egress TLS session",
        user_id="usr-fin-610",
        asset_id="asset-ws-610",
        source_ip="198.51.100.61",
        destination_ip="203.0.113.188",
        domain="files-gateway.example",
        session_id="CX6108841",
        bytes_out=61829108,
        outcome="completed",
        mitre=["T1567.002"],
        attributes={
            "destination_port": 443,
            "service": "ssl",
            "duration_seconds": 3.686,
            "category": "uncategorized",
        },
        related=("incident-upload",),
    )

    # Structured decoys are linked to the context that resolves them.
    add(
        "decoy-admin-change",
        moment("08:44:30.000"),
        {
            "TimeCreated": iso(moment("08:44:30")),
            "Provider": "ChangeControl",
            "Ticket": "chg-4310",
            "Asset": "MGMT-030",
            "Owner": "usr-admin-030",
            "Description": "Signed endpoint inventory validation",
            "Status": "approved",
        },
        source="change_control",
        event_type="change_window",
        severity="informational",
        summary="Approved endpoint inventory change window began",
        user_id="usr-admin-030",
        asset_id="asset-mgmt-030",
        session_id="chg-4310",
        outcome="approved",
        attributes={
            "ticket": "chg-4310",
            "approved": True,
            "purpose": "endpoint_inventory",
        },
        related=("decoy-admin-powershell",),
    )
    add(
        "decoy-admin-powershell",
        moment("08:46:00.112"),
        {
            "UtcTime": iso(moment("08:46:00.112")),
            "EventID": 1,
            "Computer": "MGMT-030",
            "User": "usr-admin-030",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ParentImage": "C:\\Windows\\System32\\taskhostw.exe",
            "CommandLine": "powershell.exe -File [MANAGEMENT SHARE]\\inventory-signed.ps1 -Ticket chg-4310",
            "ProcessId": 5190,
            "ParentProcessId": 1400,
        },
        source="sysmon",
        event_type="process_created",
        severity="medium",
        summary="PowerShell started a signed inventory script on the management workstation",
        user_id="usr-admin-030",
        asset_id="asset-mgmt-030",
        process_name="powershell.exe",
        parent_process_name="taskhostw.exe",
        process_id="5190",
        parent_process_id="1400",
        session_id="chg-4310",
        outcome="started",
        mitre=["T1059.001", "T1082"],
        attributes={
            "command_line": "powershell.exe -File [MANAGEMENT SHARE]\\inventory-signed.ps1 -Ticket chg-4310",
            "execution_style": "script_file",
            "script_signed": True,
            "change_ticket": True,
        },
        related=("decoy-admin-change", "decoy-admin-script", "decoy-admin-http"),
    )
    add(
        "decoy-admin-script",
        moment("08:46:00.290"),
        {
            "TimeCreated": iso(moment("08:46:00.290")),
            "Provider": "Microsoft-Windows-PowerShell",
            "EventID": 4104,
            "Computer": "MGMT-030",
            "User": "usr-admin-030",
            "ScriptBlockId": "sb-chg-4310",
            "ScriptBlockText": "[SANITIZED: signed endpoint inventory routine]",
        },
        source="powershell",
        event_type="script_block",
        severity="informational",
        summary="Signed inventory script recorded standard host attributes",
        user_id="usr-admin-030",
        asset_id="asset-mgmt-030",
        process_name="powershell.exe",
        process_id="5190",
        session_id="chg-4310",
        outcome="executed",
        mitre=["T1082"],
        attributes={
            "script_block_id": "sb-chg-4310",
            "obfuscation": False,
            "script_signed": True,
            "change_ticket": True,
        },
        related=("decoy-admin-powershell", "decoy-admin-http"),
    )
    add(
        "decoy-admin-http",
        moment("08:46:03.880"),
        f"{iso(moment('08:46:03.880'))} uid=usr-admin-030 src=198.51.100.30 dst=192.0.2.30 method=POST host=inventory.corp.example uri=/api/results status=204 bytes_out=7821 ticket=chg-4310 category=business",
        source="proxy",
        event_type="http_request",
        severity="informational",
        summary="Signed inventory script sent results to the internal collector",
        user_id="usr-admin-030",
        asset_id="asset-mgmt-030",
        source_ip="198.51.100.30",
        destination_ip="192.0.2.30",
        domain="inventory.corp.example",
        process_name="powershell.exe",
        process_id="5190",
        session_id="chg-4310",
        bytes_out=7821,
        outcome="allowed",
        attributes={
            "method": "POST",
            "status": 204,
            "category": "business",
            "internal_service": True,
            "ticket": "chg-4310",
        },
        related=("decoy-admin-powershell", "decoy-admin-script"),
    )
    add(
        "decoy-travel-approval",
        moment("08:57:40.000"),
        {
            "timestamp": iso(moment("08:57:40")),
            "provider": "TravelExceptionRegistry",
            "user": "usr-sales-241",
            "country": "NL",
            "valid_from": f"{DAY}T08:30:00Z",
            "valid_to": f"{DAY}T18:00:00Z",
            "status": "approved",
            "device": "LT-241",
        },
        source="identity_context",
        event_type="travel_exception",
        severity="informational",
        summary="Approved same-day travel exception covered LT-241",
        user_id="usr-sales-241",
        asset_id="asset-idp-01",
        session_id="travel-241",
        outcome="approved",
        attributes={"country": "NL", "device": "LT-241", "approved": True},
        related=("decoy-vpn", "decoy-vpn-mfa"),
    )
    add(
        "decoy-vpn",
        moment("09:01:11.319"),
        {
            "timestamp": iso(moment("09:01:11.319")),
            "event": "vpn_login",
            "user": "usr-sales-241",
            "source_ip": "203.0.113.72",
            "country": "NL",
            "asn": 64542,
            "asn_category": "hosting",
            "device": "LT-241",
            "result": "success",
            "session": "vpn-241-nl",
        },
        source="vpn",
        event_type="vpn_login",
        severity="medium",
        summary="VPN login succeeded from a hosting ASN in an unusual country",
        user_id="usr-sales-241",
        asset_id="asset-idp-01",
        source_ip="203.0.113.72",
        session_id="vpn-241-nl",
        outcome="success",
        mitre=["T1078"],
        attributes={
            "country": "NL",
            "asn": 64542,
            "asn_category": "hosting",
            "managed_device": True,
            "device": "LT-241",
        },
        related=("decoy-travel-approval", "decoy-vpn-mfa"),
    )
    add(
        "decoy-vpn-mfa",
        moment("09:01:15.552"),
        {
            "createdDateTime": iso(moment("09:01:15.552")),
            "userId": "usr-sales-241",
            "authenticationMethod": "managed_application",
            "result": "success",
            "correlationId": "vpn-241-nl",
            "device": "LT-241",
            "deviceCompliant": True,
        },
        source="mfa",
        event_type="mfa_challenge",
        severity="informational",
        summary="MFA succeeded from the registered compliant travel device",
        user_id="usr-sales-241",
        asset_id="asset-idp-01",
        source_ip="203.0.113.72",
        session_id="vpn-241-nl",
        outcome="success",
        attributes={
            "method": "managed_application",
            "device": "LT-241",
            "device_compliant": True,
        },
        related=("decoy-travel-approval", "decoy-vpn"),
    )
    add(
        "decoy-network-change",
        moment("08:50:00.000"),
        {
            "TimeCreated": iso(moment("08:50:00")),
            "Provider": "ChangeControl",
            "Ticket": "chg-4322",
            "Asset": "WS-455",
            "Owner": "usr-eng-455",
            "Description": "External platform certificate validation on TCP 8443",
            "Status": "approved",
        },
        source="change_control",
        event_type="change_window",
        severity="informational",
        summary="Approved platform certificate validation window began",
        user_id="usr-eng-455",
        asset_id="asset-ws-455",
        session_id="chg-4322",
        outcome="approved",
        attributes={
            "ticket": "chg-4322",
            "approved": True,
            "destination": "validation.vendor.example",
            "port": 8443,
        },
        related=("decoy-network-8443",),
    )
    add(
        "decoy-network-8443",
        moment("08:52:13.407"),
        {
            "UtcTime": iso(moment("08:52:13.407")),
            "EventID": 3,
            "Computer": "WS-455",
            "User": "usr-eng-455",
            "Image": "C:\\Program Files\\PlatformTools\\validator.exe",
            "SourceIp": "198.51.100.55",
            "DestinationIp": "203.0.113.201",
            "DestinationPort": 8443,
            "Protocol": "tcp",
            "Initiated": True,
        },
        source="endpoint_network",
        event_type="network_connection",
        severity="medium",
        summary="Platform validator connected to an external service on TCP 8443",
        user_id="usr-eng-455",
        asset_id="asset-ws-455",
        source_ip="198.51.100.55",
        destination_ip="203.0.113.201",
        domain="validation.vendor.example",
        process_name="validator.exe",
        session_id="chg-4322",
        outcome="connected",
        attributes={
            "destination_port": 8443,
            "protocol": "tcp",
            "signed": True,
            "ticket": "chg-4322",
        },
        related=("decoy-network-change",),
    )
    add(
        "decoy-media-change",
        moment("09:17:20.000"),
        {
            "TimeCreated": iso(moment("09:17:20")),
            "Provider": "ChangeControl",
            "Ticket": "chg-4331",
            "Asset": "WS-088",
            "Owner": "usr-media-088",
            "Description": "Campaign media delivery to corporate tenant",
            "Status": "approved",
            "ExpectedBytes": 986710244,
        },
        source="change_control",
        event_type="transfer_approval",
        severity="informational",
        summary="Approved campaign media transfer was recorded",
        user_id="usr-media-088",
        asset_id="asset-ws-088",
        session_id="chg-4331",
        outcome="approved",
        attributes={
            "ticket": "chg-4331",
            "approved": True,
            "tenant": "corporate-media",
        },
        related=("decoy-media-upload", "decoy-media-zeek"),
    )
    add(
        "decoy-media-upload",
        moment("09:20:02.101"),
        f"{iso(moment('09:20:02.101'))} uid=usr-media-088 src=198.51.100.88 dst=192.0.2.44 method=PUT host=media.corp.example uri=/tenant/corporate-media/campaign status=201 bytes_out=986710244 file=campaign-master.zip category=approved-cloud tenant=corporate-media ticket=chg-4331",
        source="proxy",
        event_type="file_upload",
        severity="medium",
        summary="Large media package upload to the corporate tenant completed",
        user_id="usr-media-088",
        asset_id="asset-ws-088",
        source_ip="198.51.100.88",
        destination_ip="192.0.2.44",
        domain="media.corp.example",
        process_name="media-uploader.exe",
        session_id="chg-4331",
        file_name="campaign-master.zip",
        bytes_out=986710244,
        outcome="allowed",
        mitre=["T1567.002"],
        attributes={
            "method": "PUT",
            "status": 201,
            "category": "approved-cloud",
            "tenant": "corporate-media",
            "approved_service": True,
            "ticket": "chg-4331",
            "tls": True,
        },
        related=("decoy-media-change", "decoy-media-zeek"),
    )
    add(
        "decoy-media-zeek",
        moment("09:20:37.442"),
        {
            "ts": iso(moment("09:20:37.442")),
            "uid": "CMEDIA4331",
            "id.orig_h": "198.51.100.88",
            "id.orig_p": 52512,
            "id.resp_h": "192.0.2.44",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 35.341,
            "orig_bytes": 986722840,
            "resp_bytes": 8114,
            "conn_state": "SF",
        },
        source="zeek",
        event_type="network_session",
        severity="informational",
        summary="Network sensor confirmed the approved media transfer volume",
        user_id="usr-media-088",
        asset_id="asset-ws-088",
        source_ip="198.51.100.88",
        destination_ip="192.0.2.44",
        domain="media.corp.example",
        session_id="chg-4331",
        bytes_out=986722840,
        outcome="completed",
        attributes={
            "destination_port": 443,
            "service": "ssl",
            "duration_seconds": 35.341,
            "approved_service": True,
        },
        related=("decoy-media-change", "decoy-media-upload"),
    )

    events.sort(key=lambda item: item["normalized"]["timestamp"])
    key_to_id = {
        event["_key"]: f"evt-{index:04d}" for index, event in enumerate(events, 1)
    }
    materialized_events = [
        {
            "id": key_to_id[event["_key"]],
            "raw": event["raw"],
            "normalized": event["normalized"],
            "related_event_ids": [key_to_id[key] for key in event["_related"]],
        }
        for event in events
    ]

    def event_ids(*keys: str) -> list[str]:
        return [key_to_id[key] for key in keys]

    detections = [
        {
            "id": "det-advanced-email-alignment",
            "title": localized(
                "Inbound message authentication anomaly",
                "Authentifizierungsanomalie bei eingehender Nachricht",
            ),
            "description": localized(
                "Detects delivered email with failed DMARC alignment and a mismatched reply domain.",
                "Erkennt zugestellte E-Mails mit fehlgeschlagener DMARC-Ausrichtung und abweichender Antwortdomain.",
            ),
            "severity": "medium",
            "mitre": ["T1566.002"],
            "false_positive_context": localized(
                "Forwarding services and third-party billing platforms can break alignment. Validate sender history, reply domain, message content, and subsequent user activity.",
                "Weiterleitungsdienste und Abrechnungsplattformen können die Ausrichtung brechen. Prüfen Sie Absenderhistorie, Antwortdomain, Nachrichteninhalt und nachfolgende Benutzeraktivität.",
            ),
            "match": "all",
            "conditions": [
                {
                    "field": "event_type",
                    "operator": "equals",
                    "value": "email_received",
                },
                {"field": "attributes.dmarc", "operator": "equals", "value": "fail"},
                {
                    "field": "attributes.reply_domain_mismatch",
                    "operator": "equals",
                    "value": True,
                },
            ],
            "sigma": "title: Inbound Message Authentication Anomaly\nid: 58d11f86-7a68-4e60-9a74-610000000001\nstatus: experimental\nlogsource:\n  category: email\ndetection:\n  selection:\n    dmarc: fail\n    reply_domain_mismatch: true\n  condition: selection\nfalsepositives:\n  - Forwarding and third-party mail platforms\nlevel: medium",
            "expected_event_ids": event_ids("incident-email"),
        },
        {
            "id": "det-advanced-mail-link-execution",
            "title": localized(
                "Mail link opened to a newly observed domain",
                "Mail-Link zu neu beobachteter Domain geöffnet",
            ),
            "description": localized(
                "Detects a link opened from mail when the destination domain has little local history.",
                "Erkennt einen aus Mail geöffneten Link, dessen Zieldomain nur eine kurze lokale Historie besitzt.",
            ),
            "severity": "medium",
            "mitre": ["T1204.001"],
            "false_positive_context": localized(
                "New partner portals and event services can be legitimate. Correlate message authentication, sender history, download activity, and endpoint follow-up.",
                "Neue Partnerportale und Veranstaltungsdienste können legitim sein. Korrelieren Sie Nachrichtenauthentifizierung, Absenderhistorie, Downloads und Endpunktaktivität.",
            ),
            "match": "all",
            "conditions": [
                {"field": "source", "operator": "equals", "value": "email"},
                {"field": "event_type", "operator": "equals", "value": "link_opened"},
                {
                    "field": "attributes.domain_first_seen_days",
                    "operator": "equals",
                    "value": 1,
                },
            ],
            "sigma": "title: Mail Link Opened to a Newly Observed Domain\nid: 58d11f86-7a68-4e60-9a74-610000000012\nstatus: experimental\nlogsource:\n  category: email\ndetection:\n  selection:\n    action: link_opened\n    domain_first_seen_days: 1\n  condition: selection\nfalsepositives:\n  - New partner and event services\nlevel: medium",
            "expected_event_ids": event_ids("incident-link"),
        },
        {
            "id": "det-advanced-office-shell",
            "title": localized(
                "Office application spawned command shell",
                "Office-Anwendung startete Kommando-Shell",
            ),
            "description": localized(
                "Detects a command interpreter directly created by the synthetic word processor.",
                "Erkennt einen direkt von der synthetischen Textverarbeitung gestarteten Kommandointerpreter.",
            ),
            "severity": "high",
            "mitre": ["T1204.002", "T1059.003"],
            "false_positive_context": localized(
                "Legacy document automation can create this ancestry, but the document origin and subsequent child processes must support that explanation.",
                "Veraltete Dokumentautomatisierung kann diese Prozessherkunft erzeugen; Dokumentherkunft und Folgeprozesse müssen diese Erklärung jedoch stützen.",
            ),
            "match": "all",
            "conditions": [
                {
                    "field": "event_type",
                    "operator": "equals",
                    "value": "process_created",
                },
                {
                    "field": "parent_process_name",
                    "operator": "equals",
                    "value": "wordprocessor.exe",
                },
                {"field": "process_name", "operator": "equals", "value": "cmd.exe"},
            ],
            "sigma": "title: Office Application Spawned Command Shell\nid: 58d11f86-7a68-4e60-9a74-610000000002\nstatus: stable\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    ParentImage|endswith: '\\\\wordprocessor.exe'\n    Image|endswith: '\\\\cmd.exe'\n  condition: selection\nfalsepositives:\n  - Document workflow automation\nlevel: high",
            "expected_event_ids": event_ids("incident-cmd"),
        },
        {
            "id": "det-advanced-powershell-visibility",
            "title": localized(
                "PowerShell process visibility", "PowerShell-Prozesssichtbarkeit"
            ),
            "description": localized(
                "Broadly records PowerShell starts so ancestry, user role, signing, and change context can be evaluated.",
                "Erfasst PowerShell-Starts breit, damit Prozessherkunft, Benutzerrolle, Signatur und Änderungskontext bewertet werden können.",
            ),
            "severity": "medium",
            "mitre": ["T1059.001"],
            "false_positive_context": localized(
                "PowerShell is expected for signed endpoint administration. A documented ticket, administrative identity, trusted parent, and internal destination reduce risk.",
                "PowerShell wird für signierte Endpunktadministration erwartet. Dokumentiertes Ticket, Administrationsidentität, vertrauenswürdiger Elternprozess und internes Ziel senken das Risiko.",
            ),
            "match": "all",
            "conditions": [
                {
                    "field": "event_type",
                    "operator": "equals",
                    "value": "process_created",
                },
                {
                    "field": "process_name",
                    "operator": "equals",
                    "value": "powershell.exe",
                },
            ],
            "sigma": "title: PowerShell Process Visibility\nid: 58d11f86-7a68-4e60-9a74-610000000003\nstatus: test\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n  condition: selection\nfalsepositives:\n  - Signed administrative automation\nlevel: medium",
            "expected_event_ids": event_ids(
                "incident-powershell", "decoy-admin-powershell"
            ),
        },
        {
            "id": "det-advanced-encoded-powershell",
            "title": localized(
                "Encoded PowerShell launch", "Kodierter PowerShell-Start"
            ),
            "description": localized(
                "Detects PowerShell process telemetry normalized with an encoded execution style.",
                "Erkennt PowerShell-Prozesstelemetrie mit normalisiertem kodiertem Ausführungsstil.",
            ),
            "severity": "high",
            "mitre": ["T1059.001"],
            "false_positive_context": localized(
                "Some management products encode arguments. Confirm signer, parent process, initiating user, script-block content, and follow-on network activity.",
                "Einige Verwaltungsprodukte kodieren Argumente. Prüfen Sie Signatur, Elternprozess, Benutzer, ScriptBlock-Inhalt und nachfolgenden Netzwerkverkehr.",
            ),
            "match": "all",
            "conditions": [
                {
                    "field": "process_name",
                    "operator": "equals",
                    "value": "powershell.exe",
                },
                {
                    "field": "attributes.execution_style",
                    "operator": "equals",
                    "value": "encoded",
                },
            ],
            "sigma": "title: Encoded PowerShell Launch\nid: 58d11f86-7a68-4e60-9a74-610000000004\nstatus: stable\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n    CommandLine|contains: '-EncodedCommand'\n  condition: selection\nfalsepositives:\n  - Endpoint management wrappers\nlevel: high",
            "expected_event_ids": event_ids("incident-powershell"),
        },
        {
            "id": "det-advanced-discovery-utilities",
            "title": localized(
                "Discovery utility launched from PowerShell",
                "Discovery-Werkzeug aus PowerShell gestartet",
            ),
            "description": localized(
                "Detects host or network discovery processes whose parent is PowerShell.",
                "Erkennt Prozesse zur Host- oder Netzwerkerkennung mit PowerShell als Elternprozess.",
            ),
            "severity": "medium",
            "mitre": ["T1082", "T1016"],
            "false_positive_context": localized(
                "Inventory and support scripts use these utilities. User role, script signing, ticket context, and adjacent activity determine whether the behavior is expected.",
                "Inventar- und Supportskripte nutzen diese Werkzeuge. Benutzerrolle, Skriptsignatur, Ticketkontext und benachbarte Aktivitäten bestimmen, ob das Verhalten erwartet ist.",
            ),
            "match": "all",
            "conditions": [
                {
                    "field": "event_type",
                    "operator": "equals",
                    "value": "process_created",
                },
                {
                    "field": "parent_process_name",
                    "operator": "equals",
                    "value": "powershell.exe",
                },
                {
                    "field": "attributes.discovery_family",
                    "operator": "in",
                    "value": ["host", "network"],
                },
            ],
            "sigma": "title: Discovery Utility Launched from PowerShell\nid: 58d11f86-7a68-4e60-9a74-610000000005\nstatus: experimental\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  parent:\n    ParentImage|endswith: '\\\\powershell.exe'\n  utility:\n    Image|endswith:\n      - '\\\\systeminfo.exe'\n      - '\\\\ipconfig.exe'\n  condition: parent and utility\nfalsepositives:\n  - Inventory and support scripts\nlevel: medium",
            "expected_event_ids": event_ids("incident-systeminfo", "incident-ipconfig"),
        },
        {
            "id": "det-advanced-powershell-network",
            "title": localized(
                "PowerShell connected to an uncategorized service",
                "PowerShell verband sich mit nicht kategorisiertem Dienst",
            ),
            "description": localized(
                "Detects PowerShell network connections whose destination lacks an approved category.",
                "Erkennt PowerShell-Netzwerkverbindungen zu Zielen ohne genehmigte Kategorie.",
            ),
            "severity": "high",
            "mitre": ["T1105"],
            "false_positive_context": localized(
                "Administrative download scripts may reach new vendor endpoints. Validate the parent process, user role, change record, destination ownership, and retrieved content metadata.",
                "Administrative Downloadskripte können neue Herstellerziele erreichen. Prüfen Sie Elternprozess, Benutzerrolle, Änderungsnachweis, Zielinhaber und Metadaten des abgerufenen Inhalts.",
            ),
            "match": "all",
            "conditions": [
                {
                    "field": "event_type",
                    "operator": "equals",
                    "value": "network_connection",
                },
                {
                    "field": "process_name",
                    "operator": "equals",
                    "value": "powershell.exe",
                },
                {
                    "field": "attributes.category",
                    "operator": "equals",
                    "value": "uncategorized",
                },
            ],
            "sigma": "title: PowerShell Connected to an Uncategorized Service\nid: 58d11f86-7a68-4e60-9a74-610000000013\nstatus: experimental\nlogsource:\n  category: network_connection\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n    DestinationCategory: uncategorized\n  condition: selection\nfalsepositives:\n  - Administrative access to new vendor endpoints\nlevel: high",
            "expected_event_ids": event_ids("incident-network-control"),
        },
        {
            "id": "det-advanced-new-share-source",
            "title": localized(
                "Network share logon from a new workstation",
                "Netzwerkfreigabe-Anmeldung von neuer Arbeitsstation",
            ),
            "description": localized(
                "Detects a successful network logon whose source workstation is new for the user and share.",
                "Erkennt eine erfolgreiche Netzwerkanmeldung von einer für Benutzer und Freigabe neuen Arbeitsstation.",
            ),
            "severity": "medium",
            "mitre": ["T1078"],
            "false_positive_context": localized(
                "A device replacement or first-time remote work session can be legitimate. Validate source ownership, ticket history, session activity, and accessed files.",
                "Gerätetausch oder erstmalige Fernarbeit können legitim sein. Prüfen Sie Quellbesitz, Tickethistorie, Sitzungsaktivität und Dateizugriffe.",
            ),
            "match": "all",
            "conditions": [
                {"field": "source", "operator": "equals", "value": "windows_security"},
                {
                    "field": "event_type",
                    "operator": "equals",
                    "value": "authentication_success",
                },
                {
                    "field": "attributes.new_source_for_user",
                    "operator": "equals",
                    "value": True,
                },
            ],
            "sigma": "title: Network Share Logon from a New Workstation\nid: 58d11f86-7a68-4e60-9a74-610000000006\nstatus: experimental\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4624\n    LogonType: 3\n    NewSourceForUser: true\n  condition: selection\nfalsepositives:\n  - Device replacement or first-time remote access\nlevel: medium",
            "expected_event_ids": event_ids("incident-share-auth"),
        },
        {
            "id": "det-advanced-archive-staging",
            "title": localized(
                "Archive created in browser cache", "Archiv im Browser-Cache erstellt"
            ),
            "description": localized(
                "Detects an archive created in a browser cache directory before possible transfer.",
                "Erkennt ein vor einer möglichen Übertragung in einem Browser-Cache-Verzeichnis erstelltes Archiv.",
            ),
            "severity": "high",
            "mitre": ["T1560.001"],
            "false_positive_context": localized(
                "Browser-based export tools can stage archives. Confirm process ancestry, source material, destination, transfer approval, and deletion behavior.",
                "Browserbasierte Exportwerkzeuge können Archive bereitstellen. Prüfen Sie Prozessherkunft, Quelldaten, Ziel, Übertragungsgenehmigung und Löschverhalten.",
            ),
            "match": "all",
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "file_created"},
                {"field": "attributes.archive", "operator": "equals", "value": True},
                {
                    "field": "attributes.directory_category",
                    "operator": "equals",
                    "value": "browser_cache",
                },
            ],
            "sigma": "title: Archive Created in Browser Cache\nid: 58d11f86-7a68-4e60-9a74-610000000007\nstatus: experimental\nlogsource:\n  category: file_event\n  product: windows\ndetection:\n  selection:\n    TargetFilename|contains: '\\\\BrowserCache\\\\'\n    TargetFilename|endswith: '.zip'\n  condition: selection\nfalsepositives:\n  - Browser export workflows\nlevel: high",
            "expected_event_ids": event_ids("incident-archive-file"),
        },
        {
            "id": "det-advanced-restricted-share-read",
            "title": localized(
                "Restricted share read through a new session",
                "Lesezugriff auf eingeschränkte Freigabe über neue Sitzung",
            ),
            "description": localized(
                "Detects file reads from the restricted finance share for correlation with authentication and staging activity.",
                "Erkennt Dateizugriffe auf die eingeschränkte Finanzfreigabe zur Korrelation mit Authentifizierung und Bereitstellung.",
            ),
            "severity": "medium",
            "mitre": ["T1039"],
            "false_positive_context": localized(
                "Authorized finance work requires this share. Determine whether the session, workstation, accessed files, volume, and subsequent staging match the user's baseline.",
                "Autorisierte Finanzarbeit benötigt diese Freigabe. Prüfen Sie, ob Sitzung, Arbeitsstation, Dateien, Volumen und nachfolgende Bereitstellung zum Benutzerprofil passen.",
            ),
            "match": "all",
            "conditions": [
                {"field": "source", "operator": "equals", "value": "windows_security"},
                {"field": "event_type", "operator": "equals", "value": "file_accessed"},
                {
                    "field": "attributes.share",
                    "operator": "equals",
                    "value": "Finance-Restricted",
                },
            ],
            "sigma": "title: Restricted Share Read through a New Session\nid: 58d11f86-7a68-4e60-9a74-610000000014\nstatus: experimental\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 5145\n    ShareName: Finance-Restricted\n  condition: selection\nfalsepositives:\n  - Authorized finance access\nlevel: medium",
            "expected_event_ids": event_ids(
                "incident-file-read-one", "incident-file-read-two"
            ),
        },
        {
            "id": "det-advanced-large-upload",
            "title": localized(
                "Large outbound file upload", "Großer ausgehender Datei-Upload"
            ),
            "description": localized(
                "Detects outbound file uploads larger than 50 MB regardless of destination approval.",
                "Erkennt ausgehende Datei-Uploads über 50 MB unabhängig von der Zielgenehmigung.",
            ),
            "severity": "medium",
            "mitre": ["T1567.002"],
            "false_positive_context": localized(
                "Approved media publishing, backup, and collaboration workflows routinely exceed this threshold. Destination ownership and change context are decisive.",
                "Genehmigte Medien-, Sicherungs- und Kollaborationsabläufe überschreiten diesen Schwellenwert regelmäßig. Zielinhaberschaft und Änderungskontext sind entscheidend.",
            ),
            "match": "all",
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "file_upload"},
                {"field": "bytes_out", "operator": "greater_than", "value": 50000000},
            ],
            "sigma": "title: Large Outbound File Upload\nid: 58d11f86-7a68-4e60-9a74-610000000008\nstatus: test\nlogsource:\n  category: proxy\ndetection:\n  selection:\n    action: file_upload\n    bytes_out|gt: 50000000\n  condition: selection\nfalsepositives:\n  - Approved media, backup, and collaboration transfers\nlevel: medium",
            "expected_event_ids": event_ids("incident-upload", "decoy-media-upload"),
        },
        {
            "id": "det-advanced-unapproved-upload",
            "title": localized(
                "Upload to unapproved storage tenant",
                "Upload in nicht genehmigten Speichermandanten",
            ),
            "description": localized(
                "Detects a file upload whose normalized destination context is not an approved service.",
                "Erkennt einen Datei-Upload zu einem laut normalisiertem Zielkontext nicht genehmigten Dienst.",
            ),
            "severity": "high",
            "mitre": ["T1567.002"],
            "false_positive_context": localized(
                "Newly adopted business services may not yet be classified. Validate service ownership, tenant identity, data sensitivity, and an approval record.",
                "Neu eingeführte Geschäftsdienste sind möglicherweise noch nicht klassifiziert. Prüfen Sie Dienstinhaber, Mandantenidentität, Datensensibilität und Genehmigungsnachweis.",
            ),
            "match": "all",
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "file_upload"},
                {
                    "field": "attributes.approved_service",
                    "operator": "equals",
                    "value": False,
                },
            ],
            "sigma": "title: Upload to Unapproved Storage Tenant\nid: 58d11f86-7a68-4e60-9a74-610000000009\nstatus: stable\nlogsource:\n  category: proxy\ndetection:\n  selection:\n    action: file_upload\n    approved_service: false\n  condition: selection\nfalsepositives:\n  - Newly adopted but not yet classified business services\nlevel: high",
            "expected_event_ids": event_ids("incident-upload"),
        },
        {
            "id": "det-advanced-hosting-vpn",
            "title": localized(
                "Successful VPN access from hosting ASN",
                "Erfolgreicher VPN-Zugriff aus Hosting-ASN",
            ),
            "description": localized(
                "Detects successful VPN authentication from an address categorized as hosting infrastructure.",
                "Erkennt erfolgreiche VPN-Authentifizierung von einer als Hosting-Infrastruktur kategorisierten Adresse.",
            ),
            "severity": "medium",
            "mitre": ["T1078"],
            "false_positive_context": localized(
                "Hotel gateways, privacy relays, and provider routing can map managed travel devices to hosting ASNs. Confirm itinerary, MFA, and device compliance.",
                "Hotel-Gateways, Privacy-Relays und Provider-Routing können verwaltete Reisegeräte Hosting-ASNs zuordnen. Prüfen Sie Reiseplan, MFA und Gerätekonformität.",
            ),
            "match": "all",
            "conditions": [
                {"field": "source", "operator": "equals", "value": "vpn"},
                {"field": "event_type", "operator": "equals", "value": "vpn_login"},
                {"field": "outcome", "operator": "equals", "value": "success"},
                {
                    "field": "attributes.asn_category",
                    "operator": "equals",
                    "value": "hosting",
                },
            ],
            "sigma": "title: Successful VPN Access from Hosting ASN\nid: 58d11f86-7a68-4e60-9a74-610000000010\nstatus: test\nlogsource:\n  category: authentication\ndetection:\n  selection:\n    source: vpn\n    outcome: success\n    asn_category: hosting\n  condition: selection\nfalsepositives:\n  - Managed devices behind travel or privacy gateways\nlevel: medium",
            "expected_event_ids": event_ids("decoy-vpn"),
        },
        {
            "id": "det-advanced-uncommon-port",
            "title": localized(
                "External connection on uncommon TLS port",
                "Externe Verbindung über ungewöhnlichen TLS-Port",
            ),
            "description": localized(
                "Detects endpoint connections to TCP 8443 for contextual review.",
                "Erkennt Endpunktverbindungen über TCP 8443 zur kontextbezogenen Prüfung.",
            ),
            "severity": "medium",
            "mitre": ["T1041"],
            "false_positive_context": localized(
                "Vendor administration and validation services often use alternate TLS ports. Process signing, domain ownership, and change records can establish legitimacy.",
                "Herstelleradministration und Validierungsdienste nutzen häufig alternative TLS-Ports. Prozesssignatur, Domaininhaber und Änderungsnachweise können Legitimität belegen.",
            ),
            "match": "all",
            "conditions": [
                {
                    "field": "event_type",
                    "operator": "equals",
                    "value": "network_connection",
                },
                {
                    "field": "attributes.destination_port",
                    "operator": "equals",
                    "value": 8443,
                },
            ],
            "sigma": "title: External Connection on Uncommon TLS Port\nid: 58d11f86-7a68-4e60-9a74-610000000011\nstatus: test\nlogsource:\n  category: network_connection\ndetection:\n  selection:\n    DestinationPort: 8443\n  condition: selection\nfalsepositives:\n  - Vendor administration and validation services\nlevel: medium",
            "expected_event_ids": event_ids("decoy-network-8443"),
        },
    ]

    critical_keys = (
        "incident-email",
        "incident-link",
        "incident-office-open",
        "incident-cmd",
        "incident-powershell",
        "incident-script-block",
        "incident-systeminfo",
        "incident-network-control",
        "incident-share-auth",
        "incident-file-read-one",
        "incident-file-read-two",
        "incident-archive-process",
        "incident-archive-file",
        "incident-upload",
        "incident-upload-zeek",
    )
    pack = {
        "schema_version": 1,
        "metadata": {
            "id": "converging-signals",
            "version": 1,
            "difficulty": "advanced",
            "estimated_minutes": 40,
            "title": localized("Converging Signals", "Konvergierende Signale"),
            "description": localized(
                "Reconstruct a multi-stage enterprise compromise across email, endpoint, identity, file, and network telemetry while rejecting credible operational false positives.",
                "Rekonstruieren Sie eine mehrstufige Unternehmenskompromittierung über E-Mail-, Endpunkt-, Identitäts-, Datei- und Netzwerktelemetrie und verwerfen Sie glaubwürdige betriebliche Fehlalarme.",
            ),
            "learning_objectives": [
                localized(
                    "Build a defensible chronology by pivoting across independent telemetry sources.",
                    "Erstellen Sie durch Pivotieren über unabhängige Telemetriequellen eine belastbare Chronologie.",
                ),
                localized(
                    "Use identity, endpoint, process, session, file, domain, and timing relationships to test a compromise hypothesis.",
                    "Nutzen Sie Beziehungen zwischen Identität, Endpunkt, Prozess, Sitzung, Datei, Domain und Zeit, um eine Kompromittierungshypothese zu prüfen.",
                ),
                localized(
                    "Distinguish true-positive detections from legitimate PowerShell, travel authentication, large transfer, and alternate-port activity.",
                    "Unterscheiden Sie echte Treffer von legitimer PowerShell-, Reiseanmelde-, Großübertragungs- und Alternativport-Aktivität.",
                ),
                localized(
                    "Select proportionate containment and produce a concise threat-informed incident report.",
                    "Wählen Sie verhältnismäßige Eindämmungsmaßnahmen und erstellen Sie einen prägnanten, bedrohungsinformierten Vorfallsbericht.",
                ),
            ],
        },
        "users": users,
        "assets": assets,
        "events": materialized_events,
        "detections": detections,
        "containment_options": [
            {
                "id": "contain-isolate-ws-610",
                "label": localized("Isolate WS-610", "WS-610 isolieren"),
                "description": localized(
                    "Simulate network isolation of the affected workstation while retaining telemetry collection.",
                    "Simuliert die Netzwerkisolation der betroffenen Arbeitsstation bei fortgesetzter Telemetrieerfassung.",
                ),
            },
            {
                "id": "contain-revoke-fin-610",
                "label": localized(
                    "Revoke Finance Analyst 610 sessions",
                    "Sitzungen von Finance Analyst 610 widerrufen",
                ),
                "description": localized(
                    "Simulate credential reset, active-session revocation, and monitored re-enrolment for the affected identity.",
                    "Simuliert Kennwortzurücksetzung, Widerruf aktiver Sitzungen und überwachte Neuregistrierung der betroffenen Identität.",
                ),
            },
            {
                "id": "contain-preserve-evidence",
                "label": localized(
                    "Preserve endpoint and file-access evidence",
                    "Endpunkt- und Dateizugriffsbeweise sichern",
                ),
                "description": localized(
                    "Simulate preserving volatile endpoint telemetry, the staged archive, and FILES-02 audit records before remediation.",
                    "Simuliert die Sicherung flüchtiger Endpunkttelemetrie, des bereitgestellten Archivs und der FILES-02-Prüfprotokolle vor der Bereinigung.",
                ),
            },
            {
                "id": "contain-block-observed-services",
                "label": localized(
                    "Block observed unapproved services",
                    "Beobachtete nicht genehmigte Dienste sperren",
                ),
                "description": localized(
                    "Simulate a scoped temporary block for document-review.example, content-gateway.example, and files-gateway.example.",
                    "Simuliert eine begrenzte temporäre Sperre für document-review.example, content-gateway.example und files-gateway.example.",
                ),
            },
            {
                "id": "contain-isolate-mgmt-030",
                "label": localized("Isolate MGMT-030", "MGMT-030 isolieren"),
                "description": localized(
                    "A disruptive action against the management workstation despite signed activity and an approved change record.",
                    "Eine störende Maßnahme gegen die Verwaltungsarbeitsstation trotz signierter Aktivität und genehmigtem Änderungsnachweis.",
                ),
            },
            {
                "id": "contain-block-corporate-media",
                "label": localized(
                    "Block the corporate media tenant",
                    "Unternehmens-Medienmandanten sperren",
                ),
                "description": localized(
                    "A broad action that would interrupt an approved transfer to a verified corporate destination.",
                    "Eine breite Maßnahme, die eine genehmigte Übertragung zu einem verifizierten Unternehmensziel unterbrechen würde.",
                ),
            },
            {
                "id": "contain-disable-powershell",
                "label": localized(
                    "Disable PowerShell globally", "PowerShell global deaktivieren"
                ),
                "description": localized(
                    "A disproportionate response that would disrupt documented administration across the environment.",
                    "Eine unverhältnismäßige Reaktion, die dokumentierte Administration in der gesamten Umgebung stören würde.",
                ),
            },
        ],
        "expected_outcome": {
            "classification": "confirmed_incident",
            "severity": "high",
            "affected_user_ids": ["usr-fin-610"],
            "affected_asset_ids": ["asset-ws-610", "asset-files-02"],
            "critical_event_ids": event_ids(*critical_keys),
            "mitre": [
                "T1566.002",
                "T1204.001",
                "T1204.002",
                "T1059.003",
                "T1059.001",
                "T1082",
                "T1016",
                "T1105",
                "T1078",
                "T1039",
                "T1560.001",
                "T1567.002",
            ],
            "containment_action_ids": [
                "contain-isolate-ws-610",
                "contain-revoke-fin-610",
                "contain-preserve-evidence",
                "contain-block-observed-services",
            ],
            "false_positive_event_ids": event_ids(
                "decoy-admin-powershell",
                "decoy-vpn",
                "decoy-network-8443",
                "decoy-media-upload",
            ),
            "explanation": localized(
                "This is a confirmed high-severity incident affecting Finance Analyst 610 and WS-610, with unauthorized access to restricted data on FILES-02 and a completed external upload. The canonical timeline begins with a DMARC-misaligned planning email and user link interaction, continues through an Internet-zone document, Office-to-cmd-to-PowerShell ancestry, obfuscated discovery, and an uncategorized outbound connection, then resumes with a new-source network logon, restricted file reads, archive staging, and a 61.8 MB upload corroborated by Zeek. No single alert proves the case: user, endpoint, process ancestry, domain, authentication session, file, byte volume, and time relationships converge. The nearby administrator PowerShell is signed and ticketed; the hosting-ASN VPN login has an approved itinerary, compliant device, and MFA; the 986.7 MB media upload targets the approved corporate tenant; and TCP 8443 validation is tied to a signed process and approved change. Appropriate response is scoped isolation of WS-610, revocation of the affected user's sessions, evidence preservation, and blocking only the observed unapproved services.",
                "Dies ist ein bestätigter Vorfall mit hohem Schweregrad, der Finance Analyst 610 und WS-610 betrifft; auf FILES-02 wurden unbefugt eingeschränkte Daten gelesen und extern übertragen. Die kanonische Zeitleiste beginnt mit einer DMARC-fehlausgerichteten Planungs-E-Mail und der Link-Interaktion, führt über ein Internetzonen-Dokument, die Prozesskette Office–cmd–PowerShell, verschleierte Discovery-Aktivität und eine nicht kategorisierte ausgehende Verbindung und setzt sich mit einer Netzwerkanmeldung von neuer Quelle, Zugriffen auf eingeschränkte Dateien, Archivbereitstellung und einem durch Zeek bestätigten Upload von 61,8 MB fort. Kein einzelner Alarm beweist den Fall: Benutzer-, Endpunkt-, Prozessherkunfts-, Domain-, Sitzung-, Datei-, Volumen- und Zeitbeziehungen ergeben gemeinsam das Bild. Die nahe Administrator-PowerShell ist signiert und per Ticket genehmigt; die VPN-Anmeldung aus einem Hosting-ASN besitzt Reisegenehmigung, konformes Gerät und MFA; der Upload von 986,7 MB geht an den genehmigten Unternehmensmandanten; die TCP-8443-Validierung ist an einen signierten Prozess und eine genehmigte Änderung gebunden. Angemessen sind die gezielte Isolation von WS-610, der Widerruf der Benutzersitzungen, Beweissicherung und nur die Sperrung der beobachteten nicht genehmigten Dienste.",
            ),
            "lessons": [
                localized(
                    "The decisive chronology is message → link → downloaded document → Office child shell → encoded PowerShell → discovery → outbound retrieval → share logon → restricted reads → archive → external upload.",
                    "Die entscheidende Chronologie lautet Nachricht → Link → heruntergeladenes Dokument → Office-Kindprozess → kodierte PowerShell → Discovery → ausgehender Abruf → Freigabeanmeldung → eingeschränkte Lesezugriffe → Archiv → externer Upload.",
                ),
                localized(
                    "The email, Office-child, encoded-PowerShell, new-share-source, archive-staging, and unapproved-upload rules fired on fields that directly support the incident; the broad PowerShell and large-upload rules required context before disposition.",
                    "Die Regeln für E-Mail, Office-Kindprozess, kodierte PowerShell, neue Freigabequelle, Archivbereitstellung und nicht genehmigten Upload trafen auf unmittelbar relevante Felder; die breiten PowerShell- und Großupload-Regeln erforderten Kontext.",
                ),
                localized(
                    "Four major decoys are benign for specific reasons: signed ticketed administration, approved travel with MFA and a compliant device, an approved corporate media tenant, and ticketed validation on TCP 8443.",
                    "Vier wesentliche Ablenkungen sind aus konkreten Gründen legitim: signierte Administration mit Ticket, genehmigte Reise mit MFA und konformem Gerät, ein genehmigter Unternehmens-Medienmandant sowie validierter TCP-8443-Verkehr mit Ticket.",
                ),
                localized(
                    "Correlations that matter combine process ancestry, shared user and workstation, mail and web sessions, the FILES-02 authentication session, archive-to-upload filename, destination domain and IP, transfer size, and temporal proximity.",
                    "Relevante Korrelationen verbinden Prozessherkunft, Benutzer und Arbeitsstation, Mail- und Websitzungen, die FILES-02-Authentifizierungssitzung, den Archiv- und Upload-Dateinamen, Ziel-Domain und -IP, Übertragungsvolumen und zeitliche Nähe.",
                ),
                localized(
                    "ATT&CK mapping should describe observed behavior rather than decorate alerts: phishing and user execution led to scripting, discovery, transfer, valid-account use, network-share collection, archive staging, and exfiltration to cloud storage.",
                    "Die ATT&CK-Zuordnung soll beobachtetes Verhalten beschreiben statt Alarme zu dekorieren: Phishing und Benutzerausführung führten zu Skriptausführung, Discovery, Transfer, Nutzung gültiger Konten, Sammlung aus einer Netzwerkfreigabe, Archivbereitstellung und Exfiltration in Cloud-Speicher.",
                ),
            ],
        },
    }
    if len(materialized_events) != 192:
        raise AssertionError(f"expected 192 events, built {len(materialized_events)}")
    return pack


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check", action="store_true", help="fail if the committed pack differs"
    )
    arguments = parser.parse_args()
    rendered = json.dumps(build_pack(), indent=2, ensure_ascii=False) + "\n"
    if arguments.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
            print(f"{OUTPUT.relative_to(ROOT)} is not up to date")
            return 1
        print("Advanced scenario data is deterministic and up to date.")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)} with 192 events.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
