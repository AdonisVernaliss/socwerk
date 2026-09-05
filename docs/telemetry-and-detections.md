# Telemetry and Detection Model

## Normalized event envelope

Every scenario event retains a `raw` value and provides one normalized envelope. Raw values may be a source-shaped JSON object or a log line. The normalized fields allow uniform filtering, correlation, and detection:

| Field group | Examples | Purpose |
| --- | --- | --- |
| Identity | `user_id`, `session_id` | Authentication and cross-source pivots |
| Asset | `asset_id` | Endpoint/server ownership and impact |
| Network | `source_ip`, `destination_ip`, `domain`, `bytes_out` | DNS, proxy, and endpoint network correlation |
| Process | `process_name`, `parent_process_name`, process identifiers | Parent-child reconstruction |
| File | `file_name` | Staging, downloads, and cleanup |
| Classification | `source`, `event_type`, `severity`, `outcome` | Common exploration and rules |
| ATT&CK | `mitre` | Scenario-specific technique mapping |
| Source detail | `attributes` | Typed scenario facts not shared by all sources |

Normalization is explicit scenario data in v1. This keeps each educational transformation reviewable: the raw source field and SOCWerk interpretation can be compared side-by-side. A future ingestion profile can produce the same envelope without changing investigation behavior.

## Telemetry sources

The initial packs model Windows Security event identifiers, Sysmon-style process/file/network records, PowerShell 4104-style script-block records, identity-provider sign-ins, MFA decisions, VPN gateway lines, DNS answers, HTTP/proxy metadata, email authentication metadata, browser navigation, endpoint file activity, DLP policy results, user reports, and change-control context.

Values are synthetic and intentionally sanitized. Command lines retain only the structural facts needed for defensive analysis. Domains use `.example`; IP addresses use documentation ranges.

## Detection rules

A detection declares:

- stable identifier and localized title/description;
- severity and relevant ATT&CK techniques;
- `all` or `any` condition aggregation;
- a bounded list of normalized-field conditions;
- localized expected false-positive context;
- reviewable Sigma-inspired YAML;
- server-only expected match identifiers used for integrity tests.

Supported operators are `equals`, `not_equals`, `contains`, `in`, `greater_than`, and `exists`. Nested normalized values use dotted paths such as `attributes.failure_count`.

For every match, the engine returns each condition with its actual event value and match result. Alerts are stable functions of `(rule, event)` and therefore deterministic.

SOCWerk includes broad rules on purpose. For example, both suspicious and approved PowerShell executions trigger a visibility rule, and both suspicious and approved large uploads trigger a volume rule. The analyst must tune the signal using parent process, signing, destination, labels, and change-control evidence.

## Correlation

Correlation checks explicit relationships plus shared users, assets, IPs, domains, authentication sessions, and process ancestry. Time proximity is added only when another relationship already exists. A suggestion requires an explicit relationship or multiple meaningful signals, and the API returns the exact reasons.

There is no machine-learning or hidden correlation layer. The percentage displayed in the UI is a bounded presentation of the number of explained relationships, not a probability of maliciousness.

## ATT&CK usage

Only techniques demonstrated by scenario evidence are included. Mapping describes observed behavior and does not assert attacker identity or attribution. The initial content covers Valid Accounts, Brute Force, Phishing Link, User Execution, Command Shell, PowerShell, System Information Discovery, Ingress Tool Transfer, Archive Collected Data, Exfiltration to Cloud Storage, and File Deletion.
