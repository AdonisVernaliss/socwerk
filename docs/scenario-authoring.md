# Scenario Authoring Guide

Scenario packs are self-contained, versioned data directories. Contributors can add an investigation without changing application code.

## Directory and file

Create exactly one pack file at:

```text
scenarios/<scenario-id>/scenario.json
```

The directory and `metadata.id` must match. IDs use lowercase letters, digits, and hyphens. Increment `metadata.version` whenever changing facts or the expected outcome in a way that affects an in-progress investigation.

## Required structure

```json
{
  "schema_version": 1,
  "metadata": {},
  "users": [],
  "assets": [],
  "events": [],
  "detections": [],
  "containment_options": [],
  "expected_outcome": {}
}
```

Unknown fields are rejected. Every localized object requires non-empty `en` and `de` strings.

### Metadata

Provide a stable ID, positive version, difficulty, realistic time estimate, localized title/description, and at least two learning objectives. Objectives should describe analyst reasoning, not clicking UI controls.

### Users and assets

Use role-based synthetic identities rather than real or invented contributor biographies. A user needs a normal behavioral baseline. An asset has a hostname, type, criticality, optional operating system, and optional owner reference.

Every user or asset referenced by an event or expected outcome must exist. Keep entity scope small enough to understand while including enough overlap to make pivots useful.

### Events

Events must be chronologically ordered and have unique IDs. Each event contains:

- `raw`: a source-shaped JSON object or log string;
- `normalized`: the common event envelope;
- `related_event_ids`: optional explicit edges that are meaningful even without shared normalized fields.

Raw data should resemble a real defensive source without reproducing sensitive production records. Preserve source field names, identifiers, nested shape, and timestamps where they teach normalization. Sanitized placeholders are required for command or content details that could become harmful.

Use `.example` domains and documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`). Never include credentials, secrets, actual infrastructure, functional payloads, malicious scripts, or instructions for compromising a system.

The normalized envelope supports timestamp, source, type, severity, summary, user/asset, IP/domain, process ancestry, session, file, byte count, outcome, ATT&CK techniques, and a source-specific `attributes` object. Prefer common top-level fields whenever they apply.

### Detections

Rules are declarative. Choose `match: "all"` or `match: "any"` and combine these operators:

| Operator | Meaning |
| --- | --- |
| `equals` / `not_equals` | Exact typed comparison |
| `contains` | Case-insensitive text containment or list membership |
| `in` | Actual value appears in a declared list |
| `greater_than` | Numeric comparison |
| `exists` | Field presence matches a Boolean value |

Fields use dotted normalized paths, for example `attributes.approved_service`. Do not place code, regular expressions, SQL, or templates in a rule.

Include a structurally reviewable Sigma-inspired rule in `sigma`. SOCWerk displays this source but executes only `conditions`. The server-only `expected_event_ids` list must equal actual evaluator output; validation fails on drift.

Every scenario should include at least one useful broad detection that also fires on plausible benign behavior. Explain the relevant false-positive context without revealing the case answer.

### Containment options

Offer proportionate decisions and at least one tempting but unjustifiably broad action. Descriptions must say that behavior is simulated or clearly describe a recommendation. Scenario content cannot invoke an integration or external action.

### Expected outcome

Declare the final classification, severity, affected entities, critical evidence, ATT&CK mapping, proportionate containment choices, events expected to be handled as benign/false-positive alerts, localized explanation, and lessons.

Every expected ATT&CK technique must also appear on at least one normalized event or detection rule so the analyst can select it in the final decision.

The API never returns this object before submission. After submission it drives deterministic feedback and report lessons.

## Authoring process

1. Define the learning objective and final incident decision.
2. Write the minimal suspicious timeline needed to support that decision.
3. Add a realistic benign chain that overlaps at least one detection.
4. Add routine noise and entity baselines.
5. Normalize every event and add only explainable explicit relationships.
6. Write detections and calculate their expected matches.
7. Select critical evidence that supports the conclusion without rewarding every event.
8. Validate, run tests, and complete an investigation manually in both languages.

## Validation

```bash
.venv/bin/python scripts/validate_scenarios.py
.venv/bin/pytest backend/tests/test_scenarios.py
```

Validation checks schema constraints, localization, duplicate IDs, chronology, references, and detection-match integrity. An error names the pack and invalid path or relationship.

Review the UI at both desktop and narrow widths. Confirm raw telemetry is readable, queries find the intended events, correlation reasons make sense, benign behavior is not trivially labeled, and the expected answer stays hidden until submission.
