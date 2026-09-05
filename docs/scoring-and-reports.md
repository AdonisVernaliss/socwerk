# Scoring and Reports

SOCWerk assessment measures the outcome of an investigation rather than a sequence of quiz answers.

## Submission boundary

An analyst may revise evidence, notes, hypotheses, findings, alert dispositions, and the incident decision while a session is active. Submission requires a saved decision, changes the session to `submitted`, and makes all investigation state read-only.

Only the backend performs this transition. Expected scenario content is not included in scenario, event, detection, alert, or active-session responses. After submission the assessment is persisted so reloads and report exports remain stable.

## Score

The maximum score is 100:

| Dimension | Points | Method |
| --- | ---: | --- |
| Incident classification | 20 | Exact match |
| Severity | 10 | Exact match |
| Affected users | 10 | Set precision/recall |
| Affected assets | 10 | Set precision/recall |
| Critical evidence | 20 | Set precision/recall |
| MITRE ATT&CK mapping | 10 | Set precision/recall |
| Containment choices | 10 | Set precision/recall |
| False-positive handling | 10 | Set precision/recall over terminal benign/false-positive alert decisions |

Set-based dimensions use the harmonic mean of precision and recall. This gives partial credit while penalizing both missed facts and indiscriminate selection. Free text is included in the report but is not machine-scored; SOCWerk does not use an external model or service.

Post-submission feedback includes the expected explanation, lessons, missed critical evidence, and evidence that was not part of the critical set.

## Reports

The report projection combines the analyst’s decision and work with the immutable scenario context and post-submission assessment. Exports are available as:

- Markdown for review, version control, or case systems;
- JSON for structured processing;
- standalone HTML for direct viewing or printing.

Reports include classification, severity, affected users/assets, evidence timeline, alert decisions, ATT&CK mapping, findings, hypotheses, containment recommendations, analyst notes, assessment, and lessons learned. Containment remains a recorded simulation; export never triggers an external action.
