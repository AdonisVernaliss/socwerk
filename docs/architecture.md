# Architecture

SOCWerk is a two-service local application with one persistent data store and a read-only scenario repository.

```text
┌──────────────────────────────────────────────────────┐
│ SvelteKit web application                            │
│ scenario browser · event explorer · triage · report │
└─────────────────────────┬────────────────────────────┘
                          │ constrained JSON API
┌─────────────────────────▼────────────────────────────┐
│ FastAPI application                                  │
│                                                      │
│ Scenario repository ── normalization display         │
│          │                                           │
│          ├────────── detection evaluator             │
│          ├────────── correlation engine              │
│          ├────────── query evaluator                 │
│          └────────── scoring/reporting               │
│                                                      │
│ Analyst-state repository ───────────────── SQLite    │
└──────────────────────────────────────────────────────┘
```

## Design decisions

### Immutable facts, mutable analyst state

Scenario packs contain the facts of a case: entities, raw records, normalization, rules, explicit relationships, and the protected answer. Starting a session does not copy those facts into the database. SQLite stores only analyst state such as evidence, reasoning, alert dispositions, decisions, and assessment. This avoids duplicated scenario data and makes scenario versions reviewable.

### Declarative scenarios

JSON was selected because packs need strict, predictable semantics and no executable tags or constructors. Pydantic models reject unknown fields, invalid values, duplicate identifiers, broken references, missing English/German content, and out-of-order events. A pack directory must match its declared identifier and resolve below the configured scenario root.

### Bounded evaluation

Detection conditions use a fixed set of operators over normalized fields. Event queries use a small parser that produces in-memory predicates. Neither facility emits SQL or evaluates Python, JavaScript, shell, templates, or regular expressions supplied by a scenario.

### Explainability as domain data

Detection evaluation returns the actual value, expected value, operator, and result for every condition. Correlation returns the exact shared properties and temporal proximity. The UI presents these explanations directly instead of introducing an opaque risk score.

### API-owned assessment

Expected outcomes and expected rule matches are removed from every pre-submission API response. On submission, the API computes a deterministic score, stores the result, makes the session read-only, and only then returns the protected explanation. Reloading the browser retrieves the same persisted state.

## Main backend modules

- `scenarios.py`: safe pack discovery and strict parsing.
- `models.py`: scenario and request contracts.
- `detection.py`: deterministic rule evaluation and alert creation.
- `query.py`: tokenizer, parser, and read-only event predicates.
- `correlation.py`: explainable entity, process, session, and time relationships.
- `database.py`: parameterized SQLite persistence for analyst state.
- `reporting.py`: stable report projection and export formats.
- `api.py`: lifecycle and authorization boundaries between these services.

## Deployment

Docker Compose runs an unprivileged API container and an unprivileged SvelteKit Node container. Only SQLite data is persisted. The frontend uses the browser-visible API URL `http://localhost:8000`; CORS allows the local web origin by default. Local development uses the same service boundaries.

SOCWerk intentionally avoids queues, caches, search clusters, and cloud dependencies. Scenario sizes fit predictable in-memory filtering and pagination on a developer laptop.
