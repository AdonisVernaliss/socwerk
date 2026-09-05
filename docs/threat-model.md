# Threat Model

SOCWerk is a local defensive lab. The primary assets are local investigation state, the integrity of scenario content and scoring, and the safety of the developer workstation running the application.

## Trust boundaries

| Boundary | Untrusted input | Protection |
| --- | --- | --- |
| Scenario directory → API | JSON files, raw telemetry strings, localized text | Fixed root, resolved-path check, JSON parser, strict models, reference validation, no remote loading |
| Browser → API | identifiers, notes, decisions, filters, queries | typed request models, length limits, identifier validation, parameterized SQL, bounded query parser |
| API → browser | raw scenario content and analyst text | JSON encoding and framework escaping; restrictive response headers |
| Pre-submission → post-submission | protected answer and scoring keys | expected outcome omitted by API until an irreversible submission transition |
| Containers → host | service processes and persistence | unprivileged users, explicit ports, dedicated SQLite volume, no host socket or filesystem mount |

## Security objectives

- Scenario content cannot execute code, choose a filesystem path, or trigger a network request.
- The query language cannot reach SQL, process execution, filesystem access, or a general expression evaluator.
- Analyst-provided content cannot become active HTML or script in the application or report export.
- All database values are bound parameters.
- A session can reference only entities and events in its scenario.
- A submitted investigation is immutable and produces repeatable assessment/report content.
- Expected solutions are unavailable through supported API routes before submission.
- Routine API failures return concise messages rather than stack traces.

## Considered abuse cases

### Path traversal and symlinks

The loader only discovers `scenario.json` one directory below the configured root. It resolves every candidate and requires it to remain below that root. The scenario identifier must equal the directory name. Raw fields are display data and never become paths.

### Cross-site scripting

Svelte renders raw telemetry and localized strings as text. The application does not use raw-HTML rendering. Export generation escapes text for HTML, and Markdown fields are neutralized so embedded HTML is not active when opened in a renderer.

### Injection

The Event Explorer parser accepts field comparisons, `contains`, parentheses, and logical operators with a length limit. It never forwards expressions to SQLite. Detection conditions use enumerated operators. SQLite access uses placeholders throughout.

### Resource exhaustion

Event result pages are capped at 200 records, UI pages use 25 records, query length is capped, analyst text and list sizes are bounded, and scenario schemas constrain high-cardinality collections. SOCWerk is not intended for exposure to an untrusted network.

### Scenario answer disclosure

Expected outcomes and expected detection match IDs are server-only before submission. This is a product-integrity boundary rather than a claim against a user who can read local repository files; scenario authors and local machine owners necessarily possess the source packs.

## Out of scope

SOCWerk does not authenticate users, encrypt its local SQLite file, or provide multi-tenant isolation. It is designed for one trusted user on a local machine. Exposing the services directly to shared or public networks is unsupported.
