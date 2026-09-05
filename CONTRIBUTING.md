# Contributing to SOCWerk

SOCWerk welcomes focused contributions that improve defensive investigation, detection engineering, realistic synthetic telemetry, localization, accessibility, or project reliability.

## Before opening a change

1. Search existing issues and discussions for related work.
2. Keep a change scoped to one coherent problem.
3. For a new scenario, describe its learning objective, suspicious chain, and plausible benign lookalike.
4. Never include private, proprietary, or operational security data.

## Development setup

Follow the local setup in [README.md](README.md). Before submitting a change, run:

```bash
make validate
```

If Docker is available, also run:

```bash
docker compose build
```

## Code and content expectations

- Keep SOCWerk local, defensive, deterministic, and explainable.
- Use documentation-reserved IP ranges and `.example` domains.
- Do not add functional payloads, credential material, exploit instructions, or arbitrary execution.
- Keep scenario data declarative and valid under the strict scenario schema.
- Add tests for behavior changes and detection changes.
- Preserve English as the canonical language and provide complete German text for localized scenario fields.
- Document new public behavior and avoid unrelated refactoring.

Scenario contributions should follow [docs/scenario-authoring.md](docs/scenario-authoring.md). Changes to normalization or rules should also review [docs/telemetry-and-detections.md](docs/telemetry-and-detections.md).

## Pull requests

Explain the analyst problem addressed, the chosen implementation, the validation performed, and any remaining limitations. Repository-hosted issues and pull requests are the project’s coordination channels; do not place personal contact information in source files.
