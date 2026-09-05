.PHONY: dev-api dev-web test lint build validate smoke

dev-api:
	.venv/bin/uvicorn socwerk.main:app --reload --app-dir backend/src

dev-web:
	cd frontend && npm run dev

test:
	.venv/bin/pytest backend/tests
	cd frontend && npm test

lint:
	.venv/bin/ruff format --check backend
	.venv/bin/ruff check backend
	cd frontend && npm run check

build:
	cd frontend && npm run build

validate: lint test build
	.venv/bin/python scripts/build_advanced_scenario.py --check
	.venv/bin/python scripts/validate_scenarios.py
	.venv/bin/python scripts/repository_sanity.py
	docker compose config --quiet

smoke:
	.venv/bin/python scripts/live_smoke_test.py
