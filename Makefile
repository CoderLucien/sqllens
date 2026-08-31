PYTHON := .venv/bin/python
WEB_DIR := apps/web

.PHONY: bootstrap dev lint typecheck test test-integration test-e2e build smoke benchmark-2c4g

bootstrap:
	python3 -m venv .venv
	$(PYTHON) -m pip install -r requirements/dev.lock
	$(PYTHON) -m pip install --no-deps -e .
	cd $(WEB_DIR) && npm ci

dev:
	SQLLENS_DATA_DIR=.data $(PYTHON) -m sqllens_api.main web-api & \
	api_pid=$$!; \
	trap 'kill $$api_pid 2>/dev/null || true' EXIT INT TERM; \
	cd $(WEB_DIR) && npm run dev

lint:
	$(PYTHON) -m ruff check apps/api/src tests/api
	cd $(WEB_DIR) && npm run lint

typecheck:
	$(PYTHON) -m mypy apps/api/src
	cd $(WEB_DIR) && npm run typecheck

test:
	$(PYTHON) -m pytest -q tests/api
	cd $(WEB_DIR) && npm test

test-integration:
	$(PYTHON) -m pytest -q tests/api/test_setup_gate.py

test-e2e:
	@printf '%s\n' 'Browser E2E is not implemented in this checkpoint.'
	@exit 2

build:
	cd $(WEB_DIR) && npm run build
	$(PYTHON) -m pip wheel --no-deps --wheel-dir build .

smoke:
	$(PYTHON) -m pytest -q tests/api/test_setup_gate.py

benchmark-2c4g:
	@printf '%s\n' '2C4G qualification is not implemented in this checkpoint.'
	@exit 2
