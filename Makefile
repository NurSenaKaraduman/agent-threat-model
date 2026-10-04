.PHONY: install lint format test check build reports docs schema clean

PY ?= uv run

install:
	uv sync

lint:
	$(PY) ruff check .
	$(PY) ruff format --check .

format:
	$(PY) ruff format .
	$(PY) ruff check --fix .

test:
	$(PY) pytest -q

check: lint test

build:
	rm -rf dist
	uv build

schema:
	$(PY) python scripts/gen_schema.py

docs: schema
	$(PY) python scripts/gen_catalogue_doc.py

reports:
	@for name in support-bot coding-agent finance-agent masoon-governed; do \
	  for fmt in markdown json sarif html; do \
	    case $$fmt in markdown) ext=md ;; *) ext=$$fmt ;; esac; \
	    $(PY) atm analyse examples/$$name.yaml --format $$fmt --output examples/reports/$$name.$$ext; \
	  done; \
	done
	$(PY) atm diff examples/finance-agent.yaml examples/masoon-governed.yaml --format markdown --output examples/reports/finance-to-masoon.diff.md

clean:
	rm -rf dist build .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
