.PHONY: help install install-dev test test-cov lint format typecheck check clean build publish generate

# Default target
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─── Setup ──────────────────────────────────────────────
install: ## Install NCSB
	python3 -m pip install .

install-dev: ## Install with dev dependencies
	python3 -m pip install -e ".[dev]"
	pre-commit install

# ─── Testing ────────────────────────────────────────────
test: ## Run tests
	python3 -m pytest tests/ -v

test-cov: ## Run tests with 100% coverage requirement
	python3 -m pytest tests/ -v --cov=ncsb --cov-report=term-missing --cov-report=html --cov-fail-under=100

# ─── Code Quality ──────────────────────────────────────
lint: ## Run linter (ruff)
	python3 -m ruff check src/ tests/

format: ## Auto-format code (ruff)
	python3 -m ruff format src/ tests/
	python3 -m ruff check --fix src/ tests/

check: lint test-cov ## Run all checks (lint + test with 100% coverage)

# ─── Build & Publish ───────────────────────────────────
clean: ## Clean build artifacts
	rm -rf dist/ build/ *.egg-info src/*.egg-info .pytest_cache .ruff_cache htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build: clean ## Build distribution packages
	python3 -m build

publish: build ## Publish to PyPI (requires PYPI_TOKEN)
	python3 -m twine upload dist/*

# ─── Application Usage ─────────────────────────────────
generate: ## Run generation script for the baseline JSON
	mkdir -p baseline/historical
	python3 -m ncsb.generate --out baseline/nist80053r5_full_catalog_enriched.json
	@TIMESTAMP=$$(date -u +"%Y-%m-%dT%H-%M-%SZ"); \
	cp baseline/nist80053r5_full_catalog_enriched.json baseline/historical/nist80053r5_full_catalog_enriched_$${TIMESTAMP}.json
