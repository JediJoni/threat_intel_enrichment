.PHONY: install format lint typecheck test check run clean

install:
	python -m pip install --upgrade pip
	python -m pip install -e ".[dev]"

format:
	python -m ruff format .
	python -m ruff check --fix .

lint:
	python -m ruff check .
	python -m ruff format --check .

typecheck:
	python -m mypy src

test:
	python -m pytest --cov=threat_intel_enrichment --cov-report=term-missing

check: lint typecheck test

run:
	python -m threat_intel_enrichment.cli --help

clean:
	rm -rf build dist *.egg-info
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov
	rm -f .coverage coverage.xml
	find . -type d -name "__pycache__" -exec rm -rf {} +
