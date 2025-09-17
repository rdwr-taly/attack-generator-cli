.PHONY: install test lint run dryrun validate

install:
	pip install -e .

test:
	pytest -q

lint:
	ruff check attack_generator tests

run:
	attack-generator run --attackmap examples/basic_injection_spray.json --allowlist "*.radware.net" --qps 3 --metrics-port 0

dryrun:
	attack-generator dry-run examples/basic_injection_spray.json --dry-run 5 --seed 42

validate:
	attack-generator validate examples/basic_injection_spray.json
