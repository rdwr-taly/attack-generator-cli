.PHONY: install test lint run

install:
	pip install -e .

test:
	pytest -q

lint:
	ruff check attack_generator tests

run:
	attack-generator run --help
