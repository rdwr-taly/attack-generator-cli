from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft7Validator

BASE = Path(__file__).resolve().parent.parent
SCHEMA_PATH = BASE / "schemas" / "attackmap.schema.json"
EXAMPLE_PATH = BASE / "examples" / "basic_injection_spray.json"


def test_examples_validate() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft7Validator(schema)
    example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
    validator.validate(example)


def test_invalid_map_rejected(tmp_path: Path) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft7Validator(schema)
    invalid_map = {
        "version": 1,
        "name": "Broken",
        "target": {"base_url": "https://example.com"},
        "safety": {"allowlist": []},
        "attacks": [],
    }
    errors = list(validator.iter_errors(invalid_map))
    assert errors
