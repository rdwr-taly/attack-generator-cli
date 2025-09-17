from __future__ import annotations

import json
import sys

import pytest

from attack_generator.models import AttackMap
from tools.convert_v0 import convert_v0_to_v1, main


def _sample_v0() -> dict:
    return {
        "name": "Legacy",
        "target_url": "https://legacy.example.com",
        "allowlist": ["legacy.example.com"],
        "attacks": [
            {
                "id": "LEGACY1",
                "name": "Ping",
                "method": "GET",
                "path": "/ping",
                "headers": {"Accept": "*/*"},
            }
        ],
    }


def test_convert_function_produces_valid_map() -> None:
    v1 = convert_v0_to_v1(_sample_v0())
    AttackMap.model_validate(v1)


def test_cli_wrapper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    input_path = tmp_path / "legacy.json"
    output_path = tmp_path / "converted.json"
    input_path.write_text(json.dumps(_sample_v0()), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["convert_v0.py", str(input_path), str(output_path)])
    main()
    converted = json.loads(output_path.read_text(encoding="utf-8"))
    AttackMap.model_validate(converted)
