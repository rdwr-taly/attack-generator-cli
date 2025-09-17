from __future__ import annotations

import json

import pytest

from attack_generator.models import AttackMap, ConfigError, resolve_runtime_config


def _load_map(data: dict) -> AttackMap:
    return AttackMap.model_validate_json(json.dumps(data))


def test_resolve_runtime_config_default_qps() -> None:
    data = {
        "version": 1,
        "name": "Test",
        "target": {"base_url": "https://example.com", "xff_header": "client-ip"},
        "safety": {"allowlist": ["example.com"], "global_rps_cap": 10, "stop_on_target_mismatch": True},
        "attacks": [
            {
                "id": "A1",
                "name": "Ping",
                "traffic_type": "api",
                "category": "misc",
                "method": "GET",
                "path": "/attack",
            }
        ],
    }
    attack_map = _load_map(data)
    config = resolve_runtime_config(attack_map=attack_map, cli_values={}, env_values={})
    assert config.qps == 5


def test_resolve_runtime_config_scenario_rate_guard() -> None:
    data = {
        "version": 1,
        "name": "Test",
        "target": {"base_url": "https://example.com", "xff_header": "client-ip"},
        "safety": {"allowlist": ["example.com"], "global_rps_cap": 5, "stop_on_target_mismatch": True},
        "attacks": [
            {
                "id": "A1",
                "name": "Ping",
                "traffic_type": "api",
                "category": "misc",
                "method": "GET",
                "path": "/attack",
            }
        ],
        "scenarios": [
            {
                "id": "S1",
                "name": "Burst",
                "select": {"by_ids": ["A1"]},
                "rate": {"qps": 10},
            }
        ],
    }
    attack_map = _load_map(data)
    with pytest.raises(ConfigError):
        resolve_runtime_config(attack_map=attack_map, cli_values={}, env_values={})
