from __future__ import annotations

from pathlib import Path

import pytest

from attack_generator.metrics import Metrics
from attack_generator.models import AttackMap, resolve_runtime_config
from attack_generator.runner import AttackRunner

BASE_DIR = Path(__file__).resolve().parent.parent
EXAMPLE = BASE_DIR / "examples" / "basic_injection_spray.json"

pytestmark = pytest.mark.anyio("asyncio")


async def test_dry_run_deterministic() -> None:
    attack_map = AttackMap.model_validate_json(EXAMPLE.read_text(encoding="utf-8"))
    config = resolve_runtime_config(
        attack_map=attack_map,
        cli_values={
            "allowlist": ["*.radware.net"],
            "qps": 5,
            "metrics_port": 0,
            "seed": 42,
        },
        env_values={},
    )
    metrics = Metrics()
    runner = AttackRunner(attack_map, config, metrics=metrics)
    sample_one = await runner.dry_run(count=3)
    runner_two = AttackRunner(attack_map, config, metrics=metrics)
    sample_two = await runner_two.dry_run(count=3)
    assert sample_one == sample_two
