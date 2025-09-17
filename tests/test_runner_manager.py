from __future__ import annotations

import json
from typing import Any, Dict

import anyio
import httpx
import pytest

from attack_generator.cli import RunnerManager, BASE_PATH
from attack_generator.metrics import Metrics

BASE_MAP: Dict[str, Any] = {
    "version": 1,
    "name": "ServerTest",
    "target": {"base_url": "https://example.com", "xff_header": "client-ip"},
    "safety": {"allowlist": ["*.example.com", "example.com"], "global_rps_cap": 5, "stop_on_target_mismatch": True},
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
    "runtime": {"concurrency": 1, "think_time_ms": [50, 100]},
}


@pytest.mark.anyio
async def test_runner_manager_start_and_stop() -> None:
    calls: Dict[str, int] = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    metrics = Metrics()
    env_values: Dict[str, Any] = {}
    cli_defaults = {"metrics_port": 0, "server": True}

    async with anyio.create_task_group() as tg:
        manager = RunnerManager(
            metrics=metrics,
            base_path=BASE_PATH,
            env_values=env_values,
            cli_defaults=cli_defaults,
            task_group=tg,
            client_factory=lambda: httpx.AsyncClient(base_url="https://example.com", transport=transport),
        )
        config = await manager.start(attackmap_payload=json.loads(json.dumps(BASE_MAP)), override_config={})
        assert config.qps == 5
        await anyio.sleep(0.05)
        assert manager.is_running()
        await anyio.sleep(0.2)
        await manager.stop()
        assert not manager.is_running()
        tg.cancel_scope.cancel()

    snapshot = metrics.json_snapshot()
    assert "attack_sent_total" in snapshot
    assert calls["count"] > 0
