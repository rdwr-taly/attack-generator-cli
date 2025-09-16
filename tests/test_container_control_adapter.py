from __future__ import annotations

import sys

import httpx
import pytest
from prometheus_client import CollectorRegistry

from attack_generator.integrations import container_control_adapter

pytestmark = pytest.mark.anyio("asyncio")


def test_adapter_unavailable(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "container_control", None)
    monkeypatch.setitem(sys.modules, "fastapi", None)
    assert not container_control_adapter.available()


async def test_mount_and_routes() -> None:
    if not container_control_adapter.available():
        pytest.skip("container-control stack not installed")

    from fastapi import FastAPI

    app = FastAPI()
    calls = {}

    async def on_start(payload):
        calls["start"] = payload
        return {"status": "started"}

    async def on_stop():
        calls["stop"] = True

    async def health_probe():
        return {"status": "running"}

    registry = CollectorRegistry()
    container_control_adapter.mount_http(
        app,
        on_start=on_start,
        on_stop=on_stop,
        health_probe=health_probe,
        prometheus_registry=registry,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/start", json={"attackmap": {}, "config": {}})
        assert resp.status_code == 200
        await client.post("/api/stop")
        resp = await client.get("/api/health")
        assert resp.json()["status"] == "running"
        resp = await client.get("/metrics")
        assert resp.status_code == 200
    await transport.aclose()

    assert "start" in calls
    assert "stop" in calls
