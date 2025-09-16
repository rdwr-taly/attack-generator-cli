from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional

import anyio

from .integrations import container_control_adapter
from .metrics import Metrics

LOGGER = logging.getLogger("attack_generator.server")


class ControlServer:
    """Wrapper that starts the container-control FastAPI app when available."""

    def __init__(
        self,
        *,
        port: int,
        on_start: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
        on_stop: Callable[[], Awaitable[None]],
        health_probe: Callable[[], Awaitable[Dict[str, Any]]],
        metrics: Metrics,
    ) -> None:
        if not container_control_adapter.available():
            raise RuntimeError("container-control not installed")
        from fastapi import FastAPI
        import uvicorn

        self._app = FastAPI()
        container_control_adapter.mount_http(
            self._app,
            on_start=on_start,
            on_stop=on_stop,
            health_probe=health_probe,
            prometheus_registry=metrics.registry,
        )
        self._server = uvicorn.Server(
            uvicorn.Config(self._app, host="0.0.0.0", port=port, log_level="info", loop="asyncio")
        )

    async def run(self) -> None:
        await self._server.serve()

    async def stop(self) -> None:
        self._server.should_exit = True


async def run_control_server(
    *,
    port: int,
    on_start: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
    on_stop: Callable[[], Awaitable[None]],
    health_probe: Callable[[], Awaitable[Dict[str, Any]]],
    metrics: Metrics,
) -> None:
    server = ControlServer(
        port=port,
        on_start=on_start,
        on_stop=on_stop,
        health_probe=health_probe,
        metrics=metrics,
    )
    await server.run()


__all__ = ["ControlServer", "run_control_server"]
