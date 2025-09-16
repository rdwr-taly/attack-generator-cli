"""Adapter around the optional container-control package.

This module centralises all interactions with :mod:`container_control` so the
rest of the codebase can treat it as an optional dependency.  When available,
we reuse its FastAPI integration helpers to mount a consistent control surface
with `/api/start`, `/api/stop`, `/api/health`, and `/api/metrics` endpoints.

The adapter intentionally keeps the interface tiny so callers can stub it out
in unit tests.  When :mod:`container_control` is missing (which is common in
local development), the helper simply reports ``available() -> False`` and all
functions become no-ops.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict

from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest

StartHandler = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]
StopHandler = Callable[[], Awaitable[None]]
HealthHandler = Callable[[], Awaitable[Dict[str, Any]]]


def available() -> bool:
    try:
        import container_control  # noqa: F401
        import fastapi  # noqa: F401
    except ImportError:
        return False
    return True


def mount_http(
    app: Any,
    *,
    on_start: StartHandler,
    on_stop: StopHandler,
    health_probe: HealthHandler,
    prometheus_registry: CollectorRegistry,
) -> None:
    """Mount container-control endpoints on the provided FastAPI app."""

    if not available():  # pragma: no cover - defensive guard
        raise RuntimeError("container-control not available")

    from fastapi import APIRouter, HTTPException

    router = APIRouter()

    @router.post("/api/start")
    async def api_start(payload: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore[override]
        result = await on_start(payload)
        return result

    @router.post("/api/stop")
    async def api_stop() -> Dict[str, Any]:
        await on_stop()
        return {"status": "stopping"}

    @router.get("/api/health")
    async def api_health() -> Dict[str, Any]:
        return await health_probe()

    @router.get("/api/metrics")
    async def api_metrics() -> Dict[str, Any]:
        snapshot = {}
        for metric in prometheus_registry.collect():
            data_points = []
            for sample in metric.samples:
                data_points.append(
                    {
                        "name": sample.name,
                        "labels": sample.labels,
                        "value": sample.value,
                    }
                )
            snapshot[metric.name] = data_points
        return {"metrics": snapshot}

    app.include_router(router)

    expose_metrics(app, prometheus_registry)


def expose_metrics(app: Any, registry: CollectorRegistry) -> None:
    if not available():  # pragma: no cover - defensive guard
        return

    from fastapi import Response

    @app.get("/metrics")
    async def prometheus_metrics() -> Response:  # type: ignore[override]
        content = generate_latest(registry)
        return Response(content=content, media_type=CONTENT_TYPE_LATEST)


__all__ = ["available", "mount_http", "expose_metrics"]
