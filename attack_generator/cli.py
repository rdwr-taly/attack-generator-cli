from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass
from functools import lru_cache
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import anyio
import httpx
import typer
from jsonschema import Draft7Validator

from .integrations import container_control_adapter
from .metrics import Metrics, start_metrics_server
from .models import (
    AttackMap,
    ConfigError,
    LogFormat,
    RuntimeConfig,
    resolve_runtime_config,
)
from .pools import BUILTIN_HEADER_FILES, BUILTIN_UA_FILES, UAPool
from .runner import AttackRunner, ensure_allowlist
from .server import ControlServer

APP_NAME = "attack-generator"
app = typer.Typer(add_completion=False)

LOGGER = logging.getLogger("attack_generator.cli")
BASE_PATH = Path(__file__).resolve().parent


class JsonFormatter(logging.Formatter):
    """Minimal JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload = {
            "timestamp": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key.startswith("_"):
                continue
            if key in payload or key in {"msg", "args", "exc_info", "exc_text"}:
                continue
            if key == "password" or key.endswith("_password"):
                payload[key] = "<redacted>"
            else:
                payload[key] = value
        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info)
        return json.dumps(payload)


@dataclass
class RunOptions:
    attackmap: str
    allowlist: Optional[List[str]]
    base_url: Optional[str]
    qps: Optional[int]
    concurrency: Optional[int]
    xff: Optional[str]
    ip_pool: Optional[str]
    ua_group: Optional[str]
    metrics_port: Optional[int]
    log_format: str
    seed: Optional[int]
    unsafe_override: bool
    acknowledge_override: bool
    server: bool
    operator: Optional[str]


def configure_logging(fmt: LogFormat) -> None:
    logging.basicConfig(level=logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    if fmt == LogFormat.JSON:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)


async def _read_attackmap_source(source: str) -> str:
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https"}:
        async with httpx.AsyncClient() as client:
            response = await client.get(source)
            response.raise_for_status()
            return response.text
    path = Path(source)
    data = await anyio.Path(path).read_text()
    return data


async def load_attack_map(path_or_url: str) -> AttackMap:
    raw = await _read_attackmap_source(path_or_url)
    return AttackMap.model_validate_json(raw)


def _parse_allowlist(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _env_values() -> Dict[str, Any]:
    env = os.environ
    return {
        "allowlist": _parse_allowlist(env.get("AG_ALLOWLIST")),
        "qps": int(env["AG_QPS"]) if env.get("AG_QPS") else None,
        "concurrency": int(env["AG_CONCURRENCY"]) if env.get("AG_CONCURRENCY") else None,
        "xff": env.get("AG_XFF"),
        "ip_pool": env.get("AG_IP_POOL"),
        "ua_group": env.get("AG_UA_GROUP"),
        "metrics_port": int(env["AG_METRICS_PORT"]) if env.get("AG_METRICS_PORT") else None,
        "log_format": env.get("AG_LOG_FORMAT"),
        "seed": int(env["AG_SEED"]) if env.get("AG_SEED") else None,
        "unsafe_override": env.get("AG_UNSAFE_OVERRIDE") in {"1", "true", "True"},
        "base_url": env.get("AG_BASE_URL"),
        "operator": env.get("AG_OPERATOR"),
    }


@lru_cache(maxsize=1)
def _schema_validator() -> Draft7Validator:
    schema_path = BASE_PATH.parent / "schemas" / "attackmap.schema.json"
    with schema_path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    return Draft7Validator(schema)


def _load_attackmap_json(path_or_url: str) -> Dict[str, Any]:
    parsed = urlparse(path_or_url)
    if parsed.scheme in {"http", "https"}:
        response = httpx.get(path_or_url, timeout=10.0)
        response.raise_for_status()
        return response.json()
    with open(path_or_url, "r", encoding="utf-8") as handle:
        return json.load(handle)


@app.command()
def validate(file: str) -> None:
    """Validate an AttackMap file against the schema."""

    content = _load_attackmap_json(file)
    validator = _schema_validator()
    errors = sorted(validator.iter_errors(content), key=lambda e: e.path)
    if errors:
        for error in errors:
            pointer = "/" + "/".join(str(part) for part in error.path)
            typer.echo(f"{pointer or '/'}: {error.message}")
        raise typer.Exit(code=1)
    typer.echo("AttackMap valid")


def _build_cli_values(options: RunOptions) -> Dict[str, Any]:
    cli_values: Dict[str, Any] = {
        "allowlist": options.allowlist,
        "qps": options.qps,
        "concurrency": options.concurrency,
        "xff": options.xff,
        "ip_pool": options.ip_pool,
        "ua_group": options.ua_group,
        "metrics_port": options.metrics_port,
        "log_format": options.log_format,
        "seed": options.seed,
        "unsafe_override": options.unsafe_override,
        "base_url": options.base_url,
        "operator": options.operator,
        "server": options.server,
    }
    return {key: value for key, value in cli_values.items() if value is not None}


async def _run_async(options: RunOptions) -> None:
    if options.unsafe_override and not options.acknowledge_override:
        raise typer.Exit(code=2)
    attack_map = await load_attack_map(options.attackmap)
    env_values = _env_values()
    cli_values = _build_cli_values(options)
    config = resolve_runtime_config(attack_map=attack_map, cli_values=cli_values, env_values=env_values)
    if options.base_url:
        config.base_url_override = options.base_url
    configure_logging(config.log_format)
    base_url = config.base_url_override or str(attack_map.target.base_url)
    if not ensure_allowlist(base_url, config.allowlist):
        typer.echo("Target base URL not covered by allowlist", err=True)
        raise typer.Exit(code=1)
    metrics = Metrics()
    if not options.server and config.metrics_port:
        start_metrics_server(config.metrics_port, metrics.registry)
    runner = AttackRunner(attack_map, config, metrics=metrics, base_path=BASE_PATH)

    async def _health() -> Dict[str, Any]:
        return {"status": "running" if runner.is_running() else "stopped"}

    async def _start_endpoint(payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "running"}

    async def _stop_endpoint() -> None:
        await runner.stop()

    try:
        if options.server:
            if not container_control_adapter.available():
                typer.echo("container-control not installed; control server disabled", err=True)
                raise typer.Exit(code=1)
            port = config.metrics_port or 9102
            control_server = ControlServer(
                port=port,
                on_start=_start_endpoint,
                on_stop=_stop_endpoint,
                health_probe=_health,
                metrics=metrics,
            )
            async with anyio.create_task_group() as tg:
                tg.start_soon(control_server.run)
                await runner.run()
                await control_server.stop()
        else:
            await runner.run()
    except KeyboardInterrupt:
        await runner.stop()
        raise


@app.command()
def run(
    attackmap: str = typer.Option(..., help="Path or URL to the AttackMap"),
    allowlist: Optional[str] = typer.Option(None, help="Domain allowlist (comma-separated)"),
    base_url: Optional[str] = typer.Option(None, help="Override base URL"),
    qps: Optional[int] = typer.Option(None, help="Global QPS cap"),
    concurrency: Optional[int] = typer.Option(None, help="Concurrency level"),
    xff: Optional[str] = typer.Option(None, help="Forwarded header name"),
    ip_pool: Optional[str] = typer.Option(None, help="IP pool selector"),
    ua_group: Optional[str] = typer.Option(None, help="UA group override"),
    metrics_port: Optional[int] = typer.Option(9102, help="Metrics/Server port"),
    log_format: str = typer.Option("json", help="Log format"),
    seed: Optional[int] = typer.Option(None, help="Deterministic seed"),
    unsafe_override: bool = typer.Option(False, help="Enable unsafe overrides"),
    i_know_what_im_doing: bool = typer.Option(False, help="Confirm unsafe override"),
    server: bool = typer.Option(False, help="Enable container-control server"),
    operator: Optional[str] = typer.Option(None, help="Operator name for audit banner"),
) -> None:
    allowlist_values = _parse_allowlist(allowlist)
    options = RunOptions(
        attackmap=attackmap,
        allowlist=allowlist_values,
        base_url=base_url,
        qps=qps,
        concurrency=concurrency,
        xff=xff,
        ip_pool=ip_pool,
        ua_group=ua_group,
        metrics_port=metrics_port,
        log_format=log_format,
        seed=seed,
        unsafe_override=unsafe_override,
        acknowledge_override=i_know_what_im_doing,
        server=server,
        operator=operator,
    )
    try:
        anyio.run(_run_async, options)
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except KeyboardInterrupt:
        typer.echo("Interrupted", err=True)


@app.command()
def dry_run(
    file: str,
    dry_run: int = typer.Option(..., help="Number of requests to render"),
    seed: Optional[int] = typer.Option(None, help="Deterministic seed"),
) -> None:
    attack_map = anyio.run(load_attack_map, file)
    options = RunOptions(
        attackmap=file,
        allowlist=None,
        base_url=None,
        qps=attack_map.safety.global_rps_cap,
        concurrency=attack_map.runtime.concurrency,
        xff=None,
        ip_pool=None,
        ua_group=None,
        metrics_port=0,
        log_format="json",
        seed=seed,
        unsafe_override=False,
        acknowledge_override=False,
        server=False,
        operator=None,
    )
    env_values = _env_values()
    cli_values = _build_cli_values(options)
    config = resolve_runtime_config(attack_map=attack_map, cli_values=cli_values, env_values=env_values)
    runner = AttackRunner(attack_map, config, metrics=Metrics(), base_path=BASE_PATH)
    sample = anyio.run(runner.dry_run, count=dry_run)
    for entry in sample:
        typer.echo(f"{entry['method']} {entry['url']} {entry['headers']}")


@app.command("list-builtins")
def list_builtins() -> None:
    base = BASE_PATH / "builtins"
    ua_pool = UAPool.from_builtins(base)
    typer.echo("User-Agent groups:")
    for group in BUILTIN_UA_FILES:
        typer.echo(f"  {group}: {ua_pool.size(group)} entries")
    typer.echo("Header presets:")
    for preset, filename in BUILTIN_HEADER_FILES.items():
        path = base / filename
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        typer.echo(f"  {preset}: {len(data)} headers")


@app.command()
def version() -> None:
    try:
        dist_version = metadata.version("attack-generator")
    except metadata.PackageNotFoundError:
        dist_version = "0.0.0-dev"
    typer.echo(dist_version)


if __name__ == "__main__":
    app()
