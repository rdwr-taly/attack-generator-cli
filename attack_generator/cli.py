from __future__ import annotations

import json
import logging
import os
import signal
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from importlib import metadata
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlparse

import anyio
import anyio.abc
import httpx
import typer
from jsonschema import Draft7Validator
from pydantic import ValidationError

from .metrics import Metrics, start_metrics_server
from .models import AttackMap, ConfigError, LogFormat, RuntimeConfig, resolve_runtime_config
from .pools import BUILTIN_HEADER_FILES, BUILTIN_UA_FILES, UAPool
from .runner import AttackRunner, ensure_allowlist

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
    attackmap: Optional[str]
    allowlist: Optional[List[str]]
    base_url: Optional[str]
    qps: Optional[int]
    concurrency: Optional[int]
    xff: Optional[str]
    ip_pool: Optional[str]
    ua_group: Optional[str]
    metrics_port: Optional[int]
    log_format: Optional[str]
    seed: Optional[int]
    unsafe_override: bool
    acknowledge_override: bool
    server: bool
    operator: Optional[str]


class RunnerManager:
    """Coordinate AttackRunner lifecycle when operating in server mode."""

    def __init__(
        self,
        *,
        metrics: Metrics,
        base_path: Path,
        env_values: Dict[str, Any],
        cli_defaults: Dict[str, Any],
        task_group: anyio.abc.TaskGroup,
        client_factory: Optional[Callable[[], httpx.AsyncClient]] = None,
    ) -> None:
        self._metrics = metrics
        self._base_path = base_path
        self._env_values = env_values
        self._cli_defaults = dict(cli_defaults)
        self._cli_defaults.setdefault("server", True)
        self._tg = task_group
        self._client_factory = client_factory
        self._runner: AttackRunner | None = None
        self._current_config: RuntimeConfig | None = None
        self._current_attackmap: AttackMap | None = None
        self._current_payload: Dict[str, Any] | None = None
        self._metrics_started = False
        self._lock = anyio.Lock()

    def is_running(self) -> bool:
        return self._runner is not None and self._runner.is_running()

    async def start(
        self,
        *,
        attackmap_payload: Optional[Dict[str, Any]],
        override_config: Optional[Dict[str, Any]] = None,
    ) -> RuntimeConfig:
        async with self._lock:
            payload = attackmap_payload or self._current_payload
            if payload is None:
                raise ConfigError("attackmap payload is required to start the runner")
            errors, attack_map = _validate_attackmap_dict(payload)
            if errors:
                raise AttackMapValidationError(errors)

            overrides = dict(override_config or {})
            cli_values = dict(self._cli_defaults)
            cli_values.update({key: value for key, value in overrides.items() if value is not None})

            config = resolve_runtime_config(
                attack_map=attack_map,
                cli_values=cli_values,
                env_values=self._env_values,
            )

            base_url = config.base_url_override or str(attack_map.target.base_url)
            if not ensure_allowlist(base_url, config.allowlist):
                msg = "Target base URL not covered by allowlist"
                raise ConfigError(msg)

            if not self._metrics_started and config.metrics_port and not config.server_enabled:
                start_metrics_server(config.metrics_port, self._metrics.registry)
                self._metrics_started = True

            if self._runner is not None:
                await self._runner.stop()

            runner = AttackRunner(
                attack_map,
                config,
                metrics=self._metrics,
                base_path=self._base_path,
                client_factory=self._client_factory,
            )
            self._runner = runner
            self._current_config = config
            self._current_attackmap = attack_map
            self._current_payload = payload
            self._tg.start_soon(runner.run)
            return config

    async def stop(self) -> None:
        async with self._lock:
            if self._runner is None:
                return
            await self._runner.stop()
            self._runner = None

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
    return _parse_attackmap_source(raw)


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


def _pointer(parts: Iterable[Any]) -> str:
    tokens = [str(part) for part in parts]
    pointer = "/" + "/".join(tokens)
    return pointer if pointer != "/" else "/"


class AttackMapValidationError(RuntimeError):
    """Raised when schema or model validation fails."""

    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _friendly_error_from_schema(error) -> str:
    pointer = _pointer(error.path)
    if error.validator == "enum":
        allowed = ",".join(str(value) for value in error.validator_value)
        message = f"expected one of [{allowed}]"
    elif error.validator == "type":
        expected = error.validator_value
        message = f"expected type {expected}"
    elif error.validator == "required":
        missing = ",".join(sorted(error.validator_value))
        message = f"missing required properties [{missing}]"
    else:
        message = error.message
    return f"{pointer}: {message}"


def _friendly_error_from_model(error: Dict[str, Any]) -> str:
    pointer = _pointer(error.get("loc", []))
    message = error.get("msg", "invalid value")
    return f"{pointer}: {message}"


def _validate_attackmap_dict(data: Dict[str, Any]) -> tuple[List[str], Optional[AttackMap]]:
    validator = _schema_validator()
    schema_errors = sorted(validator.iter_errors(data), key=lambda err: list(err.path))
    errors = [_friendly_error_from_schema(error) for error in schema_errors]
    if schema_errors:
        return errors, None
    try:
        attack_map = AttackMap.model_validate(data)
    except ValidationError as exc:
        model_errors = [_friendly_error_from_model(item) for item in exc.errors()]
        return model_errors, None
    return [], attack_map


def _parse_attackmap_source(raw: str) -> AttackMap:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - handled in validate tests
        raise AttackMapValidationError(["/: invalid JSON: %s" % exc.msg]) from exc

    errors, attack_map = _validate_attackmap_dict(data)
    if errors:
        raise AttackMapValidationError(errors)
    return attack_map


@app.command()
def validate(file: str) -> None:
    """Validate an AttackMap file against the schema."""

    try:
        content = _load_attackmap_json(file)
    except json.JSONDecodeError as exc:
        typer.echo(f"/: invalid JSON: {exc.msg}")
        raise typer.Exit(code=1) from exc
    except httpx.HTTPError as exc:
        typer.echo(f"error fetching AttackMap: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    errors, _ = _validate_attackmap_dict(content)
    if errors:
        for message in errors:
            typer.echo(message)
        raise typer.Exit(code=1)
    typer.echo("valid")


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
    env_values = _env_values()
    cli_values = _build_cli_values(options)
    log_format_value = cli_values.get("log_format") or env_values.get("log_format") or LogFormat.JSON.value
    configure_logging(LogFormat(log_format_value))
    metrics = Metrics()

    if not options.server:
        if not options.attackmap:
            typer.echo("--attackmap is required in non-server mode", err=True)
            raise typer.Exit(code=2)
        attack_map = await load_attack_map(options.attackmap)
        config = resolve_runtime_config(attack_map=attack_map, cli_values=cli_values, env_values=env_values)
        if options.base_url:
            config.base_url_override = options.base_url
        base_url = config.base_url_override or str(attack_map.target.base_url)
        if not ensure_allowlist(base_url, config.allowlist):
            typer.echo("Target base URL not covered by allowlist", err=True)
            raise typer.Exit(code=1)
        if config.metrics_port and not config.server_enabled:
            start_metrics_server(config.metrics_port, metrics.registry)
        runner = AttackRunner(attack_map, config, metrics=metrics, base_path=BASE_PATH)

        async def _watch_signals() -> None:
            try:
                with anyio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as signals:
                    async for _ in signals:
                        await runner.stop()
                        break
            except (NotImplementedError, RuntimeError):  # pragma: no cover - platform guard
                return

        try:
            async with anyio.create_task_group() as tg:
                shutdown_event = anyio.Event()

                async def _signal_task() -> None:
                    await _watch_signals()
                    shutdown_event.set()

                tg.start_soon(_signal_task)
                tg.start_soon(runner.run)
                await shutdown_event.wait()
        except KeyboardInterrupt:
            await runner.stop()
            raise
        return

    # ── ShowRunner (server) mode ──
    from showrunner_sdk import config as sr_config, metrics as sr_metrics, health as sr_health

    try:
        dist_version = metadata.version("attack-generator")
    except metadata.PackageNotFoundError:
        dist_version = "0.0.0-dev"

    cfg = sr_config.load()
    sr_metrics.set_app_info(name="attack-generator", version=dist_version)
    sr_metrics.start_server()  # port 9090

    cli_values.setdefault("server", True)
    shutdown_event = anyio.Event()

    async with anyio.create_task_group() as tg:
        manager = RunnerManager(
            metrics=metrics,
            base_path=BASE_PATH,
            env_values=env_values,
            cli_defaults=cli_values,
            task_group=tg,
        )

        async def _watch_signals_server() -> None:
            try:
                with anyio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as signals:
                    async for _ in signals:
                        await manager.stop()
                        sr_health.set_status("stopped")
                        shutdown_event.set()
                        break
            except (NotImplementedError, RuntimeError):  # pragma: no cover - platform guard
                return

        tg.start_soon(_watch_signals_server)

        # Start attack from config file (/config/app.json)
        attackmap_payload = cfg.get("attackmap") if cfg else None
        override_config = cfg.get("config") if cfg else None

        # Allow --attackmap CLI flag to override config file
        if options.attackmap:
            try:
                raw = await _read_attackmap_source(options.attackmap)
                attackmap_payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                typer.echo(f"/: invalid JSON: {exc.msg}", err=True)
                raise typer.Exit(code=1) from exc

        if attackmap_payload:
            try:
                await manager.start(
                    attackmap_payload=attackmap_payload,
                    override_config=override_config,
                )
                sr_health.set_status("running")
            except AttackMapValidationError as exc:
                for message in exc.errors:
                    typer.echo(message, err=True)
                raise typer.Exit(code=1)
            except ConfigError as exc:
                typer.echo(str(exc), err=True)
                raise typer.Exit(code=1)
        else:
            LOGGER.info("No attackmap in config — waiting for config reload via SIGHUP")
            sr_health.set_status("running")

        # Register SIGHUP reload callback (config reloaded automatically by SDK)
        def _on_config_reload(new_cfg: Dict[str, Any]) -> None:
            LOGGER.info("Config reloaded (%d keys) — will apply on next container restart",
                        len(new_cfg))

        sr_config.on_reload(_on_config_reload)

        try:
            await shutdown_event.wait()
        finally:
            await manager.stop()
            sr_health.set_status("stopped")
            tg.cancel_scope.cancel()



@app.command()
def run(
    attackmap: Optional[str] = typer.Option(
        None, help="Path or URL to the AttackMap (required unless --server)", show_default=False
    ),
    allowlist: Optional[str] = typer.Option(None, help="Domain allowlist (comma-separated)"),
    base_url: Optional[str] = typer.Option(None, help="Override base URL"),
    qps: Optional[int] = typer.Option(None, help="Global QPS cap (default 5; capped by map)"),
    concurrency: Optional[int] = typer.Option(None, help="Concurrency level (default 20)"),
    xff: Optional[str] = typer.Option(None, help="Forwarded header name (default client-ip)"),
    ip_pool: Optional[str] = typer.Option(None, help="IP pool selector"),
    ua_group: Optional[str] = typer.Option(None, help="UA group override"),
    metrics_port: Optional[int] = typer.Option(
        None, help="Metrics/Server port (default 9102; 0 disables)", show_default=False
    ),
    log_format: Optional[str] = typer.Option(
        None, help="Log format (json or text; default json)", show_default=False
    ),
    seed: Optional[int] = typer.Option(None, help="Deterministic seed"),
    unsafe_override: bool = typer.Option(False, help="Enable unsafe overrides"),
    i_know_what_im_doing: bool = typer.Option(False, help="Confirm unsafe override"),
    server: bool = typer.Option(False, help="Enable ShowRunner managed mode"),
    operator: Optional[str] = typer.Option(None, help="Operator name for audit banner"),
) -> None:
    if not server and not attackmap:
        typer.echo("--attackmap is required unless --server is enabled", err=True)
        raise typer.Exit(code=2)
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
        log_format=LogFormat.JSON.value,
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
