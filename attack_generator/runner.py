from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import random
import time
from dataclasses import dataclass
from itertools import cycle
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple, Union

import anyio
import httpx

from .metrics import Metrics
from .models import (
    AttackDefinition,
    AttackMap,
    AttackBodyType,
    RuntimeConfig,
    ScenarioDefinition,
)
from .pools import IPPool, UAPool, load_header_preset
from .rate_limiter import AsyncRateLimiter, compute_jitter
from .resolver import ResolverFactory, TemplateResolver
from .transport import AttackTransport, ResolvedRequest

LOGGER = logging.getLogger("attack_generator.runner")


@dataclass
class ExecutionEntry:
    attack: AttackDefinition
    scenario: Optional[ScenarioDefinition]
    ua_group: Optional[str]
    ip_pool_spec: Optional[str]
    headers: Optional[Union[str, Dict[str, str]]]
    jitter_ms: Optional[Tuple[int, int]]


class AttackRunner:
    """Coordinate attack execution for run/dry-run paths."""

    def __init__(
        self,
        attack_map: AttackMap,
        config: RuntimeConfig,
        *,
        metrics: Metrics,
        base_path: Optional[Path] = None,
        client=None,
    ) -> None:
        self._attack_map = attack_map
        self._config = config
        self._metrics = metrics
        self._base_path = base_path or Path(__file__).resolve().parent
        self._builtins_path = self._base_path / "builtins"
        self._rng = random.Random(config.seed)
        self._header_cache: Dict[str, Dict[str, str]] = {}
        self._plan = self._build_plan()
        if not self._plan:
            raise ValueError("attack map contains no executable attacks")
        self._ua_pool = UAPool.from_builtins(self._builtins_path, seed=config.seed)
        self._ip_pools: Dict[Optional[str], IPPool] = {}
        self._resolver_factory = ResolverFactory(attack_map, self._ua_pool)
        base_url = config.base_url_override or str(attack_map.target.base_url)
        self._transport = AttackTransport(attack_map, base_url=base_url, client=client)
        self._rate_limiter = AsyncRateLimiter(config.qps)
        think_time = attack_map.runtime.think_time_ms or (100, 1500)
        self._think_time = think_time
        self._stop_event = anyio.Event()
        self._running = False

    def _build_plan(self) -> List[ExecutionEntry]:
        entries: List[ExecutionEntry] = []
        attacks = self._attack_map.attacks
        if self._attack_map.scenarios:
            for scenario in self._attack_map.scenarios:
                selected = [attack for attack in attacks if scenario.select.matches(attack)]
                for attack in selected:
                    entries.append(
                        ExecutionEntry(
                            attack=attack,
                            scenario=scenario,
                            ua_group=scenario.ua_group,
                            ip_pool_spec=scenario.ip_pool,
                            headers=scenario.headers,
                            jitter_ms=scenario.jitter_ms,
                        )
                    )
        else:
            for attack in attacks:
                entries.append(
                    ExecutionEntry(
                        attack=attack,
                        scenario=None,
                        ua_group=None,
                        ip_pool_spec=None,
                        headers=None,
                        jitter_ms=None,
                    )
                )
        return entries

    def _get_ip_pool(self, spec: Optional[str]) -> IPPool:
        key = spec or "__default__"
        if key in self._ip_pools:
            return self._ip_pools[key]
        seed_offset = int(hashlib.sha256(key.encode()).hexdigest()[:8], 16)
        base_seed = (self._config.seed or 0) + seed_offset
        selected_spec = spec if spec not in {None, "__default__"} else self._config.ip_pool
        pool = IPPool(selected_spec, seed=base_seed, base_path=self._base_path)
        self._ip_pools[key] = pool
        return pool

    def _load_header_preset(self, name: str) -> Dict[str, str]:
        if name == "auto":
            raise ValueError("auto preset should be resolved before loading")
        if name not in self._header_cache:
            self._header_cache[name] = load_header_preset(self._builtins_path, name)
        return dict(self._header_cache[name])

    def _resolve_headers(
        self,
        *,
        base_headers: Optional[Union[str, Dict[str, str]]],
        attack: AttackDefinition,
        scenario_headers: Optional[Union[str, Dict[str, str]]],
        attack_headers: Optional[Union[str, Dict[str, str]]],
        resolver: TemplateResolver,
        state: Dict[str, str],
        extra: Dict[str, str],
        ua: str,
        ip: str,
    ) -> Dict[str, str]:
        headers: Dict[str, str] = {}

        def merge(source: Optional[Union[str, Dict[str, str]]]) -> None:
            if not source:
                return
            preset_name: Optional[str] = None
            if isinstance(source, str):
                if source == "auto":
                    preset_name = (
                        "builtin.headers.web_html_v1"
                        if attack.traffic_type == "web"
                        else "builtin.headers.api_json_v1"
                    )
                else:
                    preset_name = source
            if preset_name:
                preset_headers = self._load_header_preset(preset_name)
                merge(preset_headers)
                return
            if isinstance(source, dict):
                for key, value in source.items():
                    resolved_value = resolver.resolve(value, state=state, extra=extra)
                    headers[key] = resolved_value

        map_headers = base_headers
        if map_headers == "auto":
            map_headers = "builtin.headers.web_html_v1" if attack.traffic_type == "web" else "builtin.headers.api_json_v1"
        merge(map_headers)
        merge(scenario_headers)
        merge(attack_headers)
        headers.setdefault("User-Agent", ua)
        headers[self._config.xff] = ip
        return headers

    def _resolve_request(
        self,
        entry: ExecutionEntry,
        resolver: TemplateResolver,
        *,
        ip: str,
        ua: str,
    ) -> ResolvedRequest:
        state: Dict[str, str] = {}
        extra = {"ua_group": entry.ua_group or self._config.ua_group, "ip": ip, "ua": ua}
        path = resolver.resolve(entry.attack.path, state=state, extra=extra)
        url = self._transport.absolute_url(path)
        headers = self._resolve_headers(
            base_headers=self._attack_map.presets.headers if self._attack_map.presets else None,
            attack=entry.attack,
            scenario_headers=entry.headers,
            attack_headers=entry.attack.headers,
            resolver=resolver,
            state=state,
            extra=extra,
            ua=ua,
            ip=ip,
        )
        json_body = None
        data = None
        content = None
        if entry.attack.body is not None:
            body = resolver.resolve(entry.attack.body, state=state, extra=extra)
            if entry.attack.body_type == AttackBodyType.JSON:
                json_body = body
            elif entry.attack.body_type == AttackBodyType.FORM:
                data = body
            else:
                content = body.encode() if isinstance(body, str) else body
        return ResolvedRequest(
            attack=entry.attack,
            method=entry.attack.method,
            url=url,
            headers=headers,
            json_body=json_body,
            data=data,
            content=content,
            scenario_id=entry.scenario.id if entry.scenario else None,
            ip=ip,
            ua=ua,
        )

    async def dry_run(self, *, count: int) -> List[Dict[str, str]]:
        resolver = self._resolver_factory.create(seed=self._config.seed)
        ip_pool = self._get_ip_pool(None)
        results: List[Dict[str, str]] = []
        plan_cycle = cycle(self._plan)
        for _ in range(count):
            entry = next(plan_cycle)
            ip = ip_pool.pick()
            ua = self._ua_pool.pick(entry.ua_group or self._config.ua_group)
            request = self._resolve_request(entry, resolver, ip=ip, ua=ua)
            results.append(
                {
                    "method": request.method,
                    "url": request.url,
                    "headers": json.dumps(request.headers, sort_keys=True),
                }
            )
        return results

    async def run(self) -> None:
        await self._transport.startup()
        audit = self._build_audit_banner()
        LOGGER.info("audit", extra=audit)
        self._running = True
        try:
            async with anyio.create_task_group() as tg:
                for worker_id in range(self._config.concurrency):
                    seed = (self._config.seed or 0) + worker_id
                    tg.start_soon(self._worker, worker_id, seed)
        finally:
            self._running = False

    async def _worker(self, worker_id: int, seed: int) -> None:
        resolver = self._resolver_factory.create(seed=seed)
        plan_iter = cycle(self._plan)
        rng = random.Random(seed)
        while not self._stop_event.is_set():
            entry = next(plan_iter)
            ip_pool = self._get_ip_pool(entry.ip_pool_spec)
            ip = ip_pool.pick()
            ua = self._ua_pool.pick(entry.ua_group or self._config.ua_group)
            try:
                await self._rate_limiter.acquire()
                request = self._resolve_request(entry, resolver, ip=ip, ua=ua)
                start = time.monotonic()
                response = await self._transport.send(request)
                latency_ms = (time.monotonic() - start) * 1000.0
                self._metrics.observe_success(request.attack.id, request.attack.category, response.status_code, request.scenario_id)
                self._log_success(request, response.status_code, latency_ms)
            except Exception as exc:  # pragma: no cover - network edge
                self._metrics.observe_error(type(exc).__name__)
                self._log_error(request.attack if 'request' in locals() else entry.attack, exc, entry.scenario)
            delay = compute_jitter(entry.jitter_ms or self._think_time, rng=rng)
            if delay:
                await anyio.sleep(delay)

    def _log_success(self, request: ResolvedRequest, status_code: int, latency_ms: float) -> None:
        LOGGER.info(
            "attack_sent",
            extra={
                "attack_id": request.attack.id,
                "scenario_id": request.scenario_id,
                "method": request.method,
                "url": request.url,
                "ip": request.ip,
                "ua": request.ua,
                "status_code": status_code,
                "latency_ms": round(latency_ms, 2),
            },
        )

    def _log_error(self, attack: AttackDefinition, exc: Exception, scenario: Optional[ScenarioDefinition]) -> None:
        LOGGER.error(
            "attack_error",
            extra={
                "attack_id": attack.id,
                "scenario_id": scenario.id if scenario else None,
                "error": type(exc).__name__,
                "message": str(exc),
            },
        )

    def _build_audit_banner(self) -> Dict[str, str]:
        serialized = json.dumps(self._attack_map.describe(), sort_keys=True).encode()
        digest = hashlib.sha256(serialized).hexdigest()
        return {
            "banner": self._attack_map.safety.banner or "Authorized Radware demo targets only.",
            "attackmap_hash": digest,
            "allowlist": ",".join(self._config.allowlist),
        }

    async def stop(self) -> None:
        self._stop_event.set()
        await self._transport.shutdown()

    def is_running(self) -> bool:
        return self._running and not self._stop_event.is_set()


def ensure_allowlist(base_url: str, allowlist: Iterable[str]) -> bool:
    hostname = httpx.URL(base_url).host
    if not hostname:
        return False
    return any(fnmatch.fnmatch(hostname, pattern) for pattern in allowlist)


__all__ = ["AttackRunner", "ensure_allowlist"]
