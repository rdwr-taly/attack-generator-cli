from __future__ import annotations

import time
from typing import Any, Dict, List

from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest, start_http_server


class Metrics:
    """Prometheus-backed metrics helper."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.attack_rps = Gauge("attack_rps", "Current attack rate", registry=self.registry)
        self.attack_sent_total = Counter(
            "attack_sent_total",
            "Total attacks dispatched",
            ["attack_id", "category"],
            registry=self.registry,
        )
        self.http_status_total = Counter(
            "http_status_total",
            "HTTP responses by status code",
            ["code"],
            registry=self.registry,
        )
        self.scenario_sent_total = Counter(
            "scenario_sent_total",
            "Scenario dispatch count",
            ["scenario_id"],
            registry=self.registry,
        )
        self.errors_total = Counter(
            "errors_total",
            "Errors by type",
            ["type"],
            registry=self.registry,
        )
        self.system_cpu_percent = Gauge(
            "system_cpu_percent",
            "Process CPU percent placeholder",
            registry=self.registry,
        )
        self.system_mem_percent = Gauge(
            "system_mem_percent",
            "Process memory percent placeholder",
            registry=self.registry,
        )
        self._window_count = 0
        self._window_start = time.monotonic()

    def observe_success(self, attack_id: str, category: str, status_code: int, scenario_id: str | None) -> None:
        self.attack_sent_total.labels(attack_id=attack_id, category=category).inc()
        self.http_status_total.labels(code=str(status_code)).inc()
        if scenario_id:
            self.scenario_sent_total.labels(scenario_id=scenario_id).inc()
        self._record_rps()

    def observe_error(self, error_type: str) -> None:
        self.errors_total.labels(type=error_type).inc()
        self._record_rps()

    def _record_rps(self) -> None:
        self._window_count += 1
        now = time.monotonic()
        elapsed = now - self._window_start
        if elapsed >= 1.0:
            rps = self._window_count / elapsed
            self.attack_rps.set(rps)
            self._window_count = 0
            self._window_start = now

    def json_snapshot(self) -> Dict[str, Any]:
        snapshot: Dict[str, Any] = {}
        for metric in self.registry.collect():
            samples: List[Dict[str, Any]] = []
            for sample in metric.samples:
                samples.append(
                    {
                        "name": sample.name,
                        "labels": sample.labels,
                        "value": sample.value,
                    }
                )
            snapshot[metric.name] = samples
        return snapshot


def start_metrics_server(port: int, registry: CollectorRegistry) -> None:
    if port <= 0:
        return
    start_http_server(port=port, registry=registry)


__all__ = ["Metrics", "start_metrics_server"]
