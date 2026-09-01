from __future__ import annotations

import time
from typing import Any, Dict, List


from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest, start_http_server

try:  # pragma: no cover - psutil is optional at runtime
    import psutil
except ImportError:  # pragma: no cover - fallback when psutil unavailable
    psutil = None


class Metrics:
    """Prometheus-backed metrics helper."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        if registry is not None:
            self.registry = registry
        else:
            # In ShowRunner (server) mode, use the SDK registry so all
            # app-specific metrics appear on the same /metrics endpoint.
            # In CLI mode the SDK is unused so fall back to a private registry.
            try:
                from showrunner_sdk import metrics as sr_metrics
                self.registry = sr_metrics.registry
            except ImportError:
                self.registry = CollectorRegistry()
        self.attack_rps = Gauge("attack_rps", "Current attack rate", registry=self.registry)
        self.attack_sent_counter = Counter(
            "attack_sent",
            "Total attacks dispatched",
            ["attack_id", "category"],
            registry=self.registry,
        )
        self.http_status_counter = Counter(
            "http_status",
            "HTTP responses by status code",
            ["code"],
            registry=self.registry,
        )
        self.scenario_sent_counter = Counter(
            "scenario_sent",
            "Scenario dispatch count",
            ["scenario_id"],
            registry=self.registry,
        )
        self.errors_counter = Counter(
            "errors",
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
        self.attack_sent_counter.labels(attack_id=attack_id, category=category).inc()
        self.http_status_counter.labels(code=str(status_code)).inc()
        if scenario_id:
            self.scenario_sent_counter.labels(scenario_id=scenario_id).inc()
        self._record_rps()

    def observe_error(self, error_type: str) -> None:
        self.errors_counter.labels(type=error_type).inc()
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

    def sample_system(self) -> None:
        """Populate CPU and memory gauges."""

        if psutil is not None:
            try:
                self.system_cpu_percent.set(float(psutil.cpu_percent(interval=None)))
                self.system_mem_percent.set(float(psutil.virtual_memory().percent))
                return
            except Exception:  # pragma: no cover - defensive guard when psutil misbehaves
                pass
        self.system_cpu_percent.set(0.0)
        self.system_mem_percent.set(0.0)

    def json_snapshot(self) -> Dict[str, Any]:
        snapshot: Dict[str, Any] = {}
        for metric in self.registry.collect():
            for sample in metric.samples:
                if sample.name.endswith("_created"):
                    continue
                snapshot.setdefault(sample.name, []).append(
                    {
                        "name": sample.name,
                        "labels": sample.labels,
                        "value": sample.value,
                    }
                )
        return snapshot


def start_metrics_server(port: int, registry: CollectorRegistry) -> None:
    if port <= 0:
        return
    start_http_server(port=port, registry=registry)


__all__ = ["Metrics", "start_metrics_server"]
