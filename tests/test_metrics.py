from __future__ import annotations

from attack_generator.metrics import Metrics


def test_metrics_snapshot() -> None:
    metrics = Metrics()
    metrics.observe_success("A1", "sqli", 200, "S1")
    metrics.observe_error("TimeoutError")
    metrics.sample_system()
    snapshot = metrics.json_snapshot()
    assert "attack_sent_total" in snapshot
    assert any(
        sample["labels"].get("attack_id") == "A1" for sample in snapshot["attack_sent_total"]
    )
    assert "errors_total" in snapshot
    assert "system_cpu_percent" in snapshot
    assert "system_mem_percent" in snapshot
