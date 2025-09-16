from __future__ import annotations

from attack_generator.metrics import Metrics


def test_metrics_snapshot() -> None:
    metrics = Metrics()
    metrics.observe_success("A1", "sqli", 200, "S1")
    metrics.observe_error("TimeoutError")
    snapshot = metrics.json_snapshot()
    assert "attack_sent" in snapshot
    assert any(sample["labels"].get("attack_id") == "A1" for sample in snapshot["attack_sent"])
    assert "errors" in snapshot
