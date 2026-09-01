from __future__ import annotations

import json

from attack_generator.metrics import Metrics
from attack_generator.report import build_report, responses_by_code, write_report


def _metrics_with_traffic() -> Metrics:
    metrics = Metrics()
    for _ in range(100):
        metrics.observe_success("A1", "flood", 200, "S1")
    for _ in range(50):
        metrics.observe_success("A1", "flood", 403, "S1")  # WAF blocked
    for _ in range(10):
        metrics.observe_success("A1", "flood", 429, "S1")  # rate limited
    return metrics


def test_responses_by_code_reads_registry() -> None:
    counts = responses_by_code(_metrics_with_traffic())
    assert counts == {"200": 100, "403": 50, "429": 10}


def test_build_report_measures_and_block_ratio() -> None:
    report = build_report(_metrics_with_traffic())
    assert report["schema_version"] == 1
    assert report["status"] == "final"
    m = report["measures"]
    assert m["responses.by_code"] == {"200": 100, "403": 50, "429": 10}
    assert m["responses.total"] == 160
    assert m["responses.blocked"] == 60  # 403 + 429
    assert m["responses.block_ratio"] == 0.375
    assert "block ratio" in report["summary"]


def test_build_report_no_traffic() -> None:
    report = build_report(Metrics())
    assert report["measures"]["responses.total"] == 0
    assert report["measures"]["responses.block_ratio"] == 0.0
    assert report["status"] == "final"


def test_write_report_atomic_and_final(tmp_path) -> None:
    target = tmp_path / "report" / "report.json"
    ok = write_report(_metrics_with_traffic(), str(target))
    assert ok is True
    assert target.exists()
    # no leftover tmp file
    assert not (tmp_path / "report" / "report.json.tmp").exists()
    data = json.loads(target.read_text())
    assert data["status"] == "final"
    assert data["measures"]["responses.by_code"]["403"] == 50


def test_write_report_unwritable_path_degrades() -> None:
    # A path under a file (not a dir) can't be created -> returns False, no raise.
    assert write_report(Metrics(), "/dev/null/nope/report.json") is False
