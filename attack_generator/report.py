"""SR3 report writer — emit ``/report/report.json`` for ShowRunner to pull.

ShowRunner v3.0 pulls this file out of the container at window close (via the
Docker API) and projects its ``measures`` into the demo report + runbook. The
app declares this contract in its ``.showrunner/appspec.json`` ``sdk`` block, so
ShowRunner knows the path and what measures to expect.

Fully optional and non-fatal: if the path is not writable the run is unaffected
(ShowRunner simply degrades to Tier-0, i.e. Prometheus metrics + logs). The file
is written atomically (tmp + rename) with ``status: "final"`` so ShowRunner never
observes a half-written report.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

DEFAULT_REPORT_PATH = "/report/report.json"
# Codes an attack tool reads as "mitigated" (WAF block / rate-limit / shed).
_BLOCKED_CODES = {"403", "429", "503"}


def responses_by_code(metrics: Any) -> dict[str, int]:
    """Read the per-status-code response counts from the metrics registry."""
    counts: dict[str, int] = {}
    try:
        for metric in metrics.registry.collect():
            for sample in metric.samples:
                # prometheus_client renders a Counter named "http_status" as the
                # sample "http_status_total" carrying the {code=...} label.
                if sample.name == "http_status_total":
                    code = sample.labels.get("code")
                    if code:
                        counts[code] = counts.get(code, 0) + int(sample.value)
    except Exception:  # pragma: no cover - defensive; never break the run
        LOGGER.debug("Failed to read status counts from registry", exc_info=True)
    return counts


def build_report(metrics: Any) -> dict[str, Any]:
    """Build the SR3 report document from the current metrics."""
    by_code = responses_by_code(metrics)
    total = sum(by_code.values())
    blocked = sum(v for code, v in by_code.items() if code in _BLOCKED_CODES)
    block_ratio = round(blocked / total, 4) if total else 0.0
    summary = (
        f"Sent {total} request(s); {blocked} blocked/challenged ({block_ratio:.0%} block ratio)."
        if total
        else "No requests were sent."
    )
    return {
        "schema_version": 1,
        "status": "final",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "measures": {
            "responses.by_code": by_code,
            "responses.total": total,
            "responses.blocked": blocked,
            "responses.block_ratio": block_ratio,
        },
        "summary": summary,
    }


def write_report(metrics: Any, path: str | None = None) -> bool:
    """Atomically write the SR3 report. Returns True on success, never raises."""
    target = Path(path or os.getenv("SR_REPORT_PATH", DEFAULT_REPORT_PATH))
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(json.dumps(build_report(metrics), indent=2), encoding="utf-8")
        tmp.replace(target)  # atomic rename on the same filesystem
        LOGGER.info("SR3 report written to %s", target)
        return True
    except Exception:  # pragma: no cover - degrade to Tier-0, never affect the run
        LOGGER.debug("SR3 report write failed; ShowRunner will degrade to Tier-0", exc_info=True)
        return False


__all__ = ["build_report", "responses_by_code", "write_report", "DEFAULT_REPORT_PATH"]
