"""Legacy AttackMap v0 to v1 converter.

Expected input (v0):
    {
        "name": "Optional name",
        "target_url": "https://example.com",
        "allowlist": ["*.example.com"],
        "attacks": [
            {
                "id": "A1",
                "name": "Ping",
                "method": "GET",
                "path": "/ping",
                "headers": {"Accept": "*/*"},
                "body": null,
                "category": "misc",
                "traffic_type": "api"
            }
        ]
    }

Output (v1) conforms to ``schemas/attackmap.schema.json`` with sensible defaults
for missing fields.  The converter is intentionally conservative: unsupported
fields are ignored and missing required fields raise ``ValueError``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse


DEFAULT_RUNTIME = {"think_time_ms": [100, 1500], "concurrency": 1}


def _ensure_attacks(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    attacks = payload.get("attacks")
    if not attacks:
        raise ValueError("v0 payload requires one or more attacks")
    return attacks


def _default_allowlist(base_url: str) -> List[str]:
    parsed = urlparse(base_url)
    host = parsed.hostname or "localhost"
    return [host]


def convert_v0_to_v1(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a legacy payload into the v1 structure."""

    if "target_url" not in payload:
        raise ValueError("v0 payload missing target_url")
    base_url = str(payload["target_url"])
    allowlist = payload.get("allowlist") or _default_allowlist(base_url)
    safety = {
        "allowlist": allowlist,
        "global_rps_cap": int(payload.get("global_rps_cap", 50)),
        "stop_on_target_mismatch": bool(payload.get("stop_on_target_mismatch", True)),
    }
    if payload.get("banner"):
        safety["banner"] = str(payload["banner"])

    attacks_v1: List[Dict[str, Any]] = []
    for index, attack in enumerate(_ensure_attacks(payload), start=1):
        attack_id = str(attack.get("id") or f"A_CONVERTED_{index}")
        method = str(attack.get("method", "GET")).upper()
        path = str(attack.get("path") or "/")
        attack_entry: Dict[str, Any] = {
            "id": attack_id,
            "name": str(attack.get("name", attack_id)),
            "traffic_type": str(attack.get("traffic_type", "api")),
            "category": str(attack.get("category", "misc")),
            "method": method,
            "path": path,
        }
        if attack.get("headers"):
            attack_entry["headers"] = dict(attack["headers"])
        if attack.get("body") is not None:
            attack_entry["body"] = attack.get("body")
            inferred_type = attack.get("body_type")
            if isinstance(attack_entry["body"], dict) and not inferred_type:
                inferred_type = "json"
            if inferred_type:
                attack_entry["body_type"] = inferred_type
        attacks_v1.append(attack_entry)

    result: Dict[str, Any] = {
        "version": 1,
        "name": str(payload.get("name", "Converted AttackMap")),
        "description": payload.get("description"),
        "target": {"base_url": base_url, "xff_header": str(payload.get("xff_header", "client-ip"))},
        "safety": safety,
        "variables": {},
        "attacks": attacks_v1,
        "runtime": dict(payload.get("runtime", DEFAULT_RUNTIME)),
    }
    if payload.get("presets"):
        result["presets"] = payload["presets"]
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert AttackMap v0 to v1")
    parser.add_argument("input", type=Path, help="Path to v0 JSON file")
    parser.add_argument("output", type=Path, help="Destination for v1 JSON")
    args = parser.parse_args()

    data = json.loads(args.input.read_text(encoding="utf-8"))
    result = convert_v0_to_v1(data)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
