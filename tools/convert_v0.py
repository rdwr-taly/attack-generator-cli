"""Legacy AttackMap v0 to v1 converter stub.

This placeholder script documents the expected behaviour for migrating older
JSON resources into the v1 AttackMap format.  The legacy schema was loosely
defined in the initial traffic-generator proof of concept and is preserved
here for reference only.

Expected input (v0):
    - Top-level keys: target_url, attacks (list), variables (optional)
    - Attack entries contained raw method/path/header definitions without
      safety metadata or presets.

Expected output (v1):
    - AttackMap document compliant with ``schemas/attackmap.schema.json``.
    - Safety information inferred from operator-provided defaults.

TODO:
    Implement field mappings and heuristics once the historic samples are
    catalogued.  Future work should preserve determinism and seed handling
    while offering operators a dry-run preview.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


def convert_v0_to_v1(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a legacy payload into the v1 structure.

    The current implementation is a stub.  It simply raises ``NotImplementedError``
    to signal that support will be added when legacy samples are available.
    """

    raise NotImplementedError("convert_v0_to_v1 is not yet implemented")


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
