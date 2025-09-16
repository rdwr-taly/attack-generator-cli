from __future__ import annotations

from attack_generator.runner import ensure_allowlist


def test_allowlist_matches_wildcard() -> None:
    assert ensure_allowlist("https://demo.radware.net", ["*.radware.net"])


def test_allowlist_blocks_mismatch() -> None:
    assert not ensure_allowlist("https://example.com", ["*.radware.net"])
