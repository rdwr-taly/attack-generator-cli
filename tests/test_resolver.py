from __future__ import annotations

from pathlib import Path

from attack_generator.models import AttackMap
from attack_generator.pools import UAPool
from attack_generator.resolver import TemplateResolver

BASE = Path(__file__).resolve().parent.parent


def _load_map() -> AttackMap:
    data = (BASE / "examples" / "basic_injection_spray.json").read_text(encoding="utf-8")
    return AttackMap.model_validate_json(data)


def test_template_functions_resolve() -> None:
    attack_map = _load_map()
    ua_pool = UAPool.from_builtins(BASE / "attack_generator" / "builtins", seed=42)
    resolver = TemplateResolver(attack_map, ua_pool, seed=42)
    state: dict[str, str] = {}
    extra = {"ua_group": "web_desktop", "ip": "198.51.100.10", "ua": ua_pool.pick("web_desktop")}

    picked = resolver.resolve("{{ pick('usernames') }}", state=state, extra=extra)
    assert picked in attack_map.variables["usernames"].values  # type: ignore[index]

    encoded = resolver.resolve("{{ base64('demo') }}", state=state, extra=extra)
    assert encoded == "ZGVtbw=="

    urlencoded = resolver.resolve("{{ urlencode('a=b&c=1') }}", state=state, extra=extra)
    assert urlencoded == "a%3Db%26c%3D1"

    ua_value = resolver.resolve("{{ ua('web_desktop') }}", state=state, extra=extra)
    assert isinstance(ua_value, str) and ua_value
