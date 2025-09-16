from __future__ import annotations

import base64
import random
import re
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional
from urllib.parse import quote_plus

from jinja2 import Environment, StrictUndefined

from .models import AttackMap, VariableDefinition, VariableInt, VariableList
from .pools import IdentityPool, UAPool


LEGACY_VAR_PATTERN = re.compile(r"@(?P<name>[A-Za-z_][A-Za-z0-9_]*)")


class TemplateResolver:
    """Resolve templated fields inside AttackMap payloads."""

    def __init__(
        self,
        attack_map: AttackMap,
        ua_pool: UAPool,
        *,
        seed: Optional[int] = None,
    ) -> None:
        self._attack_map = attack_map
        self._ua_pool = ua_pool
        self._random = random.Random(seed)
        self._env = Environment(undefined=StrictUndefined, autoescape=False)

    def _resolve_variable(self, name: str, state: MutableMapping[str, Any]) -> Any:
        if name in state:
            return state[name]
        definition = self._attack_map.variables.get(name)
        if not definition:
            msg = f"unknown variable '{name}'"
            raise KeyError(msg)
        if isinstance(definition, VariableList):
            value = self._random.choice(definition.values)
        elif isinstance(definition, VariableInt):
            value = self._random.randint(definition.min, definition.max)
        else:  # pragma: no cover - defensive
            msg = f"unsupported variable type: {definition.type}"
            raise KeyError(msg)
        state[name] = value
        return value

    def _legacy_replace(self, value: str, state: MutableMapping[str, Any]) -> str:
        def repl(match: re.Match[str]) -> str:
            key = match.group("name")
            return str(self._resolve_variable(key, state))

        return LEGACY_VAR_PATTERN.sub(repl, value)

    def _render(self, value: str, state: MutableMapping[str, Any], extra: Mapping[str, Any]) -> str:
        env = self._env.overlay()
        env.globals.update(
            pick=lambda name: self._resolve_variable(name, state),
            int=lambda low, high: self._random.randint(int(low), int(high)),
            base64=lambda text: base64.b64encode(str(text).encode()).decode(),
            urlencode=lambda text: quote_plus(str(text)),
            ua=lambda group=None: self._ua_pool.pick(group or extra.get("ua_group")),
            ip=lambda: extra.get("ip"),
        )
        context = dict(extra)
        ua_value = context.pop("ua", None)
        if ua_value is not None:
            context.setdefault("ua_value", ua_value)
            context.setdefault("user_agent", ua_value)
        ip_value = context.pop("ip", None)
        if ip_value is not None:
            context.setdefault("source_ip", ip_value)
        template = env.from_string(value)
        return template.render(**context)

    def resolve(self, payload: Any, *, state: Optional[MutableMapping[str, Any]] = None, extra: Optional[Mapping[str, Any]] = None) -> Any:
        if state is None:
            state = {}
        if extra is None:
            extra = {}
        if isinstance(payload, str):
            templated = self._legacy_replace(payload, state)
            return self._render(templated, state, extra)
        if isinstance(payload, list):
            return [self.resolve(item, state=state, extra=extra) for item in payload]
        if isinstance(payload, dict):
            return {
                key: self.resolve(value, state=state, extra=extra)
                for key, value in payload.items()
            }
        return payload


class ResolverFactory:
    """Construct TemplateResolver instances for runner contexts."""

    def __init__(self, attack_map: AttackMap, ua_pool: UAPool) -> None:
        self._attack_map = attack_map
        self._ua_pool = ua_pool

    def create(self, *, seed: Optional[int]) -> TemplateResolver:
        return TemplateResolver(self._attack_map, self._ua_pool, seed=seed)


__all__ = ["TemplateResolver", "ResolverFactory"]
