from __future__ import annotations

import ipaddress
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union


BUILTIN_UA_FILES = {
    "web_desktop": "ua_web_desktop.json",
    "web_mobile": "ua_web_mobile.json",
    "api_clients": "ua_api_clients.json",
}


BUILTIN_HEADER_FILES = {
    "builtin.headers.web_html_v1": "headers_web_html_v1.json",
    "builtin.headers.api_json_v1": "headers_api_json_v1.json",
    "builtin.headers.api_form_v1": "headers_api_form_v1.json",
}


class IdentityPool:
    """Base class for IP/User-Agent pools."""

    def __init__(self, *, seed: Optional[int] = None) -> None:
        self._random = random.Random(seed)

    @property
    def random(self) -> random.Random:
        return self._random


class IPPool(IdentityPool):
    """Select IP addresses according to map/runtime spec."""

    def __init__(self, spec: Optional[str], *, seed: Optional[int] = None, base_path: Optional[Path] = None) -> None:
        super().__init__(seed=seed)
        self._base_path = base_path or Path.cwd()
        self._mode = "static"
        self._static_ip = "203.0.113.10"
        self._values: List[str] = []
        self._network: Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = None
        if spec:
            self._parse_spec(spec)

    def _parse_spec(self, spec: str) -> None:
        if spec == "single_static":
            self._static_ip = "198.51.100.10"
            return
        if spec.startswith("random:"):
            count = int(spec.split(":", 1)[1])
            self._mode = "pool"
            self._values = [self._generate_random_ip() for _ in range(count)]
            return
        if spec.startswith("cidr:"):
            cidr = spec.split(":", 1)[1]
            self._mode = "cidr"
            self._network = ipaddress.ip_network(cidr, strict=False)
            return
        if spec.startswith("file:"):
            file_path = self._base_path.joinpath(spec.split(":", 1)[1])
            with file_path.open("r", encoding="utf-8") as handle:
                self._values = [line.strip() for line in handle if line.strip()]
            self._mode = "pool"
            return
        if spec.startswith("list:"):
            payload = spec.split(":", 1)[1]
            if payload.startswith("["):
                self._values = [addr.strip() for addr in json.loads(payload)]
            else:
                self._values = [addr.strip() for addr in payload.split(",") if addr.strip()]
            self._mode = "pool"
            return
        # treat literal IP
        try:
            ipaddress.ip_address(spec)
            self._static_ip = spec
        except ValueError as exc:
            raise ValueError(f"invalid ip pool spec: {spec}") from exc

    def _generate_random_ip(self) -> str:
        return f"203.0.113.{self.random.randint(1, 254)}"

    def pick(self) -> str:
        if self._mode == "static":
            return self._static_ip
        if self._mode == "pool" and self._values:
            return self.random.choice(self._values)
        if self._mode == "cidr" and self._network:
            hosts = list(self._network.hosts())
            return str(self.random.choice(hosts))
        return self._static_ip


@dataclass
class UAPool:
    """Pick User-Agent strings grouped by name."""

    groups: Dict[str, List[str]]
    seed: Optional[int] = None

    def __post_init__(self) -> None:
        self._random = random.Random(self.seed)
        if not self.groups:
            msg = "UA pool requires at least one group"
            raise ValueError(msg)

    @classmethod
    def from_builtins(cls, base_path: Path, *, seed: Optional[int] = None) -> "UAPool":
        groups: Dict[str, List[str]] = {}
        for group, filename in BUILTIN_UA_FILES.items():
            path = base_path / filename
            with path.open("r", encoding="utf-8") as handle:
                groups[group] = json.load(handle)
        return cls(groups=groups, seed=seed)

    def pick(self, group: Optional[str]) -> str:
        name = group or next(iter(self.groups))
        if name not in self.groups:
            msg = f"unknown UA group '{name}'"
            raise KeyError(msg)
        return self._random.choice(self.groups[name])

    def size(self, group: str) -> int:
        return len(self.groups.get(group, []))


def load_header_preset(base_path: Path, preset_name: str) -> Dict[str, str]:
    """Load built-in header presets."""

    if preset_name not in BUILTIN_HEADER_FILES:
        msg = f"unknown header preset '{preset_name}'"
        raise KeyError(msg)
    file_path = base_path / BUILTIN_HEADER_FILES[preset_name]
    with file_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        msg = f"header preset '{preset_name}' must be a JSON object"
        raise ValueError(msg)
    return {str(key): str(value) for key, value in data.items()}


__all__ = ["IPPool", "IdentityPool", "UAPool", "load_header_preset"]
