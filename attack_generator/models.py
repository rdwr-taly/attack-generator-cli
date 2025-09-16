from __future__ import annotations

import enum
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

from pydantic import (BaseModel, ConfigDict, Field, HttpUrl, PositiveInt,
                       ValidationError, field_validator, model_validator)


class Target(BaseModel):
    """Target definition for the AttackMap."""

    model_config = ConfigDict(extra="forbid")

    base_url: HttpUrl
    xff_header: str = Field(default="client-ip", alias="xff_header")


class Safety(BaseModel):
    """Safety guard rails."""

    model_config = ConfigDict(extra="forbid")

    allowlist: List[str]
    global_rps_cap: PositiveInt = Field(default=50, alias="global_rps_cap")
    stop_on_target_mismatch: bool = Field(default=True, alias="stop_on_target_mismatch")
    banner: Optional[str] = None

    @field_validator("allowlist")
    @classmethod
    def _ensure_allowlist(cls, value: Sequence[str]) -> Sequence[str]:
        if not value:
            msg = "allowlist must define at least one domain pattern"
            raise ValueError(msg)
        return value


class Presets(BaseModel):
    """Top-level presets for UA and headers."""

    model_config = ConfigDict(extra="forbid")

    ua_group: Optional[str] = Field(default=None, alias="ua_group")
    headers: Optional[Union[str, Dict[str, str]]] = None


class VariableBase(BaseModel):
    """Base class for AttackMap variables."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    type: str


class VariableList(VariableBase):
    type: Literal["list"]
    values: List[str]

    @field_validator("values")
    @classmethod
    def _ensure_values(cls, value: Sequence[str]) -> Sequence[str]:
        if not value:
            msg = "list variable must declare one or more values"
            raise ValueError(msg)
        return value


class VariableInt(VariableBase):
    type: Literal["int"]
    min: int
    max: int

    @model_validator(mode="after")
    def _check_bounds(self) -> "VariableInt":
        if self.min > self.max:
            msg = "min must be <= max"
            raise ValueError(msg)
        return self


VariableDefinition = Union[VariableList, VariableInt]


class AuthType(str, enum.Enum):
    BASIC = "basic"
    FORM = "form"
    BEARER = "bearer"


class AuthCredentials(BaseModel):
    username: str
    password: str


class AuthStore(BaseModel):
    header: bool = False
    cookie: bool = False


class AuthSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: AuthType
    path: str
    method: str = "POST"
    credentials: Optional[AuthCredentials] = None
    json_path: Optional[str] = Field(default=None, alias="json_path")
    store: Optional[AuthStore] = None

    @model_validator(mode="after")
    def _validate_credentials(self) -> "AuthSettings":
        if self.type == AuthType.BASIC and not self.credentials:
            msg = "basic auth requires credentials"
            raise ValueError(msg)
        if self.type in {AuthType.FORM, AuthType.BEARER} and not self.path:
            msg = "auth path is required"
            raise ValueError(msg)
        return self


class AttackBodyType(str, enum.Enum):
    JSON = "json"
    FORM = "form"
    RAW = "raw"


class AttackDefinition(BaseModel):
    """Single attack description."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    traffic_type: Literal["web", "api"]
    category: str
    method: str
    path: str
    headers: Optional[Union[str, Dict[str, str]]] = None
    body_type: Optional[AttackBodyType] = Field(default=None, alias="body_type")
    body: Optional[Any] = None
    weight: PositiveInt = 1
    description: Optional[str] = None

    @field_validator("method")
    @classmethod
    def _upper_method(cls, value: str) -> str:
        return value.upper()

    @field_validator("path")
    @classmethod
    def _ensure_path(cls, value: str) -> str:
        if not value.startswith("/"):
            msg = "attack path must be absolute"
            raise ValueError(msg)
        return value


class ScenarioSelect(BaseModel):
    model_config = ConfigDict(extra="forbid")

    by_ids: Optional[List[str]] = Field(default=None, alias="by_ids")
    by_category: Optional[List[str]] = Field(default=None, alias="by_category")

    def matches(self, attack: AttackDefinition) -> bool:
        if self.by_ids and attack.id in self.by_ids:
            return True
        if self.by_category and attack.category in self.by_category:
            return True
        return False


class ScenarioRate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    qps: PositiveInt
    duration_sec: Optional[int] = Field(default=None, alias="duration_sec")


class ScenarioDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    select: ScenarioSelect
    ip_pool: Optional[str] = Field(default=None, alias="ip_pool")
    ua_group: Optional[str] = Field(default=None, alias="ua_group")
    rate: Optional[ScenarioRate] = None
    jitter_ms: Optional[Tuple[int, int]] = Field(default=None, alias="jitter_ms")
    headers: Optional[Union[str, Dict[str, str]]] = None


class RetryPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_attempts: int = Field(default=0, alias="max_attempts")
    backoff_seconds: float = Field(default=0.5, alias="backoff_seconds")

    @model_validator(mode="after")
    def _adjust(self) -> "RetryPolicy":
        if self.max_attempts < 0:
            msg = "max_attempts must be >= 0"
            raise ValueError(msg)
        if self.backoff_seconds < 0:
            msg = "backoff_seconds must be >= 0"
            raise ValueError(msg)
        return self


class RuntimeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    think_time_ms: Optional[Tuple[int, int]] = Field(default=None, alias="think_time_ms")
    concurrency: PositiveInt = 20
    cookie_jar: Optional[str] = Field(default=None, alias="cookie_jar")
    session_reuse: bool = Field(default=True, alias="session_reuse")
    retry: RetryPolicy = RetryPolicy()

    @field_validator("think_time_ms")
    @classmethod
    def _validate_think_time(cls, value: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        if value is None:
            return value
        if len(value) != 2:
            msg = "think_time_ms must contain lower and upper bounds"
            raise ValueError(msg)
        low, high = value
        if low < 0 or high < 0 or low > high:
            msg = "invalid think_time_ms bounds"
            raise ValueError(msg)
        return value


class AttackMap(BaseModel):
    """Root AttackMap document."""

    model_config = ConfigDict(extra="forbid")

    version: int
    name: str
    description: Optional[str] = None
    target: Target
    safety: Safety
    presets: Optional[Presets] = None
    variables: Dict[str, VariableDefinition] = Field(default_factory=dict)
    auth: Optional[AuthSettings] = None
    attacks: List[AttackDefinition]
    scenarios: List[ScenarioDefinition] = Field(default_factory=list)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)

    @model_validator(mode="after")
    def _validate_version(self) -> "AttackMap":
        if self.version != 1:
            msg = "only AttackMap version 1 is supported"
            raise ValueError(msg)
        return self

    def attack_lookup(self) -> Dict[str, AttackDefinition]:
        return {attack.id: attack for attack in self.attacks}

    def describe(self) -> Dict[str, Any]:
        """Return a stable dict representation for hashing/logging."""
        return json.loads(self.model_dump_json())


class LogFormat(str, enum.Enum):
    JSON = "json"
    TEXT = "text"


@dataclass(slots=True)
class RuntimeConfig:
    """Runtime configuration resolved from CLI/env/map."""

    allowlist: List[str]
    qps: int
    concurrency: int
    xff: str
    ip_pool: Optional[str]
    ua_group: Optional[str]
    metrics_port: int
    log_format: LogFormat
    seed: Optional[int]
    unsafe_override: bool
    base_url_override: Optional[str]
    operator: Optional[str]
    server_enabled: bool


class ConfigError(RuntimeError):
    """Configuration resolution error."""


def merge_allowlist(cli: Optional[List[str]], env: Optional[List[str]], from_map: List[str]) -> List[str]:
    """Merge allowlist with precedence and ensure not empty."""

    if cli:
        return cli
    if env:
        return env
    return from_map


def select_ua_group(cli: Optional[str], env: Optional[str], map_group: Optional[str]) -> Optional[str]:
    if cli:
        return cli
    if env:
        return env
    return map_group


def resolve_runtime_config(
    *,
    attack_map: AttackMap,
    cli_values: Dict[str, Any],
    env_values: Dict[str, Any],
) -> RuntimeConfig:
    """Resolve runtime settings with precedence flag > env > map."""

    allowlist = merge_allowlist(
        cli_values.get("allowlist"), env_values.get("allowlist"), attack_map.safety.allowlist
    )

    if not allowlist:
        msg = "allowlist is required"
        raise ConfigError(msg)

    qps = cli_values.get("qps") or env_values.get("qps") or attack_map.safety.global_rps_cap

    unsafe = bool(cli_values.get("unsafe_override") or env_values.get("unsafe_override"))

    if not unsafe and qps > attack_map.safety.global_rps_cap:
        qps = attack_map.safety.global_rps_cap

    concurrency = (
        cli_values.get("concurrency")
        or env_values.get("concurrency")
        or attack_map.runtime.concurrency
        or 1
    )

    xff = cli_values.get("xff") or env_values.get("xff") or attack_map.target.xff_header
    ip_pool = cli_values.get("ip_pool") or env_values.get("ip_pool")
    ua_group = select_ua_group(
        cli_values.get("ua_group"), env_values.get("ua_group"), attack_map.presets.ua_group if attack_map.presets else None
    )
    metrics_port = cli_values.get("metrics_port") or env_values.get("metrics_port") or 9102

    log_format_raw = cli_values.get("log_format") or env_values.get("log_format") or LogFormat.JSON.value

    try:
        log_format = LogFormat(log_format_raw)
    except ValueError as exc:  # pragma: no cover - defensive guard
        raise ConfigError(f"invalid log format: {log_format_raw}") from exc

    seed = cli_values.get("seed") or env_values.get("seed")
    base_url_override = cli_values.get("base_url") or env_values.get("base_url")
    operator = cli_values.get("operator") or env_values.get("operator")
    server_enabled = bool(cli_values.get("server"))

    return RuntimeConfig(
        allowlist=allowlist,
        qps=int(qps),
        concurrency=int(concurrency),
        xff=xff,
        ip_pool=ip_pool,
        ua_group=ua_group,
        metrics_port=int(metrics_port),
        log_format=log_format,
        seed=seed if seed is None else int(seed),
        unsafe_override=unsafe,
        base_url_override=base_url_override,
        operator=operator,
        server_enabled=server_enabled,
    )


__all__ = [
    "AttackMap",
    "AttackDefinition",
    "AttackBodyType",
    "AuthCredentials",
    "AuthSettings",
    "AuthType",
    "ConfigError",
    "LogFormat",
    "Presets",
    "RetryPolicy",
    "RuntimeConfig",
    "RuntimeSettings",
    "Safety",
    "ScenarioDefinition",
    "ScenarioRate",
    "ScenarioSelect",
    "Target",
    "VariableDefinition",
    "VariableInt",
    "VariableList",
    "resolve_runtime_config",
]
