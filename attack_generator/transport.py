from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional
from urllib.parse import urljoin

import anyio
import httpx

from .models import AttackBodyType, AttackDefinition, AttackMap, AuthSettings, AuthType


@dataclass(slots=True)
class ResolvedRequest:
    """Concrete HTTP request assembled from an attack definition."""

    attack: AttackDefinition
    method: str
    url: str
    headers: Dict[str, str]
    json_body: Optional[Any] = None
    data: Optional[Any] = None
    content: Optional[bytes] = None
    scenario_id: Optional[str] = None
    ip: Optional[str] = None
    ua: Optional[str] = None


class AttackTransport:
    """Wrapper around httpx.AsyncClient handling auth and cookie policy."""

    def __init__(
        self,
        attack_map: AttackMap,
        *,
        base_url: str,
        client_factory: Optional[Callable[[], httpx.AsyncClient]] = None,
    ) -> None:
        self._attack_map = attack_map
        self._base_url = base_url
        self._auth_settings = attack_map.auth
        self._auth_header: Dict[str, str] = {}
        self._client_factory = client_factory
        self._cookie_scope = (attack_map.runtime.cookie_jar or "per_ip").lower()
        if self._cookie_scope not in {"per_ip", "per_scenario", "shared"}:
            raise ValueError(f"unknown cookie jar scope '{self._cookie_scope}'")
        self._session_reuse = attack_map.runtime.session_reuse
        self._clients: Dict[str, httpx.AsyncClient] = {}
        self._authed_clients: set[str] = set()
        self._client_lock = anyio.Lock()
        self._base_host = httpx.URL(base_url).host or ""

    async def startup(self) -> None:
        if not self._auth_settings:
            return
        if self._auth_settings.type == AuthType.BEARER:
            async with self._new_client() as client:
                await self._perform_bearer_auth(client, self._auth_settings)

    async def shutdown(self) -> None:
        async with self._client_lock:
            clients = list(self._clients.values())
            self._clients.clear()
            self._authed_clients.clear()
        for client in clients:
            await client.aclose()

    def _new_client(self) -> httpx.AsyncClient:
        if self._client_factory:
            return self._client_factory()
        limits = None
        if not self._session_reuse:
            limits = httpx.Limits(max_keepalive_connections=0, keepalive_expiry=0)
        return httpx.AsyncClient(base_url=self._base_url, timeout=httpx.Timeout(10.0), limits=limits)

    async def _prepare_client(self, client: httpx.AsyncClient) -> None:
        if not self._auth_settings:
            return
        if self._auth_settings.type == AuthType.BASIC:
            auth = self._auth_settings
            assert auth.credentials  # validated
            client.auth = httpx.BasicAuth(auth.credentials.username, auth.credentials.password)

    async def _perform_form_auth(self, client: httpx.AsyncClient, auth: AuthSettings) -> None:
        assert auth.credentials
        response = await client.request(
            auth.method,
            auth.path,
            data={"username": auth.credentials.username, "password": auth.credentials.password},
        )
        response.raise_for_status()
        if auth.store and auth.store.header:
            header_value = response.headers.get("Authorization")
            if header_value:
                self._auth_header["Authorization"] = header_value

    async def _perform_bearer_auth(self, client: httpx.AsyncClient, auth: AuthSettings) -> None:
        credentials = auth.credentials.dict() if auth.credentials else {}
        response = await client.request(auth.method, auth.path, json=credentials)
        response.raise_for_status()
        payload: Any
        try:
            payload = response.json()
        except json.JSONDecodeError as exc:  # pragma: no cover - network edge
            raise RuntimeError("bearer auth response not JSON") from exc
        token = None
        if auth.json_path:
            token = _dig_json(payload, auth.json_path)
        if not token:
            token = payload.get("token") if isinstance(payload, dict) else None
        if not token and auth.store and auth.store.header:
            token = response.headers.get("Authorization")
        if not token:
            raise RuntimeError("bearer auth token not found")
        self._auth_header["Authorization"] = f"Bearer {token}"

    async def send(self, request: ResolvedRequest) -> httpx.Response:
        client = await self._acquire_client(request)
        headers = {**request.headers, **self._auth_header}
        if self._base_host:
            headers["Host"] = self._base_host
        response = await client.request(
            request.method,
            request.url,
            headers=headers,
            json=request.json_body,
            data=request.data,
            content=request.content,
        )
        return response

    async def _acquire_client(self, request: ResolvedRequest) -> httpx.AsyncClient:
        key = self._client_key(request)
        async with self._client_lock:
            client = self._clients.get(key)
            if client is None:
                client = self._new_client()
                await self._prepare_client(client)
                self._clients[key] = client
        if self._auth_settings and self._auth_settings.type == AuthType.FORM and key not in self._authed_clients:
            await self._perform_form_auth(client, self._auth_settings)
            self._authed_clients.add(key)
        return client

    def _client_key(self, request: ResolvedRequest) -> str:
        scope = self._cookie_scope
        if scope == "shared":
            return "shared"
        if scope == "per_scenario" and request.scenario_id:
            return f"scenario:{request.scenario_id}"
        if scope == "per_ip" and request.ip:
            return f"ip:{request.ip}"
        return "shared"

    def absolute_url(self, path: str) -> str:
        return urljoin(self._base_url, path)


def _dig_json(payload: Any, path: str) -> Optional[str]:
    current = payload
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    if isinstance(current, str):
        return current
    return None


__all__ = ["AttackTransport", "ResolvedRequest"]
