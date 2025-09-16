from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urljoin

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
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self._attack_map = attack_map
        self._base_url = base_url
        self._client = client or httpx.AsyncClient(base_url=base_url, timeout=httpx.Timeout(10.0))
        self._auth_settings = attack_map.auth
        self._auth_header: Dict[str, str] = {}

    async def startup(self) -> None:
        if not self._auth_settings:
            return
        if self._auth_settings.type == AuthType.BASIC:
            await self._configure_basic_auth(self._auth_settings)
        elif self._auth_settings.type == AuthType.FORM:
            await self._perform_form_auth(self._auth_settings)
        elif self._auth_settings.type == AuthType.BEARER:
            await self._perform_bearer_auth(self._auth_settings)

    async def shutdown(self) -> None:
        await self._client.aclose()

    async def _configure_basic_auth(self, auth: AuthSettings) -> None:
        assert auth.credentials  # validated in model
        self._client.auth = httpx.BasicAuth(auth.credentials.username, auth.credentials.password)

    async def _perform_form_auth(self, auth: AuthSettings) -> None:
        assert auth.credentials
        response = await self._client.request(
            auth.method,
            auth.path,
            data={"username": auth.credentials.username, "password": auth.credentials.password},
        )
        response.raise_for_status()
        if auth.store and auth.store.header:
            header_value = response.headers.get("Authorization")
            if header_value:
                self._auth_header["Authorization"] = header_value

    async def _perform_bearer_auth(self, auth: AuthSettings) -> None:
        credentials = auth.credentials.dict() if auth.credentials else {}
        response = await self._client.request(auth.method, auth.path, json=credentials)
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
        if not token:
            raise RuntimeError("bearer auth token not found")
        self._auth_header["Authorization"] = f"Bearer {token}"

    async def send(self, request: ResolvedRequest) -> httpx.Response:
        headers = {**request.headers, **self._auth_header}
        # httpx client handles cookies automatically
        response = await self._client.request(
            request.method,
            request.url,
            headers=headers,
            json=request.json_body,
            data=request.data,
            content=request.content,
        )
        return response

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
