from __future__ import annotations

from typing import Any, Dict

import json
import httpx
import pytest

from attack_generator.models import AttackMap
from attack_generator.transport import AttackTransport, ResolvedRequest

BASE_MAP: Dict[str, Any] = {
    "version": 1,
    "name": "Auth Test",
    "target": {"base_url": "https://example.com", "xff_header": "client-ip"},
    "safety": {"allowlist": ["*.example.com"], "global_rps_cap": 10, "stop_on_target_mismatch": True},
    "attacks": [
        {
            "id": "A1",
            "name": "Ping",
            "traffic_type": "api",
            "category": "misc",
            "method": "GET",
            "path": "/attack",
        }
    ],
    "runtime": {"think_time_ms": [100, 1500], "concurrency": 1},
}


@pytest.mark.anyio
async def test_basic_auth_inserts_header() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.setdefault("auth", request.headers.get("Authorization"))
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)

    attack_map = AttackMap.model_validate(dict(BASE_MAP, auth={"type": "basic", "path": "/", "credentials": {"username": "u", "password": "p"}}))
    client_factory = lambda: httpx.AsyncClient(base_url=str(attack_map.target.base_url), transport=transport)
    attack_transport = AttackTransport(attack_map, base_url=str(attack_map.target.base_url), client_factory=client_factory)

    await attack_transport.startup()
    attack = attack_map.attacks[0]
    request = ResolvedRequest(
        attack=attack,
        method=attack.method,
        url=attack_transport.absolute_url(attack.path),
        headers={},
        scenario_id=None,
        ip="198.51.100.1",
        ua="TestAgent",
    )
    response = await attack_transport.send(request)
    await attack_transport.shutdown()

    assert response.status_code == 200
    assert seen["auth"] is not None
    assert seen["auth"].startswith("Basic ")


@pytest.mark.anyio
async def test_form_auth_stores_cookie() -> None:
    calls: Dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            calls["login"] = request
            return httpx.Response(200, headers={"Set-Cookie": "sessionid=abc123; Path=/"})
        calls["attack"] = request
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    auth_block = {
        "type": "form",
        "path": "/login",
        "credentials": {"username": "demo", "password": "secret"},
        "store": {"cookie": True},
    }
    map_data = dict(BASE_MAP, auth=auth_block)
    attack_map = AttackMap.model_validate(map_data)
    client_factory = lambda: httpx.AsyncClient(base_url=str(attack_map.target.base_url), transport=transport)
    attack_transport = AttackTransport(attack_map, base_url=str(attack_map.target.base_url), client_factory=client_factory)

    await attack_transport.startup()
    attack = attack_map.attacks[0]
    request = ResolvedRequest(
        attack=attack,
        method=attack.method,
        url=attack_transport.absolute_url(attack.path),
        headers={},
        scenario_id="S1",
        ip="198.51.100.10",
        ua="TestAgent",
    )
    await attack_transport.send(request)
    await attack_transport.shutdown()

    assert "login" in calls
    assert "attack" in calls
    assert "cookie" in calls["attack"].headers
    assert "sessionid=abc123" in calls["attack"].headers["cookie"]


@pytest.mark.anyio
async def test_bearer_auth_uses_token() -> None:
    events: Dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            events["token"] = request
            return httpx.Response(200, json={"data": {"token": "abc-token"}})
        events["attack"] = request
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    auth_block = {
        "type": "bearer",
        "path": "/token",
        "method": "POST",
        "json_path": "data.token",
    }
    map_data = dict(BASE_MAP, auth=auth_block)
    attack_map = AttackMap.model_validate(map_data)
    client_factory = lambda: httpx.AsyncClient(base_url=str(attack_map.target.base_url), transport=transport)
    attack_transport = AttackTransport(attack_map, base_url=str(attack_map.target.base_url), client_factory=client_factory)

    await attack_transport.startup()
    attack = attack_map.attacks[0]
    request = ResolvedRequest(
        attack=attack,
        method=attack.method,
        url=attack_transport.absolute_url(attack.path),
        headers={},
        scenario_id=None,
        ip="198.51.100.99",
        ua="TestAgent",
    )
    await attack_transport.send(request)
    await attack_transport.shutdown()

    assert "token" in events
    assert "attack" in events
    assert events["attack"].headers["Authorization"] == "Bearer abc-token"


@pytest.mark.anyio
async def test_form_cookie_scope_per_ip() -> None:
    login_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal login_calls
        if request.url.path == "/login":
            login_calls += 1
            return httpx.Response(200, headers={"Set-Cookie": "sessionid=abc123; Path=/"})
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    auth_block = {
        "type": "form",
        "path": "/login",
        "credentials": {"username": "demo", "password": "secret"},
        "store": {"cookie": True},
    }
    map_data = dict(BASE_MAP, auth=auth_block, runtime={"cookie_jar": "per_ip", "think_time_ms": [100, 1500], "concurrency": 1})
    attack_map = AttackMap.model_validate(map_data)
    client_factory = lambda: httpx.AsyncClient(base_url=str(attack_map.target.base_url), transport=transport)
    attack_transport = AttackTransport(attack_map, base_url=str(attack_map.target.base_url), client_factory=client_factory)

    await attack_transport.startup()
    attack = attack_map.attacks[0]
    for idx in range(2):
        request = ResolvedRequest(
            attack=attack,
            method=attack.method,
            url=attack_transport.absolute_url(attack.path),
            headers={},
            scenario_id=None,
            ip=f"198.51.100.{10 + idx}",
            ua="TestAgent",
        )
        await attack_transport.send(request)
    await attack_transport.shutdown()

    assert login_calls == 2


@pytest.mark.anyio
async def test_form_cookie_scope_shared_only_logs_in_once() -> None:
    login_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal login_calls
        if request.url.path == "/login":
            login_calls += 1
            return httpx.Response(200, headers={"Set-Cookie": "sessionid=abc123; Path=/"})
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    auth_block = {
        "type": "form",
        "path": "/login",
        "credentials": {"username": "demo", "password": "secret"},
        "store": {"cookie": True},
    }
    map_data = dict(BASE_MAP, auth=auth_block, runtime={"cookie_jar": "shared", "think_time_ms": [100, 1500], "concurrency": 1})
    attack_map = AttackMap.model_validate(map_data)
    client_factory = lambda: httpx.AsyncClient(base_url=str(attack_map.target.base_url), transport=transport)
    attack_transport = AttackTransport(attack_map, base_url=str(attack_map.target.base_url), client_factory=client_factory)

    await attack_transport.startup()
    attack = attack_map.attacks[0]
    for idx in range(2):
        request = ResolvedRequest(
            attack=attack,
            method=attack.method,
            url=attack_transport.absolute_url(attack.path),
            headers={},
            scenario_id=None,
            ip=f"198.51.100.{10 + idx}",
            ua="TestAgent",
        )
        await attack_transport.send(request)
    await attack_transport.shutdown()

    assert login_calls == 1


@pytest.mark.anyio
async def test_host_header_enforced() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["host"] = request.headers.get("Host")
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    map_data = json.loads(json.dumps(BASE_MAP))
    map_data["attacks"] = [
        {
            "id": "A2",
            "name": "HostOverride",
            "traffic_type": "api",
            "category": "misc",
            "method": "GET",
            "path": "/attack",
            "headers": {"Host": "evil.com"},
        }
    ]
    attack_map = AttackMap.model_validate(map_data)
    client_factory = lambda: httpx.AsyncClient(base_url=str(attack_map.target.base_url), transport=transport)
    attack_transport = AttackTransport(attack_map, base_url=str(attack_map.target.base_url), client_factory=client_factory)

    await attack_transport.startup()
    attack = attack_map.attacks[0]
    request = ResolvedRequest(
        attack=attack,
        method=attack.method,
        url=attack_transport.absolute_url(attack.path),
        headers={"Host": "evil.com"},
        scenario_id=None,
        ip="198.51.100.10",
        ua="TestAgent",
    )
    await attack_transport.send(request)
    await attack_transport.shutdown()

    assert seen["host"] == "example.com"
