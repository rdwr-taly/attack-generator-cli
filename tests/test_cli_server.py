from __future__ import annotations

import pytest
import typer

from attack_generator import cli


@pytest.mark.anyio
async def test_run_async_requires_container_control(monkeypatch) -> None:
    monkeypatch.setattr(cli.container_control_adapter, "available", lambda: False)
    options = cli.RunOptions(
        attackmap=None,
        allowlist=None,
        base_url=None,
        qps=None,
        concurrency=None,
        xff=None,
        ip_pool=None,
        ua_group=None,
        metrics_port=0,
        log_format=None,
        seed=None,
        unsafe_override=False,
        acknowledge_override=False,
        server=True,
        operator=None,
    )
    with pytest.raises(typer.Exit) as exc:
        await cli._run_async(options)
    assert exc.value.exit_code == 1
