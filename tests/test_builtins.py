from __future__ import annotations

import json
from typer.testing import CliRunner

from attack_generator.cli import BASE_PATH, app
from attack_generator.pools import BUILTIN_HEADER_FILES, BUILTIN_UA_FILES


def test_list_builtins_reports_counts() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["list-builtins"])
    assert result.exit_code == 0
    output = result.stdout
    base = BASE_PATH / "builtins"

    for group, filename in BUILTIN_UA_FILES.items():
        path = base / filename
        data = json.loads(path.read_text(encoding="utf-8"))
        expected = len(data)
        assert f"{group}: {expected} entries" in output

    for preset, filename in BUILTIN_HEADER_FILES.items():
        path = base / filename
        data = json.loads(path.read_text(encoding="utf-8"))
        expected = len(data)
        assert f"{preset}: {expected} headers" in output
