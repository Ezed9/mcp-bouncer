"""server.json is what the MCP Registry publishes; it must agree with the package."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_server_json_matches_the_package() -> None:
    server = json.loads((ROOT / "server.json").read_text())
    project = tomllib.loads((ROOT / "bouncer-mcp" / "pyproject.toml").read_text())["project"]
    package = server["packages"][0]

    assert package["identifier"] == project["name"]
    assert server["version"] == package["version"] == project["version"]
    assert len(server["description"]) <= 100  # the registry rejects longer ones
    # uvx runs the executable named after the package.
    assert package["identifier"] in project["scripts"]
    # The registry proves PyPI ownership by finding this line in the package README.
    readme = (ROOT / "bouncer-mcp" / "README.md").read_text()
    assert re.search(rf"mcp-name: {re.escape(server['name'])}(\s|-->)", readme)
