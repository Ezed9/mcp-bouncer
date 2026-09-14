from importlib.metadata import version

import bouncer_mcp


def test_version_attribute_matches_the_installed_distribution() -> None:
    assert bouncer_mcp.__version__ == version("bouncer-mcp")
