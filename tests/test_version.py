from importlib.metadata import version

import bouncer


def test_version_attribute_matches_the_installed_distribution() -> None:
    # 0.1.1 shipped reporting 0.1.0: a bug report quoting __version__ would
    # have named a release the reporter never had.
    assert bouncer.__version__ == version("bouncer-core")
