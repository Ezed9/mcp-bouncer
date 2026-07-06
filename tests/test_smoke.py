import bouncer


def test_package_imports_and_has_version() -> None:
    assert isinstance(bouncer.__version__, str)
    assert bouncer.__version__
