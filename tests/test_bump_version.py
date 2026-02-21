import pytest
from scripts.bump_version import bump_version


def test_bump_version_patch():
    assert bump_version("0.1.0", "patch") == "0.1.1"


def test_bump_version_minor():
    assert bump_version("0.1.0", "minor") == "0.2.0"


def test_bump_version_major():
    assert bump_version("0.1.0", "major") == "1.0.0"


def test_bump_version_invalid_format():
    with pytest.raises(ValueError, match="is not in expected format"):
        bump_version("1.0", "patch")


def test_bump_version_invalid_type():
    with pytest.raises(ValueError, match="Unknown bump type"):
        bump_version("1.0.0", "invalid")
