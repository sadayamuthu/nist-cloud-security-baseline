from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ncsb")
except PackageNotFoundError:
    try:
        __version__ = version("nist-cloud-security-baseline")
    except PackageNotFoundError:  # pragma: no cover
        __version__ = "0.0.0"
