"""cfsniff — sniff out secrets in arbitrary text."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cfsniff")
except PackageNotFoundError:
    __version__ = "unknown"
