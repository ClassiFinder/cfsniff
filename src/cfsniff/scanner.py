"""File discovery, reading, and binary detection."""

from __future__ import annotations

import os
from pathlib import Path

_BINARY_CHECK_SIZE = 8192


def is_binary(path: Path) -> bool:
    """Check if a file is binary by looking for null bytes in the first 8KB."""
    try:
        chunk = path.read_bytes()[:_BINARY_CHECK_SIZE]
    except OSError:
        return False
    return b"\x00" in chunk


def discover_files(
    targets: list[Path],
    max_file_size: int,
) -> list[Path]:
    """Resolve targets (files and dirs) into a flat list of scannable text files.

    Skips binary files, files over max_file_size, and nonexistent paths.
    Recurses into directories. Does not skip hidden files.
    """
    result: list[Path] = []

    for target in targets:
        if not target.exists():
            continue

        if target.is_file():
            if _should_scan(target, max_file_size):
                result.append(target)
        elif target.is_dir():
            for root, dirs, filenames in os.walk(target):
                # Skip .git and node_modules
                dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
                for name in filenames:
                    path = Path(root) / name
                    if _should_scan(path, max_file_size):
                        result.append(path)

    return sorted(result)


def _should_scan(path: Path, max_file_size: int) -> bool:
    """Check if a file should be scanned (exists, not binary, not too large)."""
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size == 0 or size > max_file_size:
        return False
    return not is_binary(path)


def read_file_text(path: Path) -> str | None:
    """Read a file's text content. Returns None if the file can't be read."""
    try:
        return path.read_text(errors="replace")
    except OSError:
        return None
