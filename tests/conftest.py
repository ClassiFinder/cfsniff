"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def tmp_tree(tmp_path: Path) -> Path:
    """Create a temp directory with a mix of files for scanning."""
    # Text file with a fake secret
    (tmp_path / "config.env").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

    # Nested directory
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "app.conf").write_text("db_password=hunter2\n")

    # Binary file (null bytes)
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")

    # Large file (will be skipped by size limit)
    (tmp_path / "huge.log").write_text("x" * (2 * 1024 * 1024))

    # Hidden file (should NOT be skipped)
    (tmp_path / ".secret").write_text("token=ghp_abc123\n")

    return tmp_path
