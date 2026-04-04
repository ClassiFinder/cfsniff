"""Tests for file discovery and reading."""

from __future__ import annotations

from pathlib import Path

from cfsniff.scanner import discover_files, is_binary, read_file_text


class TestIsBinary:
    def test_text_file(self, tmp_path: Path) -> None:
        f = tmp_path / "text.txt"
        f.write_text("hello world")
        assert is_binary(f) is False

    def test_binary_file(self, tmp_path: Path) -> None:
        f = tmp_path / "bin.dat"
        f.write_bytes(b"\x00\x01\x02\x03")
        assert is_binary(f) is True

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty"
        f.write_text("")
        assert is_binary(f) is False


class TestDiscoverFiles:
    def test_single_file(self, tmp_tree: Path) -> None:
        files = discover_files([tmp_tree / "config.env"], max_file_size=1024 * 1024)
        assert len(files) == 1
        assert files[0].name == "config.env"

    def test_directory_recursive(self, tmp_tree: Path) -> None:
        files = discover_files([tmp_tree], max_file_size=1024 * 1024)
        names = {f.name for f in files}
        # Includes text files and hidden files
        assert "config.env" in names
        assert "app.conf" in names
        assert ".secret" in names
        # Skips binary
        assert "image.png" not in names
        # Skips large files
        assert "huge.log" not in names

    def test_nonexistent_skipped(self, tmp_path: Path) -> None:
        files = discover_files([tmp_path / "nope.txt"], max_file_size=1024 * 1024)
        assert files == []

    def test_max_file_size(self, tmp_tree: Path) -> None:
        # Set a tiny max so even config.env is skipped
        files = discover_files([tmp_tree / "config.env"], max_file_size=5)
        assert files == []


class TestReadFileText:
    def test_reads_content(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello\nworld\n")
        content = read_file_text(f)
        assert content == "hello\nworld\n"

    def test_unreadable_returns_none(self, tmp_path: Path) -> None:
        f = tmp_path / "nope.txt"
        # File doesn't exist
        assert read_file_text(f) is None
