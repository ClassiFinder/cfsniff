"""Tests for audit location registry."""

from __future__ import annotations

from pathlib import Path

from cfsniff.audit import AuditCategory, get_audit_locations, resolve_audit_files


class TestGetAuditLocations:
    def test_returns_categories(self) -> None:
        categories = get_audit_locations(include_logs=False)
        names = [c.name for c in categories]
        assert "Shell History" in names
        assert "Shell Config" in names
        assert "Cloud Credentials" in names
        assert "Package Managers" in names
        assert "Container/K8s" in names
        assert "SSH" in names

    def test_logs_excluded_by_default(self) -> None:
        categories = get_audit_locations(include_logs=False)
        names = [c.name for c in categories]
        assert "Logs" not in names

    def test_logs_included_when_requested(self) -> None:
        categories = get_audit_locations(include_logs=True)
        names = [c.name for c in categories]
        assert "Logs" in names


class TestResolveAuditFiles:
    def test_skips_nonexistent_paths(self, tmp_path: Path) -> None:
        category = AuditCategory(
            name="Test",
            paths=[tmp_path / "does_not_exist.txt"],
        )
        files = resolve_audit_files([category])
        assert files == []

    def test_resolves_existing_paths(self, tmp_path: Path) -> None:
        real_file = tmp_path / "secret.env"
        real_file.write_text("SECRET=abc123\n")
        category = AuditCategory(
            name="Test",
            paths=[real_file, tmp_path / "nope.txt"],
        )
        files = resolve_audit_files([category])
        assert len(files) == 1
        assert files[0] == (category, real_file)

    def test_glob_patterns_in_paths(self, tmp_path: Path) -> None:
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        (logs_dir / "app.log").write_text("log data\n")
        (logs_dir / "error.log").write_text("error data\n")
        category = AuditCategory(
            name="Logs",
            glob_patterns=[str(logs_dir / "*.log")],
            max_glob_files=50,
        )
        files = resolve_audit_files([category])
        assert len(files) == 2
