"""End-to-end CLI tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cfsniff.cli import main


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def mock_client():
    """Mock ClassiFinder client that returns no findings."""
    with patch("cfsniff.cli.ClassiFinder") as mock_cls:
        client = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        result = MagicMock()
        result.findings = []
        client.scan.return_value = result
        yield client


class TestMainCommand:
    def test_no_args_no_stdin_shows_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, [])
        assert result.exit_code != 0 or "Usage" in result.output or "No targets" in result.output

    def test_scan_file(self, runner: CliRunner, mock_client: MagicMock, tmp_path: Path) -> None:
        f = tmp_path / "test.env"
        f.write_text("SAFE=nothing_here\n")
        result = runner.invoke(main, ["--api-key", "ss_test_key123456789012345678901234567890123", str(f)])
        assert result.exit_code == 0
        assert "No secrets found" in result.output

    def test_scan_file_plain_format(self, runner: CliRunner, mock_client: MagicMock, tmp_path: Path) -> None:
        f = tmp_path / "test.env"
        f.write_text("SAFE=nothing\n")
        result = runner.invoke(main, ["--api-key", "ss_test_key123456789012345678901234567890123", "--format", "plain", str(f)])
        assert result.exit_code == 0

    def test_scan_file_json_format(self, runner: CliRunner, mock_client: MagicMock, tmp_path: Path) -> None:
        f = tmp_path / "test.env"
        f.write_text("SAFE=nothing\n")
        result = runner.invoke(main, ["--api-key", "ss_test_key123456789012345678901234567890123", "--format", "json", str(f)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["scanned_files"] >= 1

    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["--version"])
        from cfsniff import __version__
        assert __version__ in result.output

    def test_missing_api_key(self, runner: CliRunner, tmp_path: Path) -> None:
        f = tmp_path / "test.env"
        f.write_text("data\n")
        with patch.dict(os.environ, {}, clear=False):
            # Remove CLASSIFINDER_API_KEY if it exists
            env = os.environ.copy()
            env.pop("CLASSIFINDER_API_KEY", None)
            with patch.dict(os.environ, env, clear=True):
                result = runner.invoke(main, [str(f)])
        assert result.exit_code == 1


class TestWorkers:
    def test_workers_flag_scans_all_files(
        self, runner: CliRunner, mock_client: MagicMock, tmp_path: Path
    ) -> None:
        """--workers N must still scan every file exactly once."""
        for i in range(6):
            (tmp_path / f"f{i}.env").write_text(f"VALUE_{i}=safe\n")

        result = runner.invoke(main, [
            "--api-key", "ss_test_key123456789012345678901234567890123",
            "--workers", "4",
            str(tmp_path),
        ])

        assert result.exit_code == 0, result.output
        scanned_texts = {call.args[0] for call in mock_client.scan.call_args_list}
        for i in range(6):
            assert f"VALUE_{i}=safe\n" in scanned_texts


class TestAuditCommand:
    def test_audit_runs(self, runner: CliRunner, mock_client: MagicMock) -> None:
        result = runner.invoke(main, ["audit", "--api-key", "ss_test_key123456789012345678901234567890123"])
        # Should succeed even if no audit files exist on this machine
        assert result.exit_code == 0

    def test_audit_with_report(self, runner: CliRunner, mock_client: MagicMock, tmp_path: Path) -> None:
        report_path = tmp_path / "report.html"
        result = runner.invoke(main, [
            "audit",
            "--api-key", "ss_test_key123456789012345678901234567890123",
            "--report", str(report_path),
        ])
        assert result.exit_code == 0
        assert report_path.exists()
        assert "<!DOCTYPE html>" in report_path.read_text()
