"""Tests for the --timing instrumentation MVP."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cfsniff.cli import _percentile, main
from cfsniff.output import TimingRecord, format_timing_stderr


@pytest.fixture
def runner() -> CliRunner:
    # Click 8.2+ separates stderr automatically; mix_stderr arg was removed.
    return CliRunner()


@pytest.fixture
def mock_clean_client():
    """Mock ClassiFinder that returns no findings on every scan."""
    with patch("cfsniff.cli.ClassiFinder") as mock_cls:
        client = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        client._base_url = "https://api.classifinder.ai"
        result = MagicMock()
        result.findings = []
        client.scan.return_value = result
        yield client


class TestPercentile:
    def test_empty_list_returns_zero(self) -> None:
        assert _percentile([], 0.5) == 0.0

    def test_single_value_returns_self_for_any_pct(self) -> None:
        assert _percentile([42.0], 0.5) == 42.0
        assert _percentile([42.0], 0.95) == 42.0

    def test_p50_of_evens(self) -> None:
        # p50 of [10, 20, 30, 40, 50] linear-interp = 30
        assert _percentile([10.0, 20.0, 30.0, 40.0, 50.0], 0.5) == 30.0

    def test_p95_picks_high_end(self) -> None:
        vals = [float(i) for i in range(1, 101)]  # 1..100
        # p95 with linear interpolation lands between 95 and 96
        assert 95.0 <= _percentile(vals, 0.95) <= 96.0

    def test_unsorted_input(self) -> None:
        # Should sort internally — order of input must not matter
        assert _percentile([50.0, 10.0, 30.0, 40.0, 20.0], 0.5) == 30.0


class TestFormatTimingStderr:
    def test_renders_required_fields(self) -> None:
        rec = TimingRecord(
            cfsniff_version="0.1.3",
            sdk_version="0.1.4",
            base_url="https://api.classifinder.ai",
            workers=8,
            wall_time_seconds=12.34,
            file_count=100,
            p50_per_file_ms=38.0,
            p95_per_file_ms=142.0,
            rate_limited_files=2,
            retries_exhausted=["~/.zsh_history", "~/.bash_history"],
        )
        lines = format_timing_stderr(rec)
        joined = "\n".join(lines)
        assert "wall time" in joined
        assert "12.34" in joined
        assert "p50" in joined and "38" in joined
        assert "p95" in joined and "142" in joined
        assert "rate-limited files" in joined and "2" in joined
        assert "0.1.3" in joined and "0.1.4" in joined
        assert "8" in joined  # workers
        assert "https://api.classifinder.ai" in joined


class TestTimingFlag:
    def test_no_timing_flag_no_timing_output(
        self, runner: CliRunner, mock_clean_client: MagicMock, tmp_path: Path
    ) -> None:
        """Default behavior: no --timing means no timing stderr block, no timing in JSON."""
        f = tmp_path / "test.env"
        f.write_text("HARMLESS=1\n")
        result = runner.invoke(
            main,
            ["--api-key", "ss_test_key123456789012345678901234567890123", str(f)],
        )
        assert result.exit_code == 0
        assert "── timing ──" not in (result.output + (result.stderr or ""))

    def test_timing_flag_emits_stderr_block_in_rich(
        self, runner: CliRunner, mock_clean_client: MagicMock, tmp_path: Path
    ) -> None:
        f = tmp_path / "test.env"
        f.write_text("HARMLESS=1\n")
        result = runner.invoke(
            main,
            ["--api-key", "ss_test_key123456789012345678901234567890123", "--timing", str(f)],
        )
        assert result.exit_code == 0
        # Timing summary lands on stderr in non-JSON modes.
        assert "timing" in (result.stderr or "").lower()
        assert "wall time" in (result.stderr or "").lower()

    def test_timing_flag_embeds_in_json_envelope(
        self, runner: CliRunner, mock_clean_client: MagicMock, tmp_path: Path
    ) -> None:
        f = tmp_path / "test.env"
        f.write_text("HARMLESS=1\n")
        result = runner.invoke(
            main,
            [
                "--api-key", "ss_test_key123456789012345678901234567890123",
                "--format", "json",
                "--timing",
                str(f),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "timing" in data
        t = data["timing"]
        assert t["file_count"] == 1
        assert "wall_time_seconds" in t
        assert "p50_per_file_ms" in t
        assert "p95_per_file_ms" in t
        assert t["rate_limited_files"] == 0
        assert t["retries_exhausted"] == []
        assert "cfsniff_version" in t
        assert "sdk_version" in t
        assert "base_url" in t
        assert t["workers"] >= 1
        # In JSON mode the timing block must NOT be duplicated on stderr
        # (would be confusing/redundant for piping).
        assert "── timing ──" not in (result.stderr or "")

    def test_timing_env_var_enables_without_flag(
        self, runner: CliRunner, mock_clean_client: MagicMock, tmp_path: Path
    ) -> None:
        f = tmp_path / "test.env"
        f.write_text("HARMLESS=1\n")
        result = runner.invoke(
            main,
            [
                "--api-key", "ss_test_key123456789012345678901234567890123",
                "--format", "json",
                str(f),
            ],
            env={"CFSNIFF_TIMING": "1"},
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "timing" in data

    def test_rate_limited_file_counted(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """When the SDK raises RateLimitError on a file, retries_exhausted lists it."""
        from classifinder import RateLimitError as SDKRateLimit
        with patch("cfsniff.cli.ClassiFinder") as mock_cls:
            client = MagicMock()
            mock_cls.return_value.__enter__ = MagicMock(return_value=client)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            client._base_url = "https://api.classifinder.ai"
            # First scan call raises RateLimitError (retry-exhausted from cfsniff's POV).
            client.scan.side_effect = SDKRateLimit("rate limit exceeded", retry_after=30)

            f = tmp_path / "test.env"
            f.write_text("HARMLESS=1\n")
            result = runner.invoke(
                main,
                [
                    "--api-key", "ss_test_key123456789012345678901234567890123",
                    "--format", "json",
                    "--timing",
                    str(f),
                ],
            )
            data = json.loads(result.stdout)
            assert data["timing"]["rate_limited_files"] == 1
            assert len(data["timing"]["retries_exhausted"]) == 1
