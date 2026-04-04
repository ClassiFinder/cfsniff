"""Tests for HTML report generation."""

from __future__ import annotations

from pathlib import Path

from cfsniff.api import FileFinding
from cfsniff.output import ScanSummary
from cfsniff.report import generate_html_report


def _finding(**kwargs) -> FileFinding:
    defaults = dict(
        line=10, type="aws_access_key", type_name="AWS Access Key",
        severity="high", confidence=0.95, value_preview="AKIA****MPLE",
        span_start=0, span_end=20,
    )
    defaults.update(kwargs)
    return FileFinding(**defaults)


class TestGenerateHtmlReport:
    def test_produces_valid_html(self, tmp_path: Path) -> None:
        file_findings = [(Path("/home/.env"), [_finding()])]
        summary = ScanSummary(
            scanned_files=5, total_findings=1,
            files_with_findings=1,
            by_severity={"critical": 0, "high": 1, "medium": 0, "low": 0},
        )
        html = generate_html_report(file_findings, summary)
        assert "<!DOCTYPE html>" in html
        assert "cfsniff" in html
        assert "AWS Access Key" in html
        assert "AKIA****MPLE" in html
        assert "ClassiFinder" in html

    def test_contains_summary_stats(self) -> None:
        summary = ScanSummary(
            scanned_files=42, total_findings=3,
            files_with_findings=2,
            by_severity={"critical": 0, "high": 2, "medium": 1, "low": 0},
        )
        html = generate_html_report(
            [(Path("/a"), [_finding()]), (Path("/b"), [_finding(), _finding()])],
            summary,
        )
        assert "42" in html  # scanned files
        assert "3" in html   # total findings

    def test_writes_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        summary = ScanSummary(
            scanned_files=1, total_findings=1,
            files_with_findings=1,
            by_severity={"critical": 0, "high": 1, "medium": 0, "low": 0},
        )
        html = generate_html_report(
            [(Path("/test"), [_finding()])], summary,
        )
        out.write_text(html)
        assert out.read_text().startswith("<!DOCTYPE html>")
