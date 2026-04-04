"""Tests for output formatters."""

from __future__ import annotations

import json
from pathlib import Path

from cfsniff.api import FileFinding
from cfsniff.output import format_json, format_plain, ScanSummary


def _finding(
    *,
    line: int = 10,
    type: str = "aws_access_key",
    type_name: str = "AWS Access Key",
    severity: str = "high",
    confidence: float = 0.95,
    value_preview: str = "AKIA****MPLE",
) -> FileFinding:
    return FileFinding(
        line=line,
        type=type,
        type_name=type_name,
        severity=severity,
        confidence=confidence,
        value_preview=value_preview,
        span_start=0,
        span_end=20,
    )


class TestFormatPlain:
    def test_single_finding(self) -> None:
        file_findings = [(Path("/home/user/.env"), [_finding()])]
        lines = format_plain(file_findings)
        assert lines == ["/home/user/.env:10:aws_access_key:high:0.95:AKIA****MPLE"]

    def test_multiple_findings(self) -> None:
        file_findings = [
            (Path("/home/.env"), [_finding(line=1), _finding(line=5, type="stripe_secret_key", type_name="Stripe Key", severity="medium", confidence=0.88, value_preview="sk_l****789")]),
        ]
        lines = format_plain(file_findings)
        assert len(lines) == 2
        assert "stripe_secret_key" in lines[1]

    def test_empty_findings(self) -> None:
        lines = format_plain([])
        assert lines == []


class TestFormatJson:
    def test_structure(self) -> None:
        file_findings = [(Path("/home/.env"), [_finding()])]
        summary = ScanSummary(scanned_files=5, total_findings=1, files_with_findings=1, by_severity={"critical": 0, "high": 1, "medium": 0, "low": 0})
        data = json.loads(format_json(file_findings, summary))
        assert data["scanned_files"] == 5
        assert len(data["findings"]) == 1
        assert data["findings"][0]["file"] == "/home/.env"
        assert data["findings"][0]["line"] == 10
        assert data["summary"]["total_findings"] == 1

    def test_empty(self) -> None:
        summary = ScanSummary(scanned_files=0, total_findings=0, files_with_findings=0, by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0})
        data = json.loads(format_json([], summary))
        assert data["findings"] == []
