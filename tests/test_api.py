"""Tests for the ClassiFinder API wrapper."""

from __future__ import annotations

from unittest.mock import MagicMock

from cfsniff.api import scan_text


def _make_mock_finding(
    *,
    type_name: str = "AWS Access Key",
    type: str = "aws_access_key",
    severity: str = "high",
    confidence: float = 0.95,
    value_preview: str = "AKIA****MPLE",
    span_start: int = 0,
    span_end: int = 20,
) -> MagicMock:
    finding = MagicMock()
    finding.type = type
    finding.type_name = type_name
    finding.severity = severity
    finding.confidence = confidence
    finding.value_preview = value_preview
    finding.span = MagicMock(start=span_start, end=span_end)
    return finding


class TestScanText:
    def test_returns_findings_with_line_numbers(self) -> None:
        text = "line one\nAKIAIOSFODNN7EXAMPLE\nline three\n"
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.findings = [
            _make_mock_finding(span_start=9, span_end=29),
        ]
        mock_client.scan.return_value = mock_result

        findings = scan_text(mock_client, text, min_confidence=0.5)

        assert len(findings) == 1
        assert findings[0].line == 2
        assert findings[0].type_name == "AWS Access Key"
        assert findings[0].severity == "high"

    def test_empty_text_returns_empty(self) -> None:
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.findings = []
        mock_client.scan.return_value = mock_result

        findings = scan_text(mock_client, "", min_confidence=0.5)
        assert findings == []

    def test_line_number_calculation(self) -> None:
        # "aaa\nbbb\nccc\n" — span in 3rd line starts at offset 8
        text = "aaa\nbbb\nccc\n"
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.findings = [
            _make_mock_finding(span_start=8, span_end=11),
        ]
        mock_client.scan.return_value = mock_result

        findings = scan_text(mock_client, text, min_confidence=0.5)
        assert findings[0].line == 3

    def test_deduplicates_same_type_and_preview_on_same_line(self) -> None:
        text = "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE\n"
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.findings = [
            _make_mock_finding(span_start=0, span_end=20, confidence=0.90),
            _make_mock_finding(span_start=21, span_end=41, confidence=0.95),
        ]
        mock_client.scan.return_value = mock_result

        findings = scan_text(mock_client, text, min_confidence=0.5)
        # Same line, same type, same preview — should deduplicate to one, keeping higher confidence
        assert len(findings) == 1
        assert findings[0].confidence == 0.95

    def test_keeps_different_types_on_same_line(self) -> None:
        text = "AKIAIOSFODNN7EXAMPLE sk_live_abc123\n"
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.findings = [
            _make_mock_finding(span_start=0, span_end=20, type="aws_access_key"),
            _make_mock_finding(span_start=21, span_end=35, type="stripe_secret_key", type_name="Stripe Key", value_preview="sk_l****c123"),
        ]
        mock_client.scan.return_value = mock_result

        findings = scan_text(mock_client, text, min_confidence=0.5)
        assert len(findings) == 2
