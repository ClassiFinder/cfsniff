"""ClassiFinder SDK wrapper — scan text and enrich results with line numbers."""

from __future__ import annotations

from dataclasses import dataclass

from classifinder import ClassiFinder


@dataclass
class FileFinding:
    """A single finding enriched with line number."""

    line: int
    type: str
    type_name: str
    severity: str
    confidence: float
    value_preview: str
    span_start: int
    span_end: int


def _offset_to_line(text: str, offset: int) -> int:
    """Convert a character offset to a 1-based line number."""
    return text[:offset].count("\n") + 1


def scan_text(
    client: ClassiFinder,
    text: str,
    min_confidence: float = 0.5,
) -> list[FileFinding]:
    """Scan text via the ClassiFinder API and return findings with line numbers."""
    if not text:
        result = client.scan(text, min_confidence=min_confidence)
        return []

    result = client.scan(text, min_confidence=min_confidence)

    return [
        FileFinding(
            line=_offset_to_line(text, f.span.start),
            type=f.type,
            type_name=f.type_name,
            severity=f.severity,
            confidence=f.confidence,
            value_preview=f.value_preview,
            span_start=f.span.start,
            span_end=f.span.end,
        )
        for f in result.findings
    ]
