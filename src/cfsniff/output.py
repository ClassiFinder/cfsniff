"""Terminal output formatters: rich, plain, and JSON."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from rich.console import Console

from cfsniff import __version__
from cfsniff.api import FileFinding

_HOME = str(Path.home())


def tilde_path(path: Path) -> str:
    """Replace the home directory prefix with ~ for display."""
    s = str(path)
    if s.startswith(_HOME):
        return "~" + s[len(_HOME):]
    return s

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
}


@dataclass
class ScanSummary:
    scanned_files: int
    total_findings: int
    files_with_findings: int
    by_severity: dict[str, int]


def format_plain(file_findings: list[tuple[Path, list[FileFinding]]]) -> list[str]:
    """Format findings as colon-delimited lines for piping."""
    lines: list[str] = []
    for path, findings in file_findings:
        for f in findings:
            lines.append(f"{tilde_path(path)}:{f.line}:{f.type}:{f.severity}:{f.confidence:.2f}:{f.value_preview}")
    return lines


def format_json(
    file_findings: list[tuple[Path, list[FileFinding]]],
    summary: ScanSummary,
) -> str:
    """Format findings as JSON."""
    findings_list = []
    for path, findings in file_findings:
        for f in findings:
            findings_list.append({
                "file": tilde_path(path),
                "line": f.line,
                "type": f.type,
                "type_name": f.type_name,
                "severity": f.severity,
                "confidence": f.confidence,
                "value_preview": f.value_preview,
                "span": {"start": f.span_start, "end": f.span_end},
            })

    exit_code = 2 if summary.total_findings > 0 else 0
    output = {
        "version": __version__,
        "scanned_files": summary.scanned_files,
        "findings": findings_list,
        "summary": asdict(summary),
        "exit_code": exit_code,
    }
    return json.dumps(output, indent=2)


def print_rich(
    file_findings: list[tuple[Path, list[FileFinding]]],
    summary: ScanSummary,
    console: Console | None = None,
    quiet: bool = False,
) -> None:
    """Print findings with rich formatting."""
    console = console or Console()

    if not file_findings:
        console.print(f"[green]No secrets found[/green] ({summary.scanned_files} files scanned)")
        return

    if not quiet:
        for path, findings in file_findings:
            console.print(f"\n[bold]{tilde_path(path)}[/bold]")
            for f in findings:
                color = SEVERITY_COLORS.get(f.severity, "")
                console.print(
                    f"  line {f.line:<6} | {f.type_name:<22} | [{color}]{f.severity:<8}[/{color}] | {f.confidence:.2f} | {f.value_preview}"
                )
        console.print()

    console.rule()
    sev = summary.by_severity
    console.print(
        f"  {summary.total_findings} secrets found across "
        f"{summary.files_with_findings} files ({summary.scanned_files} scanned)"
    )
    console.print(
        f"  [red]{sev.get('high', 0) + sev.get('critical', 0)} high[/red] · "
        f"[yellow]{sev.get('medium', 0)} medium[/yellow] · "
        f"[dim]{sev.get('low', 0)} low[/dim]"
    )
    console.rule()
    console.print()
