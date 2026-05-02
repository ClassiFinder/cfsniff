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
    prefiltered_skips: int = 0


@dataclass
class TimingRecord:
    """MVP timing instrumentation per the speed-enhancement plan.

    Required aggregates only. Sampled per-file records, slowest-N, schema
    versioning, and DNS/TLS breakdowns are deferred until step 2 of the
    Recommended sequence justifies them.
    """

    cfsniff_version: str
    sdk_version: str
    base_url: str
    workers: int
    wall_time_seconds: float
    file_count: int
    p50_per_file_ms: float
    p95_per_file_ms: float
    rate_limited_files: int
    retries_exhausted: list[str]


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
    timing: TimingRecord | None = None,
) -> str:
    """Format findings as JSON. Optionally embeds a `timing` object."""
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
    output: dict = {
        "version": __version__,
        "scanned_files": summary.scanned_files,
        "findings": findings_list,
        "summary": asdict(summary),
        "exit_code": exit_code,
    }
    if timing is not None:
        output["timing"] = asdict(timing)
    return json.dumps(output, indent=2)


def format_timing_stderr(timing: TimingRecord) -> list[str]:
    """Render a timing summary as plain-text lines (one per line) for stderr."""
    return [
        "",
        "── timing ──────────────────────────────",
        f"  wall time:           {timing.wall_time_seconds:.2f}s",
        f"  files:               {timing.file_count}",
        f"  p50 per file:        {timing.p50_per_file_ms:.0f}ms",
        f"  p95 per file:        {timing.p95_per_file_ms:.0f}ms",
        f"  rate-limited files:  {timing.rate_limited_files}",
        f"  cfsniff/sdk:         {timing.cfsniff_version} / {timing.sdk_version}",
        f"  workers:             {timing.workers}",
        f"  base url:            {timing.base_url}",
        "────────────────────────────────────────",
    ]


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
