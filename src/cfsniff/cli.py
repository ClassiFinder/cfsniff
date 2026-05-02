"""Click CLI entry point for cfsniff."""

from __future__ import annotations

import os
import sys
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from importlib.metadata import PackageNotFoundError, version as pkg_version
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TaskID, TextColumn, BarColumn, MofNCompleteColumn

from cfsniff import __version__
from cfsniff.api import FileFinding, scan_text
from cfsniff.audit import get_audit_locations, resolve_audit_files
from cfsniff.output import (
    ScanSummary,
    TimingRecord,
    format_json,
    format_plain,
    format_timing_stderr,
    print_rich,
    tilde_path,
)
from cfsniff.report import generate_html_report
from cfsniff.scanner import discover_files, read_file_text

from classifinder import ClassiFinder, RateLimitError
from classifinder._exceptions import AuthenticationError, ClassiFinderError

_DEFAULT_MAX_FILE_SIZE = 1024 * 1024  # 1 MB
_DEFAULT_BASE_URL = "https://api.classifinder.ai"


def _sdk_version() -> str:
    """Best-effort SDK version detection. Returns 'unknown' if not installed via pip."""
    try:
        return pkg_version("classifinder")
    except PackageNotFoundError:
        return "unknown"


def _percentile(values: list[float], pct: float) -> float:
    """Simple percentile (linear interpolation). Returns 0.0 for empty input."""
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    s = sorted(values)
    k = (len(s) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def _resolve_api_key(api_key: str | None) -> str | None:
    """Resolve API key from flag or environment variable."""
    return api_key or os.environ.get("CLASSIFINDER_API_KEY")


def _scan_one(
    client: ClassiFinder,
    path: Path,
    min_confidence: float,
    prefilter_enabled: bool = False,
) -> tuple[Path, list[FileFinding] | None, Exception | None, float, bool]:
    """Scan a single file. Returns (path, findings_or_None, error_or_None, elapsed_seconds, was_skipped).

    elapsed_seconds is wall-time around the scan_text() call only — does not
    include file read. Returned as 0.0 when the file is unreadable.

    When prefilter_enabled is True, run the local pre-filter before the API
    call. If it returns True, no API call is made and was_skipped is True
    (findings = []).
    """
    text = read_file_text(path)
    if text is None:
        return (path, None, None, 0.0, False)
    if prefilter_enabled:
        from cfsniff.prefilter import should_skip_api

        prefilter_start = time.perf_counter()
        if should_skip_api(text):
            return (path, [], None, time.perf_counter() - prefilter_start, True)
    start = time.perf_counter()
    try:
        findings = scan_text(client, text, min_confidence=min_confidence)
    except AuthenticationError:
        raise
    except ClassiFinderError as exc:
        return (path, None, exc, time.perf_counter() - start, False)
    return (path, findings, None, time.perf_counter() - start, False)


def _scan_files(
    client: ClassiFinder,
    files: list[Path],
    min_confidence: float,
    verbose: bool,
    console: Console,
    workers: int = 1,
    progress: Progress | None = None,
    task_id: TaskID | None = None,
    prefilter_enabled: bool = False,
) -> tuple[list[tuple[Path, list[FileFinding]]], list[tuple[Path, float, bool]], int]:
    """Scan a list of files. Returns (file_findings, per_file_timings, prefiltered_skips).

    per_file_timings is list[(path, elapsed_seconds, was_rate_limited)]. Files
    skipped by the pre-filter still produce a timing entry (useful for the
    speed report) but never count as rate-limited. Files that were unreadable
    are excluded from per_file_timings since the API was never called.

    When workers > 1, file scans run concurrently via a thread pool. The
    underlying API call is I/O-bound, so threads suffice (no GIL contention).
    """
    results: list[tuple[Path, list[FileFinding]]] = []
    timings: list[tuple[Path, float, bool]] = []
    skipped = 0

    def _record(
        path: Path,
        findings: list[FileFinding] | None,
        err: Exception | None,
        elapsed: float,
        was_skipped: bool,
    ) -> None:
        nonlocal skipped
        if progress and task_id is not None:
            progress.update(task_id, description=f"[dim]{path.name}[/dim]", advance=1)
        elif verbose:
            console.print(f"  [dim]scanning {path}[/dim]", highlight=False)
        if was_skipped:
            skipped += 1
        if findings is not None or err is not None:
            timings.append((path, elapsed, isinstance(err, RateLimitError)))
        if err is not None:
            click.echo(f"  error scanning {path}: {err.message}", err=True)  # type: ignore[attr-defined]
            return
        if findings is None:
            if verbose:
                console.print(f"  [yellow]skipped (unreadable): {path}[/yellow]")
            return
        if findings:
            results.append((path, findings))

    if workers <= 1 or len(files) <= 1:
        for path in files:
            _, findings, err, elapsed, was_skipped = _scan_one(
                client, path, min_confidence, prefilter_enabled=prefilter_enabled
            )
            _record(path, findings, err, elapsed, was_skipped)
        return results, timings, skipped

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_path = {
            pool.submit(
                _scan_one, client, path, min_confidence, prefilter_enabled
            ): path
            for path in files
        }
        for future in as_completed(future_to_path):
            path, findings, err, elapsed, was_skipped = future.result()
            _record(path, findings, err, elapsed, was_skipped)

    results.sort(key=lambda pair: pair[0])
    return results, timings, skipped


def _build_timing_record(
    timings: list[tuple[Path, float, bool]],
    wall_time_seconds: float,
    workers: int,
    base_url: str,
) -> TimingRecord:
    """Build a TimingRecord from per-file timings."""
    elapsed_ms = [e * 1000.0 for _, e, _ in timings]
    rate_limited = [tilde_path(p) for p, _, rl in timings if rl]
    return TimingRecord(
        cfsniff_version=__version__,
        sdk_version=_sdk_version(),
        base_url=base_url,
        workers=workers,
        wall_time_seconds=wall_time_seconds,
        file_count=len(timings),
        p50_per_file_ms=_percentile(elapsed_ms, 0.50),
        p95_per_file_ms=_percentile(elapsed_ms, 0.95),
        rate_limited_files=len(rate_limited),
        retries_exhausted=rate_limited,
    )


def _filter_severity(
    file_findings: list[tuple[Path, list[FileFinding]]],
    min_severity: str | None,
) -> list[tuple[Path, list[FileFinding]]]:
    """Filter findings by minimum severity."""
    if not min_severity:
        return file_findings
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold = order.get(min_severity, 0)
    filtered = []
    for path, findings in file_findings:
        kept = [f for f in findings if order.get(f.severity, 0) >= threshold]
        if kept:
            filtered.append((path, kept))
    return filtered


def _build_summary(
    file_findings: list[tuple[Path, list[FileFinding]]],
    scanned_files: int,
    prefiltered_skips: int = 0,
) -> ScanSummary:
    """Build a summary from results."""
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total = 0
    for _, findings in file_findings:
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            total += 1
    return ScanSummary(
        scanned_files=scanned_files,
        total_findings=total,
        files_with_findings=len(file_findings),
        by_severity=by_severity,
        prefiltered_skips=prefiltered_skips,
    )


def _output_results(
    file_findings: list[tuple[Path, list[FileFinding]]],
    summary: ScanSummary,
    fmt: str,
    report_path: str | None,
    open_report: bool,
    console: Console,
    quiet: bool = False,
    timing: TimingRecord | None = None,
) -> None:
    """Output results in the requested format and optionally generate a report.

    When timing is provided: rich/plain modes render it to stderr; json mode
    embeds it in the JSON envelope alongside summary and findings.
    """
    if fmt == "plain":
        if not quiet:
            for line in format_plain(file_findings):
                click.echo(line)
    elif fmt == "json":
        click.echo(format_json(file_findings, summary, timing=timing))
    else:
        print_rich(file_findings, summary, console=console, quiet=quiet)

    # Timing summary on stderr for non-JSON modes (JSON embeds it inline above).
    if timing is not None and fmt != "json":
        for line in format_timing_stderr(timing):
            click.echo(line, err=True)

    if report_path:
        report_out = Path(report_path)
        if report_out.is_dir():
            report_out = report_out / "report.html"
        html = generate_html_report(file_findings, summary)
        report_out.write_text(html)
        console.print(f"\n[green]Report written to {report_out}[/green]")
        if open_report:
            webbrowser.open(f"file://{report_out.resolve()}")


class _DefaultGroup(click.Group):
    """A Click group that routes unknown positional args to the 'scan' subcommand."""

    # Group-level options that consume the next token as their value
    _OPTIONS_WITH_VALUE = frozenset({
        "--api-key", "--format", "--min-confidence",
        "--min-severity", "--max-file-size", "--report", "--workers",
    })

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        if not args:
            args = ["scan"]
            return super().parse_args(ctx, args)

        # Walk through args to find the first positional (non-option) token
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "--":
                # Everything after -- is positional; insert scan before --
                args = args[:i] + ["scan"] + args[i:]
                break
            if arg in self._OPTIONS_WITH_VALUE:
                i += 2  # skip option and its value
                continue
            if arg.startswith("-"):
                i += 1  # flag like --verbose, --open, --version, --help, --clipboard
                continue
            # First positional arg found
            if arg not in self.commands:
                args = args[:i] + ["scan"] + args[i:]
            break
        else:
            # Ran out of args without finding a positional — all were options
            args.append("scan")

        return super().parse_args(ctx, args)


@click.group(cls=_DefaultGroup)
@click.option("--api-key", default=None, help="ClassiFinder API key")
@click.option("--format", "fmt", type=click.Choice(["rich", "plain", "json"]), default="rich", help="Output format")
@click.option("--min-confidence", type=float, default=0.5, help="Minimum confidence threshold")
@click.option("--min-severity", type=click.Choice(["low", "medium", "high", "critical"]), default=None, help="Minimum severity filter")
@click.option("--max-file-size", type=int, default=_DEFAULT_MAX_FILE_SIZE, help="Max file size in bytes")
@click.option("--report", default=None, type=click.Path(), help="Write HTML report to path")
@click.option("--open", "open_report", is_flag=True, help="Open HTML report in browser")
@click.option("--workers", type=int, default=8, show_default=True, help="Parallel scan workers (1 = sequential)")
@click.option("--verbose", is_flag=True, help="Show files being scanned")
@click.option("--quiet", is_flag=True, help="Only show summary, not individual findings")
@click.option("--timing", is_flag=True, help="Emit timing instrumentation (wall time, p50/p95, rate-limit counters)")
@click.version_option(__version__)
@click.pass_context
def main(
    ctx: click.Context,
    api_key: str | None,
    fmt: str,
    min_confidence: float,
    min_severity: str | None,
    max_file_size: int,
    report: str | None,
    open_report: bool,
    workers: int,
    verbose: bool,
    quiet: bool,
    timing: bool,
) -> None:
    """cfsniff — sniff out secrets in arbitrary text."""
    ctx.ensure_object(dict)
    ctx.obj["api_key"] = api_key
    ctx.obj["fmt"] = fmt
    ctx.obj["min_confidence"] = min_confidence
    ctx.obj["min_severity"] = min_severity
    ctx.obj["max_file_size"] = max_file_size
    ctx.obj["report"] = report
    ctx.obj["open_report"] = open_report
    ctx.obj["workers"] = max(1, workers)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet
    # CFSNIFF_TIMING=1 in env enables timing without the flag (per the plan's MVP spec).
    ctx.obj["timing"] = timing or os.environ.get("CFSNIFF_TIMING", "").lower() in {"1", "true", "yes"}


@main.command(hidden=True)
@click.argument("targets", nargs=-1, type=click.Path())
@click.option("--clipboard", is_flag=True, help="Scan clipboard contents")
@click.pass_context
def scan(
    ctx: click.Context,
    targets: tuple[str, ...],
    clipboard: bool,
) -> None:
    """Scan files, directories, or stdin for secrets (default command)."""
    obj = ctx.obj
    fmt = obj["fmt"]
    min_confidence = obj["min_confidence"]
    min_severity = obj["min_severity"]
    max_file_size = obj["max_file_size"]
    report = obj["report"]
    open_report = obj["open_report"]
    workers = obj["workers"]
    verbose = obj["verbose"]
    quiet = obj["quiet"]
    timing_enabled = obj.get("timing", False)

    console = Console(stderr=True) if fmt != "rich" else Console()

    # Check for stdin
    reading_stdin = not sys.stdin.isatty() or (targets and targets[0] == "-")

    # Check for clipboard
    clipboard_text = None
    if clipboard:
        try:
            import pyperclip
            clipboard_text = pyperclip.paste()
        except ImportError:
            click.echo("Error: clipboard support requires pyperclip. Run: pip install cfsniff[clipboard]", err=True)
            ctx.exit(1)
            return
        except Exception as exc:
            click.echo(f"Error reading clipboard: {exc}", err=True)
            ctx.exit(1)
            return

    if not targets and not reading_stdin and not clipboard:
        click.echo(ctx.parent.get_help() if ctx.parent else ctx.get_help())
        return

    # Resolve API key
    resolved_key = _resolve_api_key(obj["api_key"])
    if not resolved_key:
        click.echo(
            "Error: No API key found.\n\n"
            "Set CLASSIFINDER_API_KEY or pass --api-key.\n"
            "Get a key at https://classifinder.ai",
            err=True,
        )
        ctx.exit(1)
        return

    try:
        wall_start = time.perf_counter()
        with ClassiFinder(api_key=resolved_key) as client:
            all_file_findings: list[tuple[Path, list[FileFinding]]] = []
            scanned_count = 0
            per_file_timings: list[tuple[Path, float, bool]] = []

            def _scan_inline(label_path: Path, text: str) -> None:
                """Scan a string source (clipboard/stdin) inline and record timing.

                Empty input short-circuits without an API call, so it does NOT
                appear in per_file_timings — matches the file path's behavior
                where unreadable files are excluded from timing aggregates.
                """
                nonlocal scanned_count
                scanned_count += 1
                if not text:
                    return
                start = time.perf_counter()
                try:
                    findings = scan_text(client, text, min_confidence=min_confidence)
                except RateLimitError:
                    per_file_timings.append((label_path, time.perf_counter() - start, True))
                    return
                except ClassiFinderError:
                    per_file_timings.append((label_path, time.perf_counter() - start, False))
                    raise
                per_file_timings.append((label_path, time.perf_counter() - start, False))
                if findings:
                    all_file_findings.append((label_path, findings))

            # Scan clipboard
            if clipboard_text:
                _scan_inline(Path("<clipboard>"), clipboard_text)

            # Scan stdin
            if reading_stdin:
                stdin_text = sys.stdin.read()
                _scan_inline(Path("<stdin>"), stdin_text)

            # Scan file targets (exclude "-" which means stdin)
            file_targets = [Path(t) for t in targets if t != "-"]
            if file_targets:
                files = discover_files(file_targets, max_file_size=max_file_size)
                scanned_count += len(files)
                if fmt == "rich" and len(files) > 1 and not verbose:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        MofNCompleteColumn(),
                        console=console,
                        transient=True,
                    ) as progress:
                        tid = progress.add_task("Scanning...", total=len(files))
                        file_results, file_timings, _ = _scan_files(client, files, min_confidence, verbose, console, workers=workers, progress=progress, task_id=tid)
                else:
                    file_results, file_timings, _ = _scan_files(client, files, min_confidence, verbose, console, workers=workers)
                all_file_findings.extend(file_results)
                per_file_timings.extend(file_timings)

            wall_time = time.perf_counter() - wall_start

            # Build timing record if requested. Falls outside the scope guard
            # so reporting still happens even if findings is empty.
            timing_record: TimingRecord | None = None
            if timing_enabled:
                timing_record = _build_timing_record(
                    per_file_timings,
                    wall_time_seconds=wall_time,
                    workers=workers,
                    base_url=getattr(client, "_base_url", _DEFAULT_BASE_URL),
                )

            # Filter and output
            all_file_findings = _filter_severity(all_file_findings, min_severity)
            summary = _build_summary(all_file_findings, scanned_count)
            _output_results(all_file_findings, summary, fmt, report, open_report, console, quiet, timing=timing_record)

            # Exit code: 2 if secrets found, 0 if clean
            if summary.total_findings > 0:
                ctx.exit(2)

    except AuthenticationError:
        click.echo("Error: Invalid API key.", err=True)
        ctx.exit(1)
    except ClassiFinderError as exc:
        click.echo(f"Error: {exc.message}", err=True)
        ctx.exit(1)


@main.command()
@click.option("--include", multiple=True, help="Include optional categories (e.g., 'logs')")
@click.option("--api-key", default=None, help="ClassiFinder API key (overrides group option)")
@click.option("--format", "fmt", type=click.Choice(["rich", "plain", "json"]), default=None)
@click.option("--min-confidence", type=float, default=None)
@click.option("--min-severity", type=click.Choice(["low", "medium", "high", "critical"]), default=None)
@click.option("--max-file-size", type=int, default=None)
@click.option("--report", default=None, type=click.Path())
@click.option("--open", "open_report", is_flag=True, default=False)
@click.option("--workers", type=int, default=None, help="Parallel scan workers")
@click.option("--verbose", is_flag=True, default=False)
@click.option(
    "--local-prefilter",
    is_flag=True,
    default=False,
    help="Skip the API for files the local engine confirms are clean (size + entropy + zero-candidate gate).",
)
@click.option(
    "--no-version-cache",
    is_flag=True,
    default=False,
    help="Bypass the on-disk types cache and re-fetch /v1/types this run (only meaningful with --local-prefilter).",
)
@click.pass_context
def audit(
    ctx: click.Context,
    include: tuple[str, ...],
    api_key: str | None,
    fmt: str | None,
    min_confidence: float | None,
    min_severity: str | None,
    max_file_size: int | None,
    report: str | None,
    open_report: bool,
    workers: int | None,
    verbose: bool,
    local_prefilter: bool,
    no_version_cache: bool,
) -> None:
    """Audit your machine for secrets in non-code locations."""
    obj = ctx.obj or {}

    # Merge with group-level options (audit's own options take priority)
    api_key = api_key or obj.get("api_key")
    fmt = fmt or obj.get("fmt", "rich")
    min_confidence = min_confidence if min_confidence is not None else obj.get("min_confidence", 0.5)
    min_severity = min_severity or obj.get("min_severity")
    max_file_size = max_file_size if max_file_size is not None else obj.get("max_file_size", _DEFAULT_MAX_FILE_SIZE)
    report = report or obj.get("report")
    open_report = open_report or obj.get("open_report", False)
    workers = max(1, workers if workers is not None else obj.get("workers", 8))
    verbose = verbose or obj.get("verbose", False)
    quiet = obj.get("quiet", False)
    timing_enabled = obj.get("timing", False)

    console = Console(stderr=True) if fmt != "rich" else Console()

    resolved_key = _resolve_api_key(api_key)
    if not resolved_key:
        click.echo(
            "Error: No API key found.\n\n"
            "Set CLASSIFINDER_API_KEY or pass --api-key.\n"
            "Get a key at https://classifinder.ai",
            err=True,
        )
        ctx.exit(1)
        return

    include_logs = "logs" in include
    categories = get_audit_locations(include_logs=include_logs)
    audit_files = resolve_audit_files(categories)

    if fmt == "rich":
        console.print(f"\n[bold]cfsniff[/bold] v{__version__} — sniffing for secrets...\n")
        console.print(f"Scanning {len(audit_files)} files across {len(categories)} categories...\n")

    try:
        wall_start = time.perf_counter()
        with ClassiFinder(api_key=resolved_key) as client:
            all_file_findings: list[tuple[Path, list[FileFinding]]] = []
            per_file_timings: list[tuple[Path, float, bool]] = []
            prefiltered_skips = 0

            # Version-check gate. Pre-filter is only safe when local engine
            # patterns are a superset of server patterns; otherwise a stale
            # local install would silently miss real secrets.
            prefilter_enabled = False
            if local_prefilter:
                from cfsniff.version_check import (
                    compare_pattern_sets,
                    get_or_fetch_server_types,
                    local_pattern_ids,
                )

                base_url = getattr(client, "_base_url", _DEFAULT_BASE_URL)
                server_types = get_or_fetch_server_types(
                    client,
                    api_base_url=base_url,
                    api_key=resolved_key,
                    use_cache=not no_version_cache,
                )
                if server_types is None:
                    click.echo(
                        "warning: could not verify server pattern set; "
                        "--local-prefilter disabled for this run",
                        err=True,
                    )
                else:
                    decision = compare_pattern_sets(server_types, local_pattern_ids())
                    prefilter_enabled = decision.enabled
                    if not decision.enabled:
                        click.echo(f"warning: {decision.reason}", err=True)
                    elif verbose:
                        click.echo(f"[prefilter] {decision.reason}", err=True)

            use_progress = fmt == "rich" and not verbose and len(audit_files) > 0
            progress_ctx = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                console=console,
                transient=True,
            ) if use_progress else None

            with progress_ctx if progress_ctx else nullcontext():
                tid = progress_ctx.add_task("Sniffing...", total=len(audit_files)) if progress_ctx else None

                def _on_done(
                    path: Path,
                    findings: list[FileFinding] | None,
                    err: Exception | None,
                    elapsed: float,
                    was_skipped: bool,
                ) -> None:
                    nonlocal prefiltered_skips
                    if progress_ctx and tid is not None:
                        progress_ctx.update(tid, description=f"[dim]{path.name}[/dim]", advance=1)
                    elif verbose:
                        console.print(f"  [dim]scanning {path}[/dim]", highlight=False)
                    if err is not None and verbose:
                        click.echo(f"  error: {path}: {err.message}", err=True)  # type: ignore[attr-defined]
                    if was_skipped:
                        prefiltered_skips += 1
                    # Only record timing for files where the API was called.
                    if findings is not None or err is not None:
                        per_file_timings.append((path, elapsed, isinstance(err, RateLimitError)))
                    if findings:
                        all_file_findings.append((path, findings))

                paths = [path for _category, path in audit_files]
                if workers <= 1 or len(paths) <= 1:
                    for path in paths:
                        _, findings, err, elapsed, was_skipped = _scan_one(
                            client, path, min_confidence, prefilter_enabled=prefilter_enabled
                        )
                        _on_done(path, findings, err, elapsed, was_skipped)
                else:
                    with ThreadPoolExecutor(max_workers=workers) as pool:
                        futures = {
                            pool.submit(
                                _scan_one, client, p, min_confidence, prefilter_enabled
                            ): p
                            for p in paths
                        }
                        for fut in as_completed(futures):
                            path, findings, err, elapsed, was_skipped = fut.result()
                            _on_done(path, findings, err, elapsed, was_skipped)
                    all_file_findings.sort(key=lambda pair: pair[0])

            wall_time = time.perf_counter() - wall_start

            timing_record: TimingRecord | None = None
            if timing_enabled:
                timing_record = _build_timing_record(
                    per_file_timings,
                    wall_time_seconds=wall_time,
                    workers=workers,
                    base_url=getattr(client, "_base_url", _DEFAULT_BASE_URL),
                )

            all_file_findings = _filter_severity(all_file_findings, min_severity)
            summary = _build_summary(
                all_file_findings, len(audit_files), prefiltered_skips=prefiltered_skips
            )
            _output_results(all_file_findings, summary, fmt, report, open_report, console, quiet, timing=timing_record)

            if prefiltered_skips > 0 and fmt != "json":
                click.echo(
                    f"[prefilter] skipped {prefiltered_skips} file(s) "
                    f"({len(audit_files)} scanned total) — local engine confirmed clean",
                    err=True,
                )

            if summary.total_findings > 0:
                ctx.exit(2)

    except AuthenticationError:
        click.echo("Error: Invalid API key.", err=True)
        ctx.exit(1)
    except ClassiFinderError as exc:
        click.echo(f"Error: {exc.message}", err=True)
        ctx.exit(1)
