"""Self-contained HTML report generator."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from cfsniff import __version__
from cfsniff.api import FileFinding
from cfsniff.output import ScanSummary

_SEVERITY_COLORS = {
    "critical": "#e85454",
    "high": "#e85454",
    "medium": "#e8a054",
    "low": "#6e6e82",
}


def generate_html_report(
    file_findings: list[tuple[Path, list[FileFinding]]],
    summary: ScanSummary,
) -> str:
    """Generate a self-contained HTML report string."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    rows = ""
    for path, findings in file_findings:
        for i, f in enumerate(findings):
            color = _SEVERITY_COLORS.get(f.severity, "#9ca3af")
            file_cell = html.escape(str(path)) if i == 0 else ""
            rows += f"""<tr>
                <td class="file">{file_cell}</td>
                <td>{f.line}</td>
                <td>{html.escape(f.type_name)}</td>
                <td style="color:{color}">{html.escape(f.severity)}</td>
                <td>{f.confidence:.2f}</td>
                <td><code>{html.escape(f.value_preview)}</code></td>
            </tr>\n"""

    sev = summary.by_severity

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>cfsniff audit report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700;900&family=DM+Mono:wght@400;500&family=Source+Serif+4:wght@400;600&display=swap" rel="stylesheet">
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0a0a0c; color: #c8c8d4; font-family: 'Source Serif 4', Georgia, serif; padding: 2rem 3rem; }}
  .header {{ text-align: center; margin-bottom: 2.5rem; }}
  .header h1 {{ font-family: 'Playfair Display', Georgia, serif; font-size: 2rem; font-weight: 900; color: #eeeef4; margin-bottom: 0.25rem; }}
  .header h1 em {{ font-style: italic; color: #5cdb5c; }}
  .header .meta {{ font-family: 'DM Mono', monospace; color: #6e6e82; font-size: 0.8rem; }}
  .stats {{ display: flex; gap: 1.5rem; justify-content: center; margin-bottom: 2.5rem; flex-wrap: wrap; }}
  .stat {{ background: #111116; border: 1px solid #222230; padding: 1rem 1.5rem; border-radius: 8px; text-align: center; }}
  .stat .number {{ font-family: 'DM Mono', monospace; font-size: 1.8rem; font-weight: 500; color: #eeeef4; }}
  .stat .label {{ font-family: 'DM Mono', monospace; color: #6e6e82; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #111116; border: 1px solid #222230; border-radius: 8px; overflow: hidden; }}
  th {{ background: #0a0a0c; padding: 0.75rem 1rem; text-align: left; font-family: 'DM Mono', monospace; font-size: 0.75rem; text-transform: uppercase; color: #6e6e82; letter-spacing: 0.05em; border-bottom: 1px solid #222230; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #222230; font-size: 0.9rem; }}
  td.file {{ font-family: 'DM Mono', monospace; font-weight: 500; color: #5cdb5c; font-size: 0.85rem; }}
  code {{ font-family: 'DM Mono', monospace; background: #16161d; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.8rem; color: #c8c8d4; }}
  .footer {{ text-align: center; margin-top: 2.5rem; font-family: 'DM Mono', monospace; color: #6e6e82; font-size: 0.75rem; }}
  .footer a {{ color: #5cdb5c; text-decoration: none; }}
  .footer a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="header">
    <h1><em>cfsniff</em> audit report</h1>
    <div class="meta">v{__version__} &middot; {timestamp}</div>
</div>
<div class="stats">
    <div class="stat"><div class="number">{summary.total_findings}</div><div class="label">Secrets Found</div></div>
    <div class="stat"><div class="number">{summary.files_with_findings}</div><div class="label">Files Affected</div></div>
    <div class="stat"><div class="number">{summary.scanned_files}</div><div class="label">Files Scanned</div></div>
    <div class="stat"><div class="number" style="color:#e85454">{sev.get('high', 0) + sev.get('critical', 0)}</div><div class="label">High/Critical</div></div>
    <div class="stat"><div class="number" style="color:#e8a054">{sev.get('medium', 0)}</div><div class="label">Medium</div></div>
</div>
<table>
    <thead><tr><th>File</th><th>Line</th><th>Type</th><th>Severity</th><th>Confidence</th><th>Preview</th></tr></thead>
    <tbody>{rows}</tbody>
</table>
<div class="footer">Powered by <a href="https://classifinder.ai">ClassiFinder</a></div>
</body>
</html>"""
