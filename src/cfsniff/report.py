"""Self-contained HTML report generator."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from cfsniff import __version__
from cfsniff.api import FileFinding
from cfsniff.output import ScanSummary

_SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f87171",
    "medium": "#facc15",
    "low": "#9ca3af",
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
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0f172a; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 2rem; }}
  .header {{ text-align: center; margin-bottom: 2rem; }}
  .header h1 {{ font-size: 1.8rem; margin-bottom: 0.25rem; }}
  .header .meta {{ color: #94a3b8; font-size: 0.85rem; }}
  .stats {{ display: flex; gap: 1.5rem; justify-content: center; margin-bottom: 2rem; flex-wrap: wrap; }}
  .stat {{ background: #1e293b; padding: 1rem 1.5rem; border-radius: 8px; text-align: center; }}
  .stat .number {{ font-size: 1.8rem; font-weight: 700; }}
  .stat .label {{ color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
  th {{ background: #334155; padding: 0.75rem 1rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; color: #94a3b8; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #334155; font-size: 0.9rem; }}
  td.file {{ font-weight: 600; color: #93c5fd; }}
  code {{ background: #334155; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }}
  .footer {{ text-align: center; margin-top: 2rem; color: #64748b; font-size: 0.8rem; }}
  .footer a {{ color: #60a5fa; text-decoration: none; }}
</style>
</head>
<body>
<div class="header">
    <h1>cfsniff audit report</h1>
    <div class="meta">v{__version__} &middot; {timestamp}</div>
</div>
<div class="stats">
    <div class="stat"><div class="number">{summary.total_findings}</div><div class="label">Secrets Found</div></div>
    <div class="stat"><div class="number">{summary.files_with_findings}</div><div class="label">Files Affected</div></div>
    <div class="stat"><div class="number">{summary.scanned_files}</div><div class="label">Files Scanned</div></div>
    <div class="stat"><div class="number" style="color:#f87171">{sev.get('high', 0) + sev.get('critical', 0)}</div><div class="label">High/Critical</div></div>
    <div class="stat"><div class="number" style="color:#facc15">{sev.get('medium', 0)}</div><div class="label">Medium</div></div>
</div>
<table>
    <thead><tr><th>File</th><th>Line</th><th>Type</th><th>Severity</th><th>Confidence</th><th>Preview</th></tr></thead>
    <tbody>{rows}</tbody>
</table>
<div class="footer">Powered by <a href="https://classifinder.ai">ClassiFinder</a></div>
</body>
</html>"""
