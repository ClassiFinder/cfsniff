# cfsniff

CLI tool that sniffs out secrets in arbitrary text using the ClassiFinder API. Scans files, directories, stdin, clipboard, and curated non-code locations (shell history, cloud credentials, configs, etc.).

## Tech Stack

- Python 3.10+
- Click (CLI framework)
- Rich (terminal formatting)
- classifinder SDK (API client)
- pyperclip (optional, clipboard support)

## Commands

```bash
pip install -e ".[dev]"              # install with dev deps
python -m pytest tests/ -v           # run all 34 tests
cfsniff --version                    # print version
cfsniff --help                       # show help
cfsniff <file|dir>                   # scan files/directories
echo "text" | cfsniff                # scan stdin
cfsniff --clipboard                  # scan clipboard
cfsniff audit                        # scan non-code locations on this machine
cfsniff audit --include logs         # include log files
cfsniff audit --report out.html      # generate HTML report
```

## Architecture

```
src/cfsniff/
  cli.py      — Click commands (main group + scan/audit subcommands)
  scanner.py  — File discovery, binary detection, size limits
  audit.py    — Curated scan locations (7 categories + optional logs)
  api.py      — ClassiFinder SDK wrapper, line number enrichment
  output.py   — Rich/plain/JSON formatters, ScanSummary dataclass
  report.py   — Self-contained HTML report generator (dark theme)
```

### Key Design Decisions

- **Click with _DefaultGroup**: `cfsniff myfile.env` routes to a hidden `scan` subcommand so variadic args and `cfsniff audit` coexist cleanly.
- **File-level batching**: Each file is one `/v1/scan` API call. No concatenation — preserves line numbers.
- **No concurrency**: Files scanned sequentially. Fine for dozens of files.
- **Value previews from API**: cfsniff never constructs masked values. Uses `value_preview` from ClassiFinder response.
- **Exit code 2**: Secrets found. Exit 0 = clean. Exit 1 = error. Useful for scripting.

## Auth

API key resolved in order: `--api-key` flag > `CLASSIFINDER_API_KEY` env var.

## Tests

34 tests across 6 files. All use mocked HTTP — no live API calls.

| File | What |
|------|------|
| `test_scanner.py` | File discovery, binary detection, size limits (9 tests) |
| `test_audit.py` | Location registry, glob resolution (6 tests) |
| `test_api.py` | SDK wrapper, line number calculation (3 tests) |
| `test_output.py` | Plain and JSON formatters (5 tests) |
| `test_report.py` | HTML report generation (3 tests) |
| `test_cli.py` | End-to-end CLI invocation (8 tests) |

## Dependencies on Other ClassiFinder Components

- **classifinder SDK** (`classifinder>=0.1.3`): API client. If SDK models change, update `api.py`.
- No dependency on the engine, server, site, or MCP server.

## Design Docs

- `../classifinder/docs/specs/2026-04-04-cfsniff-design.md` — Design spec
- `../classifinder/docs/specs/2026-04-04-cfsniff-plan.md` — Implementation plan
