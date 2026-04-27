"""Deterministic generator for the cfsniff performance baseline corpus.

Produces a fixed file tree under `data/` that mirrors the file classes
`cfsniff audit` walks (shell history, configs, dotfiles, env files, logs,
seeded-secret files for regression detection). Same seed → byte-identical
output every run.

Used by the speed-enhancement plan's measurement step:
    cfsniff --timing --format json tests/fixtures/perf/data/

See ../../docs/perf-baselines/README.md for the schema of resulting
timing JSON files, and classifinder-knowledge/2026-04-24-cfsniff-speed-
enhancement.md for the broader plan.

Usage:
    python tests/fixtures/perf/generate.py            # writes ./data/
    python tests/fixtures/perf/generate.py --check    # verify determinism
"""

from __future__ import annotations

import argparse
import hashlib
import random
import shutil
from pathlib import Path

# Pinning the seed makes the corpus reproducible across machines.
# Bumping this is a breaking change to baseline comparability — don't do it
# casually. If the corpus needs to grow, prefer adding new files behind a
# feature flag in this script over re-seeding.
SEED = 0x_C5_5F_F1_FF  # "csniff" leetspeak, cute, also stable forever

# Canonical fake secrets used by the seeded files. These are AWS's own
# documentation examples — universally recognized as fake by secret scanners
# and safe to include in public test fixtures. NEVER seed real secrets here.
AWS_ACCESS_KEY_FAKE = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY_FAKE = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_PAT_FAKE = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
OPENAI_KEY_FAKE = "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
SLACK_TOKEN_FAKE = "xoxb-1111111111-2222222222-AbCdEfGhIjKlMnOpQrStUvWx"

# Realistic-looking command lines for shell history. Keeping a fixed pool
# rather than ad-hoc generation keeps the output deterministic regardless of
# Python version's iteration ordering.
_SHELL_COMMANDS = [
    "cd ~/projects/classifinder",
    "git status",
    "git log --oneline -10",
    "ls -la",
    "python -m pytest tests/",
    "ruff check .",
    "mypy src/",
    "docker ps",
    "kubectl get pods",
    "pip install -e .",
    "git diff",
    "git checkout main",
    "git pull",
    "cd ../classifinder-sdk",
    "git push origin feat/foo",
    "fly deploy",
    "fly logs",
    "echo 'hello world'",
    "vim README.md",
    "cat pyproject.toml",
    "find . -name '*.py'",
    "grep -r 'TODO' src/",
    "psql -h localhost -U me",
    "redis-cli ping",
    "curl https://api.classifinder.ai/v1/health",
]

_LOG_COMPONENTS = [
    "INFO", "WARN", "ERROR", "DEBUG",
    "auth.login", "scan.start", "scan.complete", "request.in", "request.out",
    "rate_limit.tick", "cache.hit", "cache.miss", "db.query",
]


def _detrand(seed_offset: int) -> random.Random:
    """Per-file-class RNG so adding a new class doesn't reshuffle others."""
    return random.Random(SEED + seed_offset)


def _write(path: Path, content: str) -> None:
    """Write a text file, creating parents. Idempotent."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def gen_shell_history(out: Path) -> None:
    """Synthetic .bash_history / .zsh_history files, ~50 KB each."""
    rng = _detrand(1)
    for name in (".bash_history", ".zsh_history"):
        lines = [rng.choice(_SHELL_COMMANDS) for _ in range(2000)]
        _write(out / "shell_history" / name, "\n".join(lines) + "\n")


def gen_shell_config(out: Path) -> None:
    """Synthetic .bashrc / .zshrc / .profile, small each."""
    rng = _detrand(2)
    for name in (".bashrc", ".zshrc", ".profile"):
        lines = [
            "# auto-generated benchmark fixture, not real config",
            'export PATH="$HOME/.local/bin:$PATH"',
            "export EDITOR=vim",
        ]
        for i in range(rng.randint(20, 40)):
            lines.append(f'alias g{i}="git status"')
        _write(out / "shell_config" / name, "\n".join(lines) + "\n")


def gen_env_files(out: Path) -> None:
    """Synthetic .env-style files, mostly clean placeholder values."""
    rng = _detrand(3)
    for name in (".env", ".env.local", ".env.example", ".env.development"):
        lines = [
            "# benchmark fixture, no real secrets",
            "DATABASE_URL=postgres://user:placeholder@localhost:5432/db",
            f"PORT={rng.randint(3000, 9000)}",
            f"DEBUG={'true' if rng.random() > 0.5 else 'false'}",
            f"LOG_LEVEL={rng.choice(['debug', 'info', 'warn'])}",
        ]
        for i in range(rng.randint(15, 30)):
            lines.append(f"FEATURE_FLAG_{i:02d}={'on' if rng.random() > 0.5 else 'off'}")
        _write(out / "env" / name, "\n".join(lines) + "\n")


def gen_cloud_creds(out: Path) -> None:
    """Synthetic AWS / Kube config files with PLACEHOLDER values, no secrets."""
    aws_creds = (
        "[default]\n"
        "# benchmark fixture, placeholder values only\n"
        "aws_access_key_id = PLACEHOLDER_NOT_A_REAL_KEY\n"
        "aws_secret_access_key = PLACEHOLDER_NOT_A_REAL_SECRET\n"
        "[work]\n"
        "aws_access_key_id = PLACEHOLDER_NOT_A_REAL_KEY_2\n"
        "aws_secret_access_key = PLACEHOLDER_NOT_A_REAL_SECRET_2\n"
    )
    _write(out / "cloud" / "aws_credentials", aws_creds)

    kube = "apiVersion: v1\nkind: Config\nclusters:\n"
    for i in range(20):
        kube += f"- name: cluster-{i}\n  cluster:\n    server: https://k8s-{i}.example.com\n"
    _write(out / "cloud" / "kube_config", kube)


def gen_package_configs(out: Path) -> None:
    """Synthetic .npmrc / .pypirc / etc."""
    npmrc = (
        "# benchmark fixture\n"
        "registry=https://registry.npmjs.org/\n"
        "save-exact=true\n"
    )
    _write(out / "packages" / ".npmrc", npmrc)

    pypirc = (
        "[distutils]\n"
        "index-servers = pypi\n"
        "[pypi]\n"
        "username = __token__\n"
        "password = PLACEHOLDER_NOT_A_REAL_TOKEN\n"
    )
    _write(out / "packages" / ".pypirc", pypirc)


def gen_ssh_config(out: Path) -> None:
    rng = _detrand(4)
    lines = ["# benchmark fixture"]
    for i in range(rng.randint(10, 20)):
        lines.append(f"Host host{i}.example.com")
        lines.append(f"  HostName {i+1}.{i+2}.{i+3}.{i+4}")
        lines.append("  User benchmark")
        lines.append(f"  Port {rng.randint(22, 2222)}")
        lines.append("")
    _write(out / "ssh" / "config", "\n".join(lines) + "\n")


def gen_logs(out: Path) -> None:
    """Mix of small, medium, and large log files. Mostly noise — no secrets."""
    rng = _detrand(5)

    def _log_line(rng: random.Random) -> str:
        ts = f"2026-04-{rng.randint(1, 25):02d}T{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}Z"
        comp = rng.choice(_LOG_COMPONENTS)
        msg = rng.choice([
            "request received",
            f"processed in {rng.randint(1, 500)}ms",
            "cache hit",
            "rate limit ok",
            f"queued task t{rng.randint(1000, 9999)}",
            f"user u{rng.randint(1, 1000)} action ok",
        ])
        return f"{ts} {comp} {msg}"

    # ~20 small logs, ~200 KB each
    for i in range(20):
        lines = [_log_line(rng) for _ in range(2500)]
        _write(out / "logs" / f"app_{i:02d}.log", "\n".join(lines) + "\n")

    # ~3 medium logs, ~2 MB each
    for i in range(3):
        lines = [_log_line(rng) for _ in range(25000)]
        _write(out / "logs" / f"big_{i:02d}.log", "\n".join(lines) + "\n")


def gen_seeded(out: Path) -> None:
    """Files with KNOWN-FAKE secrets so finding-count regressions are detectable.

    All values used here are AWS's own documentation examples or clearly-fake
    constants — universally recognized by secret scanners as non-credentials.
    Never replace these with real values.
    """
    leaked_env = (
        "# benchmark fixture — fake-format secrets only\n"
        f"AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY_FAKE}\n"
        f"AWS_SECRET_ACCESS_KEY={AWS_SECRET_KEY_FAKE}\n"
        "API_HOST=https://api.example.com\n"
    )
    _write(out / "seeded" / "leaked.env", leaked_env)

    notes = (
        "# Engineering notes — benchmark fixture\n\n"
        "Quick reminder for the new dev rotation:\n"
        f"- our prod AWS key starts with `{AWS_ACCESS_KEY_FAKE}` (yes I know, please rotate)\n"
        f"- github bot pat is `{GITHUB_PAT_FAKE}` (in vault as well)\n"
        "- everything else is in 1Password\n"
    )
    _write(out / "seeded" / "notes.md", notes)

    config_with_secret = (
        "{\n"
        '  "service": "ingest",\n'
        f'  "openai_key": "{OPENAI_KEY_FAKE}",\n'
        f'  "slack_webhook_token": "{SLACK_TOKEN_FAKE}",\n'
        '  "timeout_ms": 30000\n'
        "}\n"
    )
    _write(out / "seeded" / "service.json", config_with_secret)

    history_with_secret = (
        "ls -la\n"
        "git status\n"
        f"export AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY_FAKE}\n"
        f"export AWS_SECRET_ACCESS_KEY={AWS_SECRET_KEY_FAKE}\n"
        "aws s3 ls\n"
        "echo done\n"
    )
    _write(out / "seeded" / ".bash_history_seeded", history_with_secret)

    # One Python source file with an embedded fake key (often-missed code path).
    py = (
        "# benchmark fixture — fake API key only\n"
        f"API_KEY = \"{OPENAI_KEY_FAKE}\"\n\n"
        "def fetch():\n"
        "    return {\"ok\": True}\n"
    )
    _write(out / "seeded" / "client.py", py)


def generate(target: Path) -> None:
    """Wipe target/ and regenerate the full corpus."""
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    gen_shell_history(target)
    gen_shell_config(target)
    gen_env_files(target)
    gen_cloud_creds(target)
    gen_package_configs(target)
    gen_ssh_config(target)
    gen_logs(target)
    gen_seeded(target)


def corpus_fingerprint(target: Path) -> str:
    """Stable hash of the full corpus contents — for determinism checks."""
    h = hashlib.sha256()
    for path in sorted(target.rglob("*")):
        if path.is_file():
            rel = path.relative_to(target).as_posix()
            h.update(rel.encode())
            h.update(b"\0")
            h.update(path.read_bytes())
            h.update(b"\0")
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output", nargs="?", default=None,
        help="Output directory (default: data/ next to this script)",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Generate twice and verify byte-identical output (determinism check)",
    )
    args = parser.parse_args()

    target = Path(args.output) if args.output else Path(__file__).parent / "data"
    target = target.resolve()

    if args.check:
        # Generate to a tmp location twice, compare fingerprints.
        import tempfile
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            generate(Path(a))
            generate(Path(b))
            fa = corpus_fingerprint(Path(a))
            fb = corpus_fingerprint(Path(b))
        if fa != fb:
            raise SystemExit(f"FAIL: corpus is non-deterministic ({fa} != {fb})")
        print(f"OK: corpus is deterministic (sha256={fa[:16]}...)")
        return

    generate(target)
    file_count = sum(1 for _ in target.rglob("*") if _.is_file())
    total_bytes = sum(p.stat().st_size for p in target.rglob("*") if p.is_file())
    print(f"Wrote {file_count} files ({total_bytes / 1024 / 1024:.1f} MB) to {target}")
    print(f"Fingerprint: {corpus_fingerprint(target)[:16]}...")


if __name__ == "__main__":
    main()
