"""Audit mode — curated scan locations for non-code secrets."""

from __future__ import annotations

import glob
import platform
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AuditCategory:
    """A category of files to scan in audit mode."""

    name: str
    paths: list[Path] = field(default_factory=list)
    glob_patterns: list[str] = field(default_factory=list)
    max_glob_files: int = 50


def get_audit_locations(include_logs: bool = False) -> list[AuditCategory]:
    """Return the list of audit categories with their file paths."""
    home = Path.home()

    categories = [
        AuditCategory(
            name="Shell History",
            paths=[
                home / ".bash_history",
                home / ".zsh_history",
                home / ".local" / "share" / "fish" / "fish_history",
            ],
        ),
        AuditCategory(
            name="Shell Config",
            paths=[
                home / ".bashrc",
                home / ".zshrc",
                home / ".profile",
                home / ".bash_profile",
            ],
        ),
        AuditCategory(
            name="Environment",
            paths=[home / ".env"],
            glob_patterns=[
                str(home / ".env*"),
                str(home / "Desktop" / ".env*"),
                str(home / "Documents" / ".env*"),
                str(home / "Downloads" / ".env*"),
            ],
        ),
        AuditCategory(
            name="Cloud Credentials",
            paths=[
                home / ".aws" / "credentials",
                home / ".aws" / "config",
                home / ".azure" / "credentials",
                home / ".config" / "gcloud" / "application_default_credentials.json",
            ],
        ),
        AuditCategory(
            name="Package Managers",
            paths=[
                home / ".npmrc",
                home / ".pypirc",
                home / ".gem" / "credentials",
                home / ".composer" / "auth.json",
            ],
        ),
        AuditCategory(
            name="Container/K8s",
            paths=[
                home / ".docker" / "config.json",
                home / ".kube" / "config",
            ],
        ),
        AuditCategory(
            name="SSH",
            paths=[home / ".ssh" / "config"],
        ),
    ]

    if include_logs:
        log_category = AuditCategory(name="Logs", max_glob_files=50)
        if platform.system() == "Darwin":
            log_category.glob_patterns.append(str(home / "Library" / "Logs" / "**" / "*.log"))
        else:
            log_category.glob_patterns.append("/var/log/*.log")
        categories.append(log_category)

    return categories


def resolve_audit_files(
    categories: list[AuditCategory],
) -> list[tuple[AuditCategory, Path]]:
    """Resolve audit categories into (category, path) pairs for existing files."""
    result: list[tuple[AuditCategory, Path]] = []
    seen: set[Path] = set()

    for category in categories:
        # Resolve explicit paths
        for path in category.paths:
            resolved = path.expanduser().resolve()
            if resolved not in seen and resolved.is_file():
                seen.add(resolved)
                result.append((category, resolved))

        # Resolve glob patterns
        glob_files: list[Path] = []
        for pattern in category.glob_patterns:
            for match in glob.glob(pattern, recursive=True):
                p = Path(match).resolve()
                if p not in seen and p.is_file():
                    glob_files.append(p)
                    seen.add(p)

        # Sort by modification time (newest first), cap at max
        glob_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        for p in glob_files[: category.max_glob_files]:
            result.append((category, p))

    return result
