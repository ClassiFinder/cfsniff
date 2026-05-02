"""
cfsniff.version_check — pattern-set parity gate for --local-prefilter.

Pre-filter cannot run safely if the locally-installed classifinder-engine has a
narrower pattern set than the server. A user with a stale install would silently
miss secrets the API would catch — version skew here is a security defect, not
a drift problem.

This module:
1. Compares set(server_types[*].id) vs set(local_engine.pattern_ids).
2. Caches the server response on disk to avoid one round-trip per invocation.
3. Protects the cache with HMAC keyed by API-key material, so a forged file
   without the key cannot bypass the gate.
4. Sets 0700 on the cache directory and 0600 on cache files so a co-tenant
   on a shared box can't enumerate which API keys this user has used.
5. Rotates files with date prefixes older than 7 days.

Caller responsibility: invoke `get_or_fetch_server_types` once at command entry
(after client construction, before any per-file scan). Pass the result to
`compare_pattern_sets` to decide whether the pre-filter may run for this run.

Lazy-import contract: classifinder_engine is imported only inside
`local_pattern_ids()` to keep cold-start cost off non-audit code paths.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "cfsniff"
CACHE_RETENTION_DAYS = 7
_DATE_SUFFIX_RE = re.compile(r"-(\d{4}-\d{2}-\d{2})$")
_HMAC_DOMAIN = b"cfsniff-types-cache-v1|"


@dataclass(frozen=True)
class VersionCheckResult:
    """Outcome of comparing local engine pattern set vs server pattern set."""

    enabled: bool
    reason: str
    server_types: frozenset[str] = field(default_factory=frozenset)
    local_types: frozenset[str] = field(default_factory=frozenset)
    missing_local: frozenset[str] = field(default_factory=frozenset)
    extra_local: frozenset[str] = field(default_factory=frozenset)


# ─── Pattern-set primitives ────────────────────────────────────────────────────


def local_pattern_ids() -> frozenset[str]:
    """Return the set of pattern IDs registered in the locally-installed engine.

    Imports classifinder_engine lazily to keep startup cost off non-audit paths.
    """
    from classifinder_engine import PATTERN_REGISTRY

    return frozenset(p.id for p in PATTERN_REGISTRY)


def fetch_server_types(client) -> frozenset[str] | None:
    """Fetch /v1/types from the server. Returns None on any failure (fail closed)."""
    try:
        result = client.get_types()
        return frozenset(t.id for t in result.types)
    except Exception:
        return None


def compare_pattern_sets(
    server_types: frozenset[str], local_types: frozenset[str]
) -> VersionCheckResult:
    """Diagnose pattern-set skew between server and locally-installed engine.

    Disables the pre-filter if the local engine is missing any server pattern
    (would cause false negatives). Permits the pre-filter when local has extra
    patterns the server doesn't (cannot cause false negatives).
    """
    missing_local = server_types - local_types
    extra_local = local_types - server_types
    if missing_local:
        return VersionCheckResult(
            enabled=False,
            reason=(
                f"local engine missing {len(missing_local)} server pattern(s): "
                f"{sorted(missing_local)}; pre-filter disabled to avoid false negatives"
            ),
            server_types=server_types,
            local_types=local_types,
            missing_local=missing_local,
            extra_local=extra_local,
        )
    return VersionCheckResult(
        enabled=True,
        reason=(
            "local engine has extra patterns; safe (cannot cause false negatives)"
            if extra_local
            else "pattern sets match"
        ),
        server_types=server_types,
        local_types=local_types,
        missing_local=missing_local,
        extra_local=extra_local,
    )


# ─── Cache primitives (HMAC-protected, 0600/0700 perms, date-prefixed) ─────────


def _today_iso() -> str:
    """Today as YYYY-MM-DD in UTC. Wrapped for monkeypatching in tests."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _cache_filename(api_base_url: str, api_key: str, today: str) -> Path:
    """Derive a cache file path. Hashes (base_url, api_key) so the filename
    leaks neither the URL nor the key to a co-tenant listing the directory."""
    fingerprint = hashlib.sha256(f"{api_base_url}|{api_key}".encode()).hexdigest()[:16]
    return CACHE_DIR / f"types-{fingerprint}-{today}.json"


def _hmac_for(api_key: str, body: bytes) -> str:
    """Compute the cache integrity HMAC for a payload, keyed by API-key material.

    Forging the cache requires knowing the API key, not just having filesystem
    write access. Wrong key → wrong MAC → cache miss → re-fetch from /v1/types.
    """
    key = hashlib.sha256(_HMAC_DOMAIN + api_key.encode()).digest()
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def _ensure_cache_dir() -> None:
    """Create the cache dir at 0700, tightening perms if it already existed."""
    CACHE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if sys.platform != "win32":
        try:
            CACHE_DIR.chmod(0o700)
        except OSError:
            pass


def write_cache(api_base_url: str, api_key: str, types: list[str] | frozenset[str]) -> Path:
    """Persist a fetched server-types list with HMAC integrity. Returns the path.

    Atomic write via tmp file + replace, so a partial write can't be observed.
    """
    _ensure_cache_dir()
    today = _today_iso()
    path = _cache_filename(api_base_url, api_key, today)
    payload = {"types": sorted(types), "fetched_at": today}
    body = json.dumps(payload, sort_keys=True).encode()
    record = {"payload": payload, "hmac": _hmac_for(api_key, body)}

    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(record))
    if sys.platform != "win32":
        try:
            tmp.chmod(0o600)
        except OSError:
            pass
    tmp.replace(path)
    return path


def read_cache(api_base_url: str, api_key: str) -> frozenset[str] | None:
    """Read today's cache for the given key. Returns None on miss/tamper/error.

    Verifies the HMAC over the canonical (sorted-keys) JSON of the payload.
    Any mismatch — wrong key, mutated payload, mutated mac, malformed file —
    is treated as a cache miss and the caller will refetch.
    """
    today = _today_iso()
    path = _cache_filename(api_base_url, api_key, today)
    if not path.exists():
        return None
    try:
        record = json.loads(path.read_text())
        payload = record["payload"]
        provided_mac = record["hmac"]
        body = json.dumps(payload, sort_keys=True).encode()
        expected_mac = _hmac_for(api_key, body)
    except (OSError, ValueError, KeyError, TypeError):
        return None

    if not hmac.compare_digest(provided_mac, expected_mac):
        return None

    try:
        return frozenset(payload["types"])
    except (KeyError, TypeError):
        return None


def rotate_old_caches(retention_days: int = CACHE_RETENTION_DAYS) -> int:
    """Unlink cache files whose date prefix is older than retention_days.

    Date is parsed from the filename suffix, not the file's mtime, so copies
    or restores don't accidentally extend the lifetime of a stale entry.
    """
    if not CACHE_DIR.exists():
        return 0
    cutoff = date.today() - timedelta(days=retention_days)
    removed = 0
    for path in CACHE_DIR.glob("types-*.json"):
        m = _DATE_SUFFIX_RE.search(path.stem)
        if not m:
            continue
        try:
            file_date = datetime.strptime(m.group(1), "%Y-%m-%d").date()
        except ValueError:
            continue
        if file_date < cutoff:
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
    return removed


# ─── Orchestrator ──────────────────────────────────────────────────────────────


def get_or_fetch_server_types(
    client,
    api_base_url: str,
    api_key: str,
    *,
    use_cache: bool = True,
) -> frozenset[str] | None:
    """Cache-aware wrapper. Returns server type-id set or None on failure.

    Order: cache hit → server fetch → write cache → rotate old. Failures at any
    step return None and the caller is expected to fail closed (disable
    --local-prefilter for this run).
    """
    if use_cache:
        cached = read_cache(api_base_url, api_key)
        if cached is not None:
            return cached

    fetched = fetch_server_types(client)
    if fetched is None:
        return None
    write_cache(api_base_url, api_key, fetched)
    rotate_old_caches()
    return fetched
