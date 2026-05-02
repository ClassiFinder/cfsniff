"""
Tests for cfsniff.version_check — pattern-set comparison + on-disk cache.

The cache is a security gate: if it's forged or tampered, --local-prefilter
could silently bypass the version-skew check and miss secrets the API would
catch. Coverage here is heavier than typical unit-test density on purpose.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path

import pytest


# Import lazily inside fixtures/tests so monkeypatching the module's CACHE_DIR
# is reliable. Module-level imports cache attribute lookups on test discovery.


@pytest.fixture
def vc(tmp_path, monkeypatch):
    """Yield the version_check module with CACHE_DIR pointing at tmp_path."""
    from cfsniff import version_check
    monkeypatch.setattr(version_check, "CACHE_DIR", tmp_path / "cache")
    return version_check


# ─── _cache_filename / _hmac_for primitives ────────────────────────────────────

def test_cache_filename_is_stable_for_same_inputs(vc):
    p1 = vc._cache_filename("https://api.example.com", "ss_test_key", "2026-05-01")
    p2 = vc._cache_filename("https://api.example.com", "ss_test_key", "2026-05-01")
    assert p1 == p2


def test_cache_filename_changes_with_different_keys(vc):
    p1 = vc._cache_filename("https://api.example.com", "ss_test_key_a", "2026-05-01")
    p2 = vc._cache_filename("https://api.example.com", "ss_test_key_b", "2026-05-01")
    assert p1 != p2


def test_cache_filename_does_not_contain_raw_api_key(vc):
    api_key = "ss_test_supersecretkey1234567890abcdef"
    p = vc._cache_filename("https://api.example.com", api_key, "2026-05-01")
    assert api_key not in str(p)
    assert "ss_test_" not in str(p)


def test_hmac_for_is_deterministic(vc):
    body = b'{"types":["a","b"]}'
    h1 = vc._hmac_for("ss_test_key", body)
    h2 = vc._hmac_for("ss_test_key", body)
    assert h1 == h2


def test_hmac_for_changes_with_different_keys(vc):
    body = b'{"types":["a","b"]}'
    h1 = vc._hmac_for("ss_test_key_a", body)
    h2 = vc._hmac_for("ss_test_key_b", body)
    assert h1 != h2


# ─── write_cache / read_cache roundtrip ────────────────────────────────────────

def test_write_then_read_cache_roundtrip(vc):
    types = ["aws_access_key", "stripe_live_secret_key", "github_pat"]
    vc.write_cache("https://api.example.com", "ss_test_key", types)
    cached = vc.read_cache("https://api.example.com", "ss_test_key")
    assert cached == frozenset(types)


def test_read_cache_returns_none_when_no_file(vc):
    cached = vc.read_cache("https://api.example.com", "ss_test_key")
    assert cached is None


def test_read_cache_returns_none_when_payload_tampered(vc):
    vc.write_cache("https://api.example.com", "ss_test_key", ["aws_access_key"])
    today = vc._today_iso()
    path = vc._cache_filename("https://api.example.com", "ss_test_key", today)
    record = json.loads(path.read_text())
    # Tamper: add a new type without recomputing the HMAC.
    record["payload"]["types"].append("attacker_inserted_pattern")
    path.write_text(json.dumps(record))
    assert vc.read_cache("https://api.example.com", "ss_test_key") is None


def test_read_cache_returns_none_when_hmac_tampered(vc):
    vc.write_cache("https://api.example.com", "ss_test_key", ["aws_access_key"])
    today = vc._today_iso()
    path = vc._cache_filename("https://api.example.com", "ss_test_key", today)
    record = json.loads(path.read_text())
    record["hmac"] = "0" * 64  # plausible-looking but wrong
    path.write_text(json.dumps(record))
    assert vc.read_cache("https://api.example.com", "ss_test_key") is None


def test_attacker_without_api_key_cannot_forge_cache(vc):
    """An attacker with filesystem write access but not the API key must not be
    able to plant a cache file that passes HMAC verification."""
    today = vc._today_iso()
    path = vc._cache_filename("https://api.example.com", "real_api_key", today)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Attacker forges a payload signed with the WRONG key.
    payload = {"types": ["aws_access_key"], "fetched_at": today}
    body = json.dumps(payload, sort_keys=True).encode()
    forged_mac = vc._hmac_for("attacker_guessed_key", body)
    record = {"payload": payload, "hmac": forged_mac}
    path.write_text(json.dumps(record))

    assert vc.read_cache("https://api.example.com", "real_api_key") is None


# ─── File system permissions (CSO requirement) ─────────────────────────────────

@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
def test_cache_dir_is_0700_after_write(vc):
    vc.write_cache("https://api.example.com", "ss_test_key", ["a"])
    mode = oct(vc.CACHE_DIR.stat().st_mode)[-3:]
    assert mode == "700"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
def test_cache_file_is_0600_after_write(vc):
    vc.write_cache("https://api.example.com", "ss_test_key", ["a"])
    today = vc._today_iso()
    path = vc._cache_filename("https://api.example.com", "ss_test_key", today)
    mode = oct(path.stat().st_mode)[-3:]
    assert mode == "600"


# ─── Rotation: date-prefixed cache files older than retention are unlinked ─────

def test_rotate_old_caches_removes_files_older_than_retention(vc):
    vc.CACHE_DIR.mkdir(parents=True, mode=0o700)
    from datetime import date, timedelta
    today = date.today()
    fingerprint = "abcdef1234567890"
    # Create files dated 1, 5, 8, and 14 days ago. Retention is 7 days.
    for days_ago in (1, 5, 8, 14):
        d = (today - timedelta(days=days_ago)).strftime("%Y-%m-%d")
        f = vc.CACHE_DIR / f"types-{fingerprint}-{d}.json"
        f.write_text("{}")

    removed = vc.rotate_old_caches(retention_days=7)
    assert removed == 2  # 8 days and 14 days ago
    remaining = sorted(p.name for p in vc.CACHE_DIR.glob("types-*.json"))
    # The 1-day and 5-day files should remain; 8 and 14 should be gone.
    for d in (1, 5):
        date_str = (today - timedelta(days=d)).strftime("%Y-%m-%d")
        assert any(date_str in n for n in remaining)


def test_rotate_old_caches_handles_missing_dir(vc):
    # Don't create CACHE_DIR. rotate should not raise.
    assert vc.rotate_old_caches() == 0


def test_rotate_old_caches_ignores_unparseable_filenames(vc):
    vc.CACHE_DIR.mkdir(parents=True, mode=0o700)
    (vc.CACHE_DIR / "types-not-a-date.json").write_text("{}")
    (vc.CACHE_DIR / "types-fingerprint-9999-99-99.json").write_text("{}")
    # Should not crash and should not remove these (it just skips them).
    removed = vc.rotate_old_caches(retention_days=7)
    assert removed == 0


# ─── 24h TTL behavior ──────────────────────────────────────────────────────────

def test_yesterdays_cache_is_a_miss_for_todays_path(vc, monkeypatch):
    """Cache filenames are date-stamped, so yesterday's file at yesterday's path
    is invisible to today's lookup — natural 24h TTL."""
    from datetime import date, timedelta
    yesterday = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")
    monkeypatch.setattr(vc, "_today_iso", lambda: yesterday)
    vc.write_cache("https://api.example.com", "ss_test_key", ["a"])
    # Now look up with "today's" date: cache miss.
    monkeypatch.setattr(vc, "_today_iso", lambda: date.today().strftime("%Y-%m-%d"))
    assert vc.read_cache("https://api.example.com", "ss_test_key") is None


# ─── compare_pattern_sets ──────────────────────────────────────────────────────

def test_compare_pattern_sets_match_enables_prefilter(vc):
    server = frozenset({"aws", "stripe", "github"})
    local = frozenset({"aws", "stripe", "github"})
    r = vc.compare_pattern_sets(server, local)
    assert r.enabled is True


def test_compare_pattern_sets_missing_local_disables_prefilter(vc):
    """Server has patterns the local engine doesn't — risk of false negatives → fail closed."""
    server = frozenset({"aws", "stripe", "github", "new_pattern"})
    local = frozenset({"aws", "stripe", "github"})
    r = vc.compare_pattern_sets(server, local)
    assert r.enabled is False
    assert "new_pattern" in r.reason


def test_compare_pattern_sets_extra_local_still_enables(vc):
    """Local has patterns the server doesn't — cannot cause false negatives, allow."""
    server = frozenset({"aws", "stripe"})
    local = frozenset({"aws", "stripe", "ahead_of_server"})
    r = vc.compare_pattern_sets(server, local)
    assert r.enabled is True
    assert r.extra_local == frozenset({"ahead_of_server"})


# ─── fetch_server_types fails closed ───────────────────────────────────────────

def test_fetch_server_types_returns_none_on_exception(vc):
    class Boom:
        def get_types(self):
            raise RuntimeError("network down")
    assert vc.fetch_server_types(Boom()) is None


def test_fetch_server_types_returns_set_on_success(vc):
    class FakeTypes:
        def __init__(self, ids):
            self.types = [type("T", (), {"id": i})() for i in ids]
    class Client:
        def get_types(self):
            return FakeTypes(["aws_access_key", "stripe_live_secret_key"])
    result = vc.fetch_server_types(Client())
    assert result == frozenset({"aws_access_key", "stripe_live_secret_key"})


# ─── get_or_fetch_server_types orchestrator ────────────────────────────────────

def test_get_or_fetch_uses_cache_on_subsequent_call(vc):
    calls = []
    class Client:
        def get_types(self):
            calls.append(1)
            return type("R", (), {"types": [type("T", (), {"id": "aws"})()]})()

    first = vc.get_or_fetch_server_types(Client(), "https://api.example.com", "ss_test_key")
    second = vc.get_or_fetch_server_types(Client(), "https://api.example.com", "ss_test_key")

    assert first == frozenset({"aws"})
    assert second == frozenset({"aws"})
    assert len(calls) == 1, "second call should hit cache, not server"


def test_get_or_fetch_skips_cache_when_use_cache_false(vc):
    calls = []
    class Client:
        def get_types(self):
            calls.append(1)
            return type("R", (), {"types": [type("T", (), {"id": "aws"})()]})()

    vc.get_or_fetch_server_types(Client(), "https://api.example.com", "ss_test_key")
    vc.get_or_fetch_server_types(Client(), "https://api.example.com", "ss_test_key", use_cache=False)
    assert len(calls) == 2, "use_cache=False must force a fresh fetch"


def test_get_or_fetch_returns_none_on_fetch_failure_with_no_cache(vc):
    class Boom:
        def get_types(self):
            raise RuntimeError("offline")
    assert vc.get_or_fetch_server_types(Boom(), "https://api.example.com", "ss_test_key") is None


# ─── local_pattern_ids: lazy import of classifinder_engine ─────────────────────

def test_local_pattern_ids_returns_nonempty_set(vc):
    ids = vc.local_pattern_ids()
    assert isinstance(ids, frozenset)
    assert len(ids) > 0
    # Sanity check: at least one well-known pattern.
    assert "aws_access_key" in ids


def test_classifinder_engine_not_imported_at_module_load():
    """Lazy-import contract: importing cfsniff.version_check itself must not pull
    in classifinder_engine. It loads only when local_pattern_ids() is called."""
    # Force a fresh import in a subprocess-like way: clear and re-import.
    for mod in list(sys.modules):
        if mod.startswith("cfsniff.version_check") or mod.startswith("classifinder_engine"):
            del sys.modules[mod]
    import cfsniff.version_check  # noqa: F401
    assert "classifinder_engine" not in sys.modules
