"""
Tests for cfsniff.prefilter — opt-in skip rule + bounded entropy + ReDoS timeout.

The pre-filter must be conservative: skipping the API is a security decision,
not just a speed one. Coverage here verifies the three gates (size, entropy,
local engine) all hold before a skip is granted, that env vars can disable
each gate, that >4MB files always go to the API, and that a hung pattern
can't lock up the audit run.
"""

from __future__ import annotations

import sys
import time

import pytest


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Strip prefilter env vars so each test starts from documented defaults."""
    monkeypatch.delenv("CFSNIFF_PREFILTER_MIN_BYTES", raising=False)
    monkeypatch.delenv("CFSNIFF_PREFILTER_MAX_ENTROPY_LEN", raising=False)


@pytest.fixture
def pf():
    from cfsniff import prefilter
    return prefilter


# ─── _has_high_entropy_token: bounded, token-based, skips short tokens ─────────


def test_high_entropy_returns_false_on_plain_prose(pf):
    text = "The quick brown fox jumps over the lazy dog. " * 100
    assert pf._has_high_entropy_token(text, min_token_len=20) is False


def test_high_entropy_returns_true_on_long_random_token(pf):
    # Long base64-style high-entropy token embedded in plain text.
    text = "config: token=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsT done"
    assert pf._has_high_entropy_token(text, min_token_len=20) is True


def test_high_entropy_skips_tokens_shorter_than_min_len(pf):
    # All tokens are short; even if some have entropy, they're below min length.
    text = "a1B2 c3D4 e5F6 g7H8 i9J0 k1L2 m3N4 o5P6 q7R8 s9T0 " * 20
    assert pf._has_high_entropy_token(text, min_token_len=20) is False


def test_high_entropy_returns_false_on_empty_string(pf):
    assert pf._has_high_entropy_token("", min_token_len=20) is False


def test_high_entropy_pre_scan_completes_under_50ms_per_mb(pf):
    """Performance budget: linear pass over 1 MB completes in < 50 ms on CI."""
    import secrets
    payload = secrets.token_urlsafe(1_000_000)  # ~1 MB of high-entropy chars
    start = time.perf_counter()
    pf._has_high_entropy_token(payload, min_token_len=20)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    # Generous on CI (50 ms target, 200 ms ceiling for jitter).
    assert elapsed_ms < 200, f"entropy pre-scan took {elapsed_ms:.1f} ms on 1 MB"


# ─── should_skip_api: the three-gate intersection (size, entropy, engine) ─────


def _large_clean_text(size_bytes: int = 100_000) -> str:
    """A blob > 64 KB with no high-entropy tokens and no real secrets."""
    return ("the quick brown fox jumps over the lazy dog. " * (size_bytes // 50))[:size_bytes]


def test_skip_returns_false_for_small_files(pf):
    """Small files (<= 64 KB) always go to the API regardless of content."""
    text = "small clean content " * 10  # ~200 bytes
    assert pf.should_skip_api(text) is False


def test_skip_returns_true_for_large_clean_file(pf):
    """Large file, no high-entropy tokens, no engine candidates → safe to skip."""
    text = _large_clean_text(100_000)
    assert pf.should_skip_api(text) is True


def test_skip_returns_false_when_high_entropy_substring_present(pf):
    """A long random-looking token forces the API path even if engine finds nothing."""
    text = _large_clean_text(80_000) + " token=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsT "
    assert pf.should_skip_api(text) is False


def test_skip_returns_false_when_engine_finds_candidate(pf):
    """A real AWS key inside an otherwise large file forces the API path."""
    text = _large_clean_text(80_000) + " AWS_KEY=AKIAJGKJHSKLDJFH3284 "
    assert pf.should_skip_api(text) is False


def test_skip_returns_false_for_files_over_4mb(pf):
    """> 4 MB files always go to the API (entropy/engine work would be wasted)."""
    text = "x" * (4 * 1024 * 1024 + 100)
    assert pf.should_skip_api(text) is False


# ─── Env var thresholds ────────────────────────────────────────────────────────


def test_env_var_min_bytes_zero_disables_skipping(pf, monkeypatch):
    """Setting CFSNIFF_PREFILTER_MIN_BYTES=0 forces every file to the API."""
    monkeypatch.setenv("CFSNIFF_PREFILTER_MIN_BYTES", "0")
    text = _large_clean_text(100_000)  # would normally skip
    assert pf.should_skip_api(text) is False


def test_env_var_max_entropy_len_zero_disables_skipping(pf, monkeypatch):
    """Setting CFSNIFF_PREFILTER_MAX_ENTROPY_LEN=0 forces every file to the API."""
    monkeypatch.setenv("CFSNIFF_PREFILTER_MAX_ENTROPY_LEN", "0")
    text = _large_clean_text(100_000)  # would normally skip
    assert pf.should_skip_api(text) is False


def test_env_var_min_bytes_lowered_lets_smaller_files_skip(pf, monkeypatch):
    """Lowering MIN_BYTES expands the skippable size range."""
    monkeypatch.setenv("CFSNIFF_PREFILTER_MIN_BYTES", "100")
    text = _large_clean_text(1000)  # 1 KB, normally too small
    assert pf.should_skip_api(text) is True


# ─── ReDoS protection: file-level timeout via concurrent.futures ──────────────


def test_redos_timeout_returns_none_when_engine_hangs(pf, monkeypatch):
    """If the local engine hangs, the prefilter falls back (treats as 'don't skip')."""
    # Patch the engine scan to sleep way past the timeout.
    import cfsniff.prefilter as prefilter_module

    def hung_scan(text, **kwargs):
        time.sleep(10)
        return []

    monkeypatch.setattr(prefilter_module, "_engine_scan", hung_scan)
    # With the hung scan, should_skip_api must NOT skip (fall back to API).
    text = _large_clean_text(100_000)
    start = time.perf_counter()
    result = pf.should_skip_api(text)
    elapsed = time.perf_counter() - start
    assert result is False
    # Should be bounded by REDOS_TIMEOUT_SECONDS plus small overhead.
    assert elapsed < 2.0, f"prefilter took {elapsed:.2f}s — timeout did not fire"


def test_redos_timeout_does_not_affect_normal_scans(pf):
    """Real engine scans of a clean file complete well under the ReDoS budget."""
    text = _large_clean_text(100_000)
    start = time.perf_counter()
    pf.should_skip_api(text)
    elapsed = time.perf_counter() - start
    # 500ms is the hard cap; normal scans should be well under it.
    assert elapsed < 1.0, f"normal scan took {elapsed:.2f}s"


# ─── Lazy-import contract ──────────────────────────────────────────────────────


def test_classifinder_engine_not_imported_at_module_load():
    """Importing cfsniff.prefilter must not pull in classifinder_engine."""
    for mod in list(sys.modules):
        if mod.startswith("cfsniff.prefilter") or mod.startswith("classifinder_engine"):
            del sys.modules[mod]
    import cfsniff.prefilter  # noqa: F401
    assert "classifinder_engine" not in sys.modules
