"""
cfsniff.prefilter — opt-in skip rule for files that almost certainly contain no secrets.

Three gates must all pass before a file is allowed to skip the API:
  1. Size is in [MIN_BYTES, 4 MB]. Tiny files aren't worth a local pre-scan;
     huge files would burn CPU on regex work that the API does anyway.
  2. No token of length >= MAX_ENTROPY_LEN has Shannon entropy above the
     high-entropy threshold. Tokenization splits on whitespace and common
     structural separators so `key=AbCd...` exposes the value as its own token.
  3. The local engine reports zero candidates within REDOS_TIMEOUT_SECONDS.
     The timeout caps pathological regex inputs (ReDoS) — on timeout the file
     falls through to the API.

Setting CFSNIFF_PREFILTER_MIN_BYTES=0 or CFSNIFF_PREFILTER_MAX_ENTROPY_LEN=0
disables skipping entirely so an operator can force every file to the API.

Lazy-import contract: classifinder_engine is imported only inside `_engine_scan`,
not at module load. Non-audit code paths never pay the import cost.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any

_DEFAULT_PREFILTER_MIN_BYTES = 64 * 1024
_DEFAULT_PREFILTER_MAX_ENTROPY_LEN = 20
MAX_PREFILTER_BYTES = 4 * 1024 * 1024
REDOS_TIMEOUT_SECONDS = 0.5

_HIGH_ENTROPY_THRESHOLD = 3.5
_TOKEN_SPLIT_RE = re.compile(r"[\s,;=:\"'()\[\]{}<>]+")


def _shannon_entropy(s: str) -> float:
    if len(s) <= 1:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _has_high_entropy_token(text: str, min_token_len: int) -> bool:
    """
    True if any token of length >= min_token_len has Shannon entropy above the
    high-entropy threshold. Bounded by tokenization: O(len(text)) for the split
    plus O(token) per entropy computation.
    """
    if not text:
        return False
    for token in _TOKEN_SPLIT_RE.split(text):
        if len(token) < min_token_len:
            continue
        if _shannon_entropy(token) >= _HIGH_ENTROPY_THRESHOLD:
            return True
    return False


def _engine_scan(text: str) -> list[Any]:
    """Lazy-imported wrapper around classifinder_engine.scan.

    Calls the engine at min_confidence=0.0 deliberately. The pre-filter uses
    the engine as a 'did anything match at all?' detector, not as a final
    classifier — any candidate (even a synthetic test value clamped to 0.15
    or a generic_high_entropy match at 0.47) must force the API path.
    Filtering here would silently miss real findings the API would catch.
    """
    from classifinder_engine.scanner import scan

    return scan(text, min_confidence=0.0)


def _read_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def should_skip_api(text: str) -> bool:
    """
    Return True only if all three gates pass: size band, zero high-entropy
    tokens, and zero local-engine candidates within the ReDoS budget. Any
    failure — including a timeout — returns False so the file falls back to
    the API.
    """
    min_bytes = _read_int_env("CFSNIFF_PREFILTER_MIN_BYTES", _DEFAULT_PREFILTER_MIN_BYTES)
    max_entropy_len = _read_int_env(
        "CFSNIFF_PREFILTER_MAX_ENTROPY_LEN", _DEFAULT_PREFILTER_MAX_ENTROPY_LEN
    )

    if min_bytes == 0 or max_entropy_len == 0:
        return False

    size = len(text)
    if size <= min_bytes:
        return False
    if size > MAX_PREFILTER_BYTES:
        return False

    if _has_high_entropy_token(text, min_token_len=max_entropy_len):
        return False

    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(_engine_scan, text)
        try:
            findings = future.result(timeout=REDOS_TIMEOUT_SECONDS)
        except FutureTimeoutError:
            return False
        except Exception:
            return False
        return not findings
    finally:
        # Don't block on hung futures — process exit will reap the worker.
        executor.shutdown(wait=False)
