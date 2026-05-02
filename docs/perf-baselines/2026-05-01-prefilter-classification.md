# 2026-05-01 — Local pre-filter classification report

Companion to `2026-05-01-prefilter-classification.json`. This is **not** an
API-timing baseline — it's a static report of how the local pre-filter
classifies the canonical fixture corpus, captured without making any API
calls. Use it to verify two things:

1. The pre-filter never silently drops files that contain real-looking
   secrets (the `safety_invariant` gate).
2. The skip rate against a representative corpus is high enough to justify
   shipping the feature on by default.

## Corpus

`tests/fixtures/perf/data/` — 42 files / 5.7 MB. Includes 5 seeded files
under `seeded/` that contain plausible-looking secrets and **must** route
to the API. See `tests/fixtures/perf/README.md` for the determinism
contract.

## Headline numbers

| Metric | Value |
|---|---|
| Files in corpus | 42 |
| Would skip API | 20 (47.6%) |
| Seeded files skipped | 0 (must be 0) |
| Rejected — too small | 19 (size ≤ 64 KB) |
| Rejected — engine candidate | 0 |
| Rejected — engine timeout | 3 (1.1 MB log files exceed 0.5 s ReDoS budget) |
| Median pre-filter cost | 66 ms / file |
| p95 pre-filter cost | 569 ms / file |

## Why the engine is invoked at `min_confidence=0.0`

The pre-filter calls `classifinder_engine.scan()` with `min_confidence=0.0`
even though the API server's default is 0.5. Reason: the engine clamps
confidence to 0.15 for synthetic test values (e.g., AWS keys containing
`EXAMPLE`), and `generic_high_entropy` ships at 0.47 minimum confidence.
Any pattern below 0.5 would be invisible to the pre-filter at the engine
default — silently skipping files that the API would still flag. The
pre-filter must be a strictly more permissive detector than the API path,
not less. See `classifinder-tests/baselines/tp_baseline.json` for the per-
pattern minima this gate has to clear.

## What this report does **not** measure

- Wall-time savings vs. a no-prefilter run (requires a live API key).
- Network conditions or rate-limit interactions.
- The interaction between `--workers N` and pre-filter cost amortization.

Generate that comparison by running the runbook in `RUNBOOK.md` against
the same corpus once with and once without `--local-prefilter`. Commit
the resulting `*-after-prefilter.json` next to this file.
