# cfsniff performance baselines

This directory holds canonical performance measurements that gate the speed-enhancement work tracked in `classifinder-knowledge/2026-04-24-cfsniff-speed-enhancement.md`.

## Why this exists

The plan has a measurement-driven decision gate (step 2): the choice between Option A (asyncio), Option B (threadpool tuning + HTTP/2), and Option C (local pre-filter) depends on what the data says. If `time(workers=32) / time(workers=8) > 0.7`, concurrency is not the bottleneck and the plan jumps to Option C. Without a committed baseline, the rationale for whichever option ships evaporates and a reviewer reading the implementation PR in 6 weeks has no way to verify the decision was data-driven.

PRs that change cfsniff's concurrency or pre-filter behavior must reference a file in this directory.

## Filename convention

`YYYY-MM-DD-baseline.json` — the canonical baseline for that date.

Variants for ad-hoc comparisons: `YYYY-MM-DD-<descriptor>.json` (e.g., `2026-05-01-after-option-b.json`). Keep names short and the descriptor purposeful.

## Schema

Matches the `--timing` MVP defined in the speed-enhancement plan:

```json
{
  "cfsniff_version": "0.1.4",
  "sdk_version": "0.1.5",
  "base_url": "https://api.classifinder.ai",
  "workers": 16,
  "wall_time_seconds": 12.34,
  "file_count": 287,
  "p50_per_file_ms": 38,
  "p95_per_file_ms": 142,
  "rate_limit_429_count": 0,
  "retry_count": 0,
  "warmup_status": "ok"
}
```

Any extra fields the implementation produces (e.g., `errors_by_file`, slowest-N tracking) are fine but not required for the gate decision.

## How to produce a baseline

Once the `--timing` flag lands:

```bash
cfsniff --format json --timing audit > perf-result.json
# extract just the timing object, or commit the full output if small
```

Run against the canonical fixture corpus committed at `cfsniff/tests/fixtures/perf/` (separate from this directory). All baselines must use the same corpus and the same API base URL to be comparable. Document any deviations in the filename or in a sibling `.md` note.

## See also

- Plan: `classifinder-knowledge/2026-04-24-cfsniff-speed-enhancement.md`
- Fixture corpus: `cfsniff/tests/fixtures/perf/`
