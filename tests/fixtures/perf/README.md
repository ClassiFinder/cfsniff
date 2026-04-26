# cfsniff performance baseline corpus

Deterministic fixture corpus used by the speed-enhancement plan to produce
canonical baseline measurements. Required input for any `--timing` run that
will be committed to `cfsniff/docs/perf-baselines/`.

## Why this exists

The plan has a measurement-driven decision gate (step 2): the choice between
asyncio refactor (Option A), threadpool tuning + HTTP/2 (Option B), and
local engine pre-filter (Option C) depends on what the data says. For the
data to be comparable across machines, networks, and days, every benchmark
must run against the same input. This corpus is that input.

See:
- Plan: `classifinder-knowledge/2026-04-24-cfsniff-speed-enhancement.md`
- Output schema: `cfsniff/docs/perf-baselines/README.md`

## Why generated, not committed

A meaningful benchmark corpus is several MB (this one is ~5.7 MB across
42 files). Committing that to git would bloat clones for every cfsniff
contributor, including those who never run benchmarks. The plan's
requirement is "byte-identical input every run" — which a deterministic
generator with a pinned seed satisfies just as well as committed bytes.

## How to use

Generate the corpus once, then run benchmarks against it:

```bash
# Generate (or regenerate — wipes data/ first)
python tests/fixtures/perf/generate.py

# Verify determinism across two runs (CI-friendly)
python tests/fixtures/perf/generate.py --check

# Run a baseline measurement at workers={1, 8, 16, 32}
for w in 1 8 16 32; do
  cfsniff --timing --format json --workers "$w" tests/fixtures/perf/data/ \
    > /tmp/baseline-w${w}.json
done

# Commit the chosen baseline
cp /tmp/baseline-w8.json docs/perf-baselines/$(date -u +%Y-%m-%d)-baseline.json
```

## What's in the corpus

42 files, ~5.7 MB total, mirroring the file classes `cfsniff audit` walks:

| Category | Files | Approx size |
|---|---|---|
| `shell_history/` | 2 | ~50 KB each (~100 KB) |
| `shell_config/` | 3 | ~1 KB each (~3 KB) |
| `env/` | 4 | ~1 KB each (~4 KB) |
| `cloud/` | 2 | ~1 KB + ~1 KB (~2 KB) |
| `packages/` | 2 | tiny |
| `ssh/` | 1 | tiny |
| `logs/` | 23 | 20 × ~200 KB + 3 × ~2 MB (~10 MB raw, ~5.5 MB net after generation seed) |
| `seeded/` | 5 | tiny — KNOWN-FAKE secrets for regression detection |

Most files are clean. The `seeded/` subdirectory contains files with known-
fake secret strings (AWS docs examples, all-zero/all-A patterns) so finding-
count regressions are detectable. **Never replace the seeded values with
real secrets.**

## Determinism contract

`generate.py` uses a single pinned seed (`SEED` constant). Same Python →
same output. Bumping the seed is a breaking change to baseline
comparability — historical baselines become incomparable. Don't do that
without a coordinated rebaseline.

If the corpus needs to grow (new file class, more files), prefer adding a
new generator function gated by its own seed offset over re-seeding the
whole corpus. See `_detrand(seed_offset)` in the script.

## CI verification

The `--check` flag generates the corpus twice in temp dirs and compares
SHA-256 fingerprints. A future CI workflow should run this on every PR
that touches `tests/fixtures/perf/` to catch accidental non-determinism
(e.g., someone introducing `os.urandom` or relying on dict iteration order).
