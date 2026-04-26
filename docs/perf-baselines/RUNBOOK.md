# Measurement runbook — cfsniff baseline benchmarks

Step-by-step procedure for running the speed-enhancement plan's measurement
gate against the canonical fixture corpus. Use this every time you produce
a baseline, an "after-change" comparison, or want to verify a regression.

**Plan reference:** `classifinder-knowledge/2026-04-24-cfsniff-speed-enhancement.md`

**Why this runbook exists:** the plan's decision gate (which option to ship)
is data-driven. Reproducible, comparable measurements are the contract.
This document removes the "how do I run it" friction so anyone can produce
a baseline without reconstructing the workflow from the plan doc.

---

## 0. Prerequisites

- [ ] Working checkout of `cfsniff` on a commit that includes the `--timing`
      instrumentation (Lane A, merged 2026-04-25 in PR #1).
- [ ] Working checkout includes `tests/fixtures/perf/` (this PR / PR #2).
- [ ] A real `ClassiFinder` API key with rate-limit headroom.
- [ ] `jq` installed for parsing the JSON output.

```bash
cd ~/Documents/ClassiFinder/cfsniff   # adjust to your path
git checkout main && git pull --ff-only
cfsniff --help | grep -- '--timing'   # must show the flag
export CLASSIFINDER_API_KEY=ss_live_...
which jq                              # must exist
```

---

## 1. Pre-flight: rate-limit budget

Before measuring, know the per-key rate limit on your API account. The
corpus is ~42 files; at `--workers 32` the run fans out 32 in-flight
requests immediately. If your limit is below ~60 req/min you'll hit 429s
and the data will reflect rate limiting, not concurrency.

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://api.classifinder.ai/v1/health
# Expect: 200
```

If the 200 takes more than ~1 second, the Fly.io machine was cold — the
warmup in step 3 will handle that.

If your rate limit is tight, raise it on your key before running. Otherwise
the decision gate in step 7 will likely fire on the rate-limit branch.

---

## 2. Generate the corpus

```bash
python tests/fixtures/perf/generate.py
```

Expected output:

```
Wrote 42 files (5.7 MB) to /.../tests/fixtures/perf/data
Fingerprint: 3e9d701868928788...
```

Check the fingerprint matches `3e9d701868928788...` (truncated). If it
doesn't, the generator has been edited since this runbook was last
calibrated — every baseline thereafter measures a different corpus and is
not comparable to prior baselines. See `tests/fixtures/perf/README.md` for
the determinism contract before proceeding.

---

## 3. Warm up Fly.io's scale-to-zero machine

The first request after idle pays cold-start cost (multi-second). The plan
acknowledges this as bottleneck #2. Run a throwaway invocation before
measuring so cold-start doesn't skew the numbers:

```bash
cfsniff --workers 8 tests/fixtures/perf/data/ > /dev/null 2>&1
```

After this completes (output discarded), the machine is warm for several
minutes. Move directly to step 4.

---

## 4. Measurement loop

Single-shot at four worker counts:

```bash
mkdir -p /tmp/cfsniff-baseline
for w in 1 8 16 32; do
  echo "=== workers=$w ===" >&2
  cfsniff --timing --format json --workers "$w" tests/fixtures/perf/data/ \
    > "/tmp/cfsniff-baseline/w${w}.json"
done
```

Total time: ~1–2 minutes. If you see `error: ...` on stderr during the
loop, it's likely 429s (visible in the resulting JSON's `rate_limited_files`
field). The loop continues regardless — cfsniff doesn't abort on per-file
rate-limit errors.

---

## 5. Optional: triples for variance

Single-shot measurements are noisy on real networks. If a single ratio
in step 7 lands near a decision boundary (e.g. `0.65`), run triples and
median:

```bash
for trial in 1 2 3; do
  for w in 1 8 16 32; do
    cfsniff --timing --format json --workers "$w" tests/fixtures/perf/data/ \
      > "/tmp/cfsniff-baseline/w${w}_t${trial}.json"
  done
done
```

Adds ~3–6 minutes. Skip if step 7's ratio is decisive.

---

## 6. Inspect

Quick extraction of the numbers needed for the decision:

```bash
for w in 1 8 16 32; do
  jq -r '"workers=\(.timing.workers): wall=\(.timing.wall_time_seconds)s p50=\(.timing.p50_per_file_ms)ms p95=\(.timing.p95_per_file_ms)ms 429=\(.timing.rate_limited_files)"' \
    /tmp/cfsniff-baseline/w${w}.json
done
```

Expected shape:

```
workers=1: wall=12.34s p50=180ms p95=420ms 429=0
workers=8: wall=2.10s p50=180ms p95=420ms 429=0
workers=16: wall=1.50s p50=180ms p95=480ms 429=0
workers=32: wall=1.45s p50=190ms p95=510ms 429=0
```

What to look for:

- **Wall time should drop sharply 1 → 8.** If it doesn't, concurrency isn't
  helping at all — that's an interesting result on its own.
- **p50 should be roughly stable across worker counts.** Per-request RTT
  doesn't change with parallelism. A spike in p50 at higher worker counts
  signals pool exhaustion, server-side queuing, or rate-limit backoff.
- **429 count should be zero or near zero** for a clean baseline. Non-zero
  changes the decision branch in step 7.

---

## 7. Apply the decision gate

Compute the key ratio:

```bash
W8=$(jq -r '.timing.wall_time_seconds' /tmp/cfsniff-baseline/w8.json)
W32=$(jq -r '.timing.wall_time_seconds' /tmp/cfsniff-baseline/w32.json)
RATIO=$(python3 -c "print(f'{$W32 / $W8:.2f}')")
echo "time(w=32) / time(w=8) = $RATIO"
```

Map the ratio + 429 count to the plan's table:

| Observation | Bottleneck | Next step |
|---|---|---|
| `RATIO > 0.7` | Concurrency not the bottleneck (server compute, RTT floor, or rate limit dominates) | **Skip A and B → ship Option C** |
| `RATIO < 0.5` AND `429 < 5%` | Per-request RTT, threads scaling | **Ship A or B** (see below) |
| `429 > 20%` at workers=8 | Rate limit | **STOP** — raise rate limit before any cfsniff change |

Murky middle (`0.5 ≤ RATIO ≤ 0.7`):

- If `8 → 16` helped meaningfully (wall time dropped > 20%), lean **B**.
- If it didn't help, lean **C**.
- If still unclear, run step 5 (triples) and recompute.

If A vs. B is the question, decide on 429 rate:

- 429s in 5–20% range → prefer **A**. Async retries yield the event loop;
  sync `time.sleep` blocks the worker thread.
- 429s near zero → prefer **B**. Smaller diff, no async refactor.

---

## 8. Commit the canonical baseline

Pick one run to be the canonical "before" reference. By convention this is
the `workers=8` run since 8 is the current cfsniff default — future
implementation PRs (Option A, B, or C) compare their "after" numbers
against this one.

```bash
DATE=$(date -u +%Y-%m-%d)
cp /tmp/cfsniff-baseline/w8.json \
   docs/perf-baselines/${DATE}-baseline.json

git checkout -b chore/baseline-${DATE}
git add docs/perf-baselines/${DATE}-baseline.json
git commit -m "chore: ${DATE} baseline measurement (workers=8)"
git push -u origin chore/baseline-${DATE}
```

Open a PR. The commit message should reference the decision (e.g.,
"ratio=0.62 → leaning Option B"). The PR description should link to
the plan doc and any relevant context (network conditions, rate-limit
state of the key used).

---

## 9. Open the implementation PR

Pick the option from step 7. Branch and implement per the plan:

- **Option B:** branch `feat/option-b-http2-warmup`. In `cfsniff/src/cfsniff/api.py`
  construct `ClassiFinder(http2=True, limits=...)`. In `cli.py` bump `--workers`
  default to 16 and add the warmup `client.health()` call before fan-out.
  See plan section "Option B" for full spec including warmup error handling.
- **Option A:** branch `feat/option-a-async`. Larger refactor — see plan
  section "Option A" for client lifecycle, bounded fan-out, exception
  isolation, and `asyncio.to_thread` for file reads.
- **Option C:** branch `feat/option-c-prefilter`. New `version_check.py`
  module, opt-in skip rule in `api.py`, lazy-imported `classifinder-engine`,
  HMAC-protected disk cache, ReDoS protection, file-mode `0700/0600`. See
  plan section "Option C" for the security spec — and confirm the supply-
  chain prereqs in `2026-04-11-pypi-trusted-publishing-plan.md` are landed
  before shipping.

After implementation: re-run steps 3–6 against the same corpus from the
same machine and same API key. Commit the after-JSON next to the baseline:

```bash
cp /tmp/cfsniff-baseline/w8.json \
   docs/perf-baselines/$(date -u +%Y-%m-%d)-after-option-b.json
```

The implementation PR's description should quote both files and the wall-
time delta.

---

## Cross-references

- `tests/fixtures/perf/README.md` — corpus structure and determinism contract
- `tests/fixtures/perf/generate.py` — the generator script (read it once
  to understand the seed-pinning before bumping `SEED`)
- `docs/perf-baselines/README.md` — schema for the baseline JSON files
- `classifinder-knowledge/2026-04-24-cfsniff-speed-enhancement.md` — the plan
- `classifinder-knowledge/2026-04-11-pypi-trusted-publishing-plan.md` — supply-
  chain prereq for Option C

## Practical heads-up before starting

- **Run from one location.** Numbers from your laptop and numbers from a Fly
  machine aren't comparable. Pick one, document it in the commit message.
- **First measurement is the most expensive in attention.** Once done,
  repeating for an after-run is mechanical (~5 minutes).
- **Network state matters.** Don't measure on hotel Wi-Fi or while a large
  download is running. Document network conditions if abnormal.
