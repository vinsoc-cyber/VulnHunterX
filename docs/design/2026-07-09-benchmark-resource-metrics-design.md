# Benchmark resource metrics + honest error accounting — design

**Date:** 2026-07-09
**Scope:** `benchmark/` version-A/B mode (`benchmark/src/modes/version_ab.py`)
**Status:** design — awaiting review

## Goal

The `version_ab` benchmark exists to monitor **version-over-version regression/improvement**, not
absolute precision. Today the only resource metric it reports is `cost_usd`. This change adds
per-target **token, time, and iteration** accounting, and fixes a latent bug where **errored findings
are silently graded as abstentions** — so an infrastructure failure currently masquerades as a
capability regression.

## Non-goals

- Wall-clock timing (the harness doesn't capture it; with `--jobs`, findings overlap). We report
  **summed per-finding model time** only.
- Any change to what the VHX engine emits. We consume existing raw fields.
- Adding resource metrics to the confound guard or making them gate a comparison. They are
  **report-only, non-deterministic observability**.
- Per-rule / per-CWE breakdowns, F1, calibration aggregates. Out of scope.

## Current state (verified against HEAD `8cd0e9c`)

- Raw per-finding output (`verification_results/*.json`) already carries: `input_tokens`,
  `output_tokens`, `cached_input_tokens`, `tokens_used`, `elapsed_seconds`, `cost_usd`,
  `iterations`, `confidence_score`.
- `build_score` (`version_ab.py:111`) keeps only `cost_usd` per finding; `aggregate` sums only
  `cost_usd`. Tokens/time/iterations never reach `score.json` or `score.md`.
- `render_verdict_md` (`version_ab.py:130`) *does* surface `iterations`, numeric `confidence_score`,
  and `context_needed` per finding in `verdicts/*.md` — so those are already visible per-finding;
  only the **aggregate** is missing.
- **Bug:** `write_verdicts` (`version_ab.py:162`) skips error stubs via `nv not in ("TP","FP","NMD")`,
  but `build_score` does not — an errored finding falls through `grade()` to `"abstain"`
  (`version_ab.py:32,34`) and is counted like a genuine "Needs More Data". The two functions disagree
  on what an error is.

## Design decisions (locked in brainstorming)

1. **Scope:** all four — tokens+time, ERROR/NMD split, iterations aggregate, cache-hit ratio.
2. **JSON shape:** a **separate `resources` block** sibling to `aggregates`. Verdict counts
   (`n_abstain`, `n_error`) go in `aggregates` (they are correctness). `cost_usd` stays in
   `aggregates` (back-compat).
3. **Error semantics:** errored findings are **excluded from the recall denominator**. Precision is
   naturally unaffected (an error is never a TP).
4. **`n_real` reporting:** stays the **oracle total**; only the recall divisor is adjusted. `n_error_real`
   is reported separately so the adjustment is traceable.
5. **`score.md`:** two per-target tables — *correctness* (adds `NMD`, `err`) and *resources*.
6. **Compare view:** a **non-gating "Resource deltas" section** beside Δprecision/Δrecall.

## Data model — `score.json`

### `aggregates` (correctness; additive)

Existing keys unchanged: `tp_total`, `tp_real`, `false_alarm`, `precision`, `n_real`, `n_not_real`,
`cost_usd`. Changes:

- `+ n_abstain` — findings graded `abstain` (genuine NMD only).
- `+ n_error` — findings graded `error`.
- `+ n_error_real` — errored findings whose key is in the oracle (truth `real`).
- `n_not_real` — **unchanged** (all findings with truth `not-real`). For population consistency with
  `n_real` (the oracle total), the count fields describe the full population; only the divisors are
  adjusted. The errored subset is reported via `n_error` / `n_error_real`.
- `recall` — divisor excludes errored reals:
  ```
  recall = tp_real / (n_real - n_error_real)   if (n_real - n_error_real) > 0 else None
  ```
  `n_real` itself remains `len(real_keys)` (oracle total). `precision = tp_real / tp_total`
  (unchanged).

### `resources` (new sibling block; non-deterministic)

Computed by a new pure function `summarize_resources(findings)`:

- `input_tokens`, `output_tokens`, `cached_input_tokens` — summed over **all** findings (errors still
  consume tokens).
- `cache_hit_ratio` = `round(cached_input_tokens / input_tokens, 4)` (`0.0` if `input_tokens == 0`).
- `elapsed_seconds` = `round(sum(per-finding elapsed_seconds), 1)` — **summed model time, not
  wall-clock** (documented in the renderer and this spec).
- `iterations_total` = sum of `iterations` over **completed** (non-error) findings.
- `iterations_mean` = `round(iterations_total / n_completed, 2)` (`0.0` if `n_completed == 0`), where
  `n_completed` = count of non-error findings.

### `findings[]` (per-finding; mirror `cost_usd`)

Each finding dict gains `input_tokens`, `output_tokens`, `cached_input_tokens`, `elapsed_seconds`,
`iterations` — mirroring the existing `cost_usd` precedent. This keeps both `aggregate` and
`summarize_resources` **pure functions of the findings list** (directly unit-testable) and preserves
per-finding debuggability. `grade` gains a new value `"error"`.

## Grading & error semantics

Extract one shared predicate, the single source of truth for "did this finding produce a real verdict":

```python
def is_real_verdict(nv: str) -> bool:
    return nv in ("TP", "FP", "NMD")
```

Used by **both** `build_score`/`grade` and `write_verdicts` (replacing the inline `nv not in (...)`
at `version_ab.py:162`) so they can never diverge again.

`grade` gets a top short-circuit; NMD still maps to `abstain`:

```python
def grade(verdict, truth):
    n = normalize_verdict(verdict)
    if not is_real_verdict(n):
        return "error"
    if truth == "real":
        return "CORRECT" if n == "TP" else ("MISS" if n == "FP" else "abstain")
    if truth == "not-real":
        return "CORRECT" if n == "FP" else ("FALSE-ALARM" if n == "TP" else "abstain")
    return "?"
```

No existing grading test changes — they exercise TP/FP/NMD inputs, whose grades are unchanged.

## Rendering

### `score.md` — rollup (`render_score_md`, `is_roll` branch)

- **Correctness table** — existing columns plus `NMD` (`n_abstain`) and `err` (`n_error`):
  `| target | prec | recall | TP (real/FA) | real | !real | NMD | err | panel |`
- **Resources table** (new):
  `| target | in-tok | out-tok | cache% | time(s) | itersμ | cost |`
- Top summary line gains a resources line (rollup totals).

### `score.md` — single target (non-`is_roll` branch)

Findings table unchanged; the summary gains the same resources line. No per-target table for a single
target.

### `compare_vs_<prev>.md` (`render_compare_md`)

New **Resource deltas** section beside the existing Δprecision/Δrecall, showing
`Δcost Δin-tok Δout-tok Δcache% Δtime Δitersμ Δn_error Δn_abstain`, with a one-line caveat that
run-to-run variance is expected and these do not gate. Missing values (comparing against an old
score.json with no `resources` block) render `n/a`.

## Code touch points (all in `benchmark/src/modes/version_ab.py`)

- `is_real_verdict` — **new** shared predicate.
- `grade` — error short-circuit.
- `aggregate` — add `n_abstain`, `n_error`, `n_error_real`; adjust recall divisor; `n_not_real`
  excludes errors.
- `summarize_resources(findings)` — **new** pure function → `resources` dict.
- `build_score` — add per-finding resource fields; attach `resources` to the returned score.
- `rollup_score` — roll `resources` across targets (via `summarize_resources` over all findings);
  carry each target's `resources` into the `targets` map for the resources table.
- `compare_scores` — compute resource + count deltas into a `resource_deltas` dict; **CONFOUND_KEYS
  untouched**.
- `rollup_compare` — roll resource deltas from the two rollup `resources` blocks.
- `render_score_md`, `render_compare_md` — the tables/sections above.
- `write_verdicts` — use `is_real_verdict`.

## Testing (`benchmark/tests/`)

- `test_grading.py` — `grade(<error>, ...) == "error"`; `aggregate` returns `n_abstain`/`n_error`/
  `n_error_real`; recall excludes errored reals; NMD still `abstain`.
- `test_resources.py` — **new** — `summarize_resources`: summation, `cache_hit_ratio`,
  iterations-over-completed, division-by-zero guards.
- `test_score_build.py` — an error stub → counted in `n_error`, excluded from recall divisor, still
  present in `findings[]` with `grade == "error"`.
- `test_render.py` — resources table renders; compare resource-delta section renders; `n/a` when the
  previous score lacks `resources`.
- `test_compare.py` — `resource_deltas` present and correct; confound guard still fires on
  model/temp/panel/max_iterations mismatch and **not** on token/time differences.

Existing assertions on error-free inputs remain valid: with zero errors, `n_error == 0`,
`n_error_real == 0`, recall divisor `== n_real`, and `n_not_real` is unchanged.

## Constraints & invariants

- **Non-gating:** `CONFOUND_KEYS` never includes token/time/iteration fields; resource deltas are
  informational.
- **Back-compat:** comparing a new run against an existing `score.json` (no `resources`, no
  `n_abstain`/`n_error`) degrades gracefully — deltas for absent fields render `n/a`; correctness
  comparison is unaffected.
- **Determinism:** tests feed synthetic raw JSON with fixed values, so they stay deterministic despite
  the metrics being non-deterministic in real runs.
