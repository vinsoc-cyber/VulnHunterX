# Compare — 1.0.0@b99ed57 → 1.0.0@182d98e

Δprecision **-4%** · Δrecall **+0%** · 2026-07-11T08:37:30

## Flips: 2 (improve 1 · regress 1 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| cpp/signed-overflow-check@exploitable/undefined_behavior.cpp:15 | not-real | FP → TP | REGRESS | Medium→High |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:13 | not-real | NMD → FP | IMPROVE | Medium→Medium |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | -$0.07         |
| input tokens      | -5k            |
| output tokens     | -2k            |
| cache hit ratio   | +2.4pp         |
| model time        | -445.5s        |
| iterations (mean) | -0.03          |
| errors            | +0             |
| abstentions       | -1             |
