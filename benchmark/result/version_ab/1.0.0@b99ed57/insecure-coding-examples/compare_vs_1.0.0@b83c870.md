# Compare — 1.0.0@b83c870 → 1.0.0@b99ed57

Δprecision **+4%** · Δrecall **+4%** · 2026-07-11T06:46:31

## Flips: 2 (improve 1 · regress 0 · neutral 1)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| cpp/overflow-buffer@practice/if_constexpr.cpp:15 | real | FP → TP | IMPROVE | Medium→Medium |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:13 | not-real | TP → NMD | neutral | Low→Medium |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | -$0.09         |
| input tokens      | -5k            |
| output tokens     | -3k            |
| cache hit ratio   | +0.0pp         |
| model time        | +388.6s        |
| iterations (mean) | -0.03          |
| errors            | +0             |
| abstentions       | +1             |
