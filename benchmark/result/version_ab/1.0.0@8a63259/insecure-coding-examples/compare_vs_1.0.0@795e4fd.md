# Compare — 1.0.0@795e4fd → 1.0.0@8a63259

Δprecision **-6%** · Δrecall **+0%** · 2026-07-10T01:45:04

## Flips: 2 (improve 0 · regress 2 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| cpp/suspicious-sizeof@practice/decay.cpp:5 | not-real | FP → TP | REGRESS | High→Low |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:13 | not-real | FP → TP | REGRESS | Medium→Low |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | -$0.09         |
| input tokens      | -41            |
| output tokens     | -2k            |
| cache hit ratio   | +2.0pp         |
| model time        | -1623.4s       |
| iterations (mean) | +0             |
| errors            | +0             |
| abstentions       | +0             |
