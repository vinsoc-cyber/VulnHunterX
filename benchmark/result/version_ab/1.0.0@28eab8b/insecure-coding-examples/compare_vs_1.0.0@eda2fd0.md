# Compare — 1.0.0@eda2fd0 → 1.0.0@28eab8b

Δprecision **+5%** · Δrecall **-12%** · 2026-07-12T12:21:06

## Flips: 9 (improve 4 · regress 5 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| cpp/overflow-buffer@practice/if_constexpr.cpp:15 | real | TP → FP | REGRESS | High→High |
| cpp/signed-overflow-check@exploitable/undefined_behavior.cpp:11 | not-real | TP → FP | IMPROVE | High→Medium |
| cpp/signed-overflow-check@exploitable/undefined_behavior.cpp:15 | not-real | TP → FP | IMPROVE | High→Medium |
| cpp/signed-overflow-check@practice/if_constexpr.cpp:14 | real | TP → FP | REGRESS | High→Medium |
| cpp/static-buffer-overflow@practice/if_constexpr.cpp:15 | real | TP → FP | REGRESS | High→Medium |
| cpp/suspicious-sizeof@practice/decay.cpp:5 | not-real | TP → FP | IMPROVE | Low→High |
| cpp/suspicious-sizeof@practice/guidelines/expressions_and_statements/cautious_pointer_use_decay.cpp:10 | not-real | TP → FP | IMPROVE | Low→High |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:13 | not-real | FP → TP | REGRESS | Medium→Medium |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:16 | not-real | FP → TP | REGRESS | Medium→Low |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | -$0.04         |
| input tokens      | +34k           |
| output tokens     | +1k            |
| cache hit ratio   | +21.1pp        |
| model time        | -585.2s        |
| iterations (mean) | +0.09          |
| errors            | +0             |
| abstentions       | +0             |
