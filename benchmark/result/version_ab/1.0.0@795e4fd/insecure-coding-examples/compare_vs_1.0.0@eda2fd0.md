# Compare — 1.0.0@eda2fd0 → 1.0.0@795e4fd

Δprecision **+2%** · Δrecall **-12%** · 2026-07-10T01:45:04

## Flips: 6 (improve 2 · regress 4 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| cpp/overflow-buffer@practice/if_constexpr.cpp:15 | real | TP → FP | REGRESS | High→Medium |
| cpp/signed-overflow-check@practice/if_constexpr.cpp:14 | real | TP → FP | REGRESS | High→Medium |
| cpp/static-buffer-overflow@practice/if_constexpr.cpp:15 | real | TP → FP | REGRESS | High→Medium |
| cpp/suspicious-sizeof@practice/decay.cpp:5 | not-real | TP → FP | IMPROVE | Low→High |
| cpp/suspicious-sizeof@practice/guidelines/expressions_and_statements/cautious_pointer_use_decay.cpp:10 | not-real | TP → FP | IMPROVE | Low→Medium |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:16 | not-real | FP → TP | REGRESS | Medium→Low |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

Δcost `+0.077` · Δin-tok `+13k` · Δout-tok `+3k` · Δcache-ratio `+0.0595` · Δtime `+822` · Δitersμ `+0.03` · Δn_error `+0` · Δn_abstain `+0`
