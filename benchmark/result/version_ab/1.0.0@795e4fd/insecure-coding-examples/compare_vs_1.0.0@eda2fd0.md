# Compare — 1.0.0@eda2fd0 → 1.0.0@795e4fd

Δprecision **+2%** · Δrecall **-12%** · 2026-07-03T12:17:58

## Flips: 6 (improve 2 · regress 4 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| cpp/overflow-buffer@practice/if_constexpr.cpp:15 | real | TP → FP | REGRESS | High→Medium |
| cpp/signed-overflow-check@practice/if_constexpr.cpp:14 | real | TP → FP | REGRESS | High→Medium |
| cpp/static-buffer-overflow@practice/if_constexpr.cpp:15 | real | TP → FP | REGRESS | High→Medium |
| cpp/suspicious-sizeof@practice/decay.cpp:5 | not-real | TP → FP | IMPROVE | Low→High |
| cpp/suspicious-sizeof@practice/guidelines/expressions_and_statements/cautious_pointer_use_decay.cpp:10 | not-real | TP → FP | IMPROVE | Low→Medium |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:16 | not-real | FP → TP | REGRESS | Medium→Low |
