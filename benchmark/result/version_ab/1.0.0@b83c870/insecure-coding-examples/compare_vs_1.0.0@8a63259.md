# Compare — 1.0.0@8a63259 → 1.0.0@b83c870

Δprecision **+10%** · Δrecall **+4%** · 2026-07-09T10:42:01

## Flips: 4 (improve 3 · regress 0 · neutral 1)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| cpp/signed-overflow-check@exploitable/undefined_behavior.cpp:15 | not-real | TP → FP | IMPROVE | High→Medium |
| cpp/static-buffer-overflow@practice/if_constexpr.cpp:15 | real | FP → TP | IMPROVE | Medium→Medium |
| cpp/suspicious-sizeof@practice/decay.cpp:5 | not-real | TP → FP | IMPROVE | Low→High |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:16 | not-real | TP → NMD | neutral | Low→Medium |
