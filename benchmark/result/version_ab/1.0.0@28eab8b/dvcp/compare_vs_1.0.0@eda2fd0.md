# Compare — 1.0.0@eda2fd0 → 1.0.0@28eab8b

Δprecision **+20%** · Δrecall **+0%** · 2026-07-12T12:21:06

## Flips: 1 (improve 1 · regress 0 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| cpp/path-injection@imgRead.c:132 | not-real | TP → FP | IMPROVE | High→Medium |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | +$0.04         |
| input tokens      | +5k            |
| output tokens     | -115           |
| cache hit ratio   | -22.4pp        |
| model time        | -119.0s        |
| iterations (mean) | +0             |
| errors            | +0             |
| abstentions       | +0             |
