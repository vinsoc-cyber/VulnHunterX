# Compare — 1.0.0@b99ed57 → 1.0.0@182d98e

Δprecision **+0%** · Δrecall **+25%** · 2026-07-11T08:37:30

## Flips: 5 (improve 4 · regress 0 · neutral 1)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| js/code-injection@app/data/allocations-dao.js:78 | real | FP → NMD | neutral | Low→Medium |
| js/missing-rate-limiting@app/routes/index.js:34 | real | NMD → TP | IMPROVE | High→Medium |
| js/polynomial-redos@app/routes/session.js:181 | real | FP → TP | IMPROVE | Low→Low |
| js/sql-injection@app/data/user-dao.js:91 | real | FP → TP | IMPROVE | Low→Low |
| js/sql-injection@app/data/user-dao.js:104 | real | FP → TP | IMPROVE | Low→High |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | +$0.02         |
| input tokens      | +12k           |
| output tokens     | -789           |
| cache hit ratio   | -1.2pp         |
| model time        | -185.3s        |
| iterations (mean) | -0.06          |
| errors            | +0             |
| abstentions       | +0             |
