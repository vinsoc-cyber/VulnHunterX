# Compare — 1.0.0@b83c870 → 1.0.0@b99ed57

Δprecision **+0%** · Δrecall **-6%** · 2026-07-11T06:46:31

## Flips: 5 (improve 1 · regress 2 · neutral 2)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| js/code-injection@app/routes/contributions.js:33 | real | NMD → TP | IMPROVE | Medium→High |
| js/missing-rate-limiting@app/routes/index.js:34 | real | TP → NMD | REGRESS | Medium→High |
| js/polynomial-redos@app/routes/session.js:181 | real | TP → FP | REGRESS | Low→Low |
| js/sql-injection@app/data/user-dao.js:91 | real | NMD → FP | neutral | High→Low |
| js/sql-injection@app/data/user-dao.js:104 | real | NMD → FP | neutral | Medium→Low |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | -$0.34         |
| input tokens      | -50k           |
| output tokens     | -5k            |
| cache hit ratio   | +3.9pp         |
| model time        | +58.8s         |
| iterations (mean) | -0.3           |
| errors            | +0             |
| abstentions       | -2             |
