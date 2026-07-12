# Compare — 1.0.0@eda2fd0 → 1.0.0@28eab8b

Δprecision **+9%** · Δrecall **+31%** · 2026-07-12T12:21:06

## Flips: 6 (improve 6 · regress 0 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| js/clear-text-cookie@server.js:78 | real | NMD → TP | IMPROVE | High→High |
| js/indirect-command-line-injection@Gruntfile.js:166 | not-real | TP → FP | IMPROVE | Low→Low |
| js/missing-rate-limiting@app/routes/index.js:34 | real | NMD → TP | IMPROVE | Medium→Medium |
| js/redos@app/routes/profile.js:59 | real | NMD → TP | IMPROVE | Medium→High |
| js/sql-injection@app/data/user-dao.js:91 | real | NMD → TP | IMPROVE | High→High |
| js/sql-injection@app/data/user-dao.js:104 | real | NMD → TP | IMPROVE | High→Medium |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | -$1.29         |
| input tokens      | -101k          |
| output tokens     | -28k           |
| cache hit ratio   | +12.5pp        |
| model time        | -2003.7s       |
| iterations (mean) | -1.17          |
| errors            | +0             |
| abstentions       | -5             |
