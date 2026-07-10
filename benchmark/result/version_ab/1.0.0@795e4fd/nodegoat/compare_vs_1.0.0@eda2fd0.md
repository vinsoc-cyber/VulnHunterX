# Compare — 1.0.0@eda2fd0 → 1.0.0@795e4fd

Δprecision **+3%** · Δrecall **+31%** · 2026-07-10T01:45:04

## Flips: 7 (improve 6 · regress 1 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| js/clear-text-cookie@server.js:78 | real | NMD → TP | IMPROVE | High→Low |
| js/missing-rate-limiting@app/routes/index.js:34 | real | NMD → TP | IMPROVE | Medium→Medium |
| js/missing-token-validation@server.js:78 | real | FP → TP | IMPROVE | Medium→Low |
| js/polynomial-redos@app/routes/profile.js:61 | real | TP → NMD | REGRESS | High→Medium |
| js/redos@app/routes/profile.js:59 | real | NMD → TP | IMPROVE | Medium→Medium |
| js/sql-injection@app/data/user-dao.js:91 | real | NMD → TP | IMPROVE | High→Low |
| js/sql-injection@app/data/user-dao.js:104 | real | NMD → TP | IMPROVE | High→Low |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

Δcost `-0.1453` · Δin-tok `+44k` · Δout-tok `-7k` · Δcache-ratio `+0.023` · Δtime `-216` · Δitersμ `+0.06` · Δn_error `+0` · Δn_abstain `-4`
