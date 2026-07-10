# Compare — 1.0.0@8a63259 → 1.0.0@b83c870

Δprecision **+6%** · Δrecall **-31%** · 2026-07-09T10:42:01

## Flips: 6 (improve 1 · regress 5 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| js/code-injection@app/data/allocations-dao.js:78 | real | TP → FP | REGRESS | Low→Low |
| js/code-injection@app/routes/contributions.js:33 | real | TP → NMD | REGRESS | High→Medium |
| js/indirect-command-line-injection@Gruntfile.js:166 | not-real | TP → FP | IMPROVE | Low→Low |
| js/missing-token-validation@server.js:78 | real | TP → FP | REGRESS | Low→Low |
| js/sql-injection@app/data/user-dao.js:91 | real | TP → NMD | REGRESS | Low→High |
| js/sql-injection@app/data/user-dao.js:104 | real | TP → NMD | REGRESS | Low→Medium |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

Δcost `+0.37` · Δin-tok `+38k` · Δout-tok `+7k` · Δcache-ratio `-0.0419` · Δtime `+198.4` · Δitersμ `+0.24` · Δn_error `+0` · Δn_abstain `+3`
