# Compare — 1.0.0@eda2fd0 → 1.0.0@795e4fd

Δprecision **+1%** · Δrecall **+6%** · 2026-07-10T01:45:04

## Flips: 21 (improve 13 · regress 8 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:67 | real | FP → TP | IMPROVE | Medium→Low |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:68 | real | TP → FP | REGRESS | Low→Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/high.php:33 | real | FP → TP | IMPROVE | Low→Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/low.php:32 | real | FP → TP | IMPROVE | Low→Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/medium.php:34 | real | FP → TP | IMPROVE | Low→Low |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/cryptography/source/ecb_attack.php:92 | not-real | FP → TP | REGRESS | High→Low |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/javascript/index.php:57 | not-real | TP → FP | IMPROVE | Low→High |
| php.lang.security.unlink-use.unlink-use@vulnerabilities/upload/source/impossible.php:54 | not-real | FP → TP | REGRESS | Low→Low |
| cpp/overflow-buffer@practice/if_constexpr.cpp:15 | real | TP → FP | REGRESS | High→Medium |
| cpp/signed-overflow-check@practice/if_constexpr.cpp:14 | real | TP → FP | REGRESS | High→Medium |
| cpp/static-buffer-overflow@practice/if_constexpr.cpp:15 | real | TP → FP | REGRESS | High→Medium |
| cpp/suspicious-sizeof@practice/decay.cpp:5 | not-real | TP → FP | IMPROVE | Low→High |
| cpp/suspicious-sizeof@practice/guidelines/expressions_and_statements/cautious_pointer_use_decay.cpp:10 | not-real | TP → FP | IMPROVE | Low→Medium |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:16 | not-real | FP → TP | REGRESS | Medium→Low |
| js/clear-text-cookie@server.js:78 | real | NMD → TP | IMPROVE | High→Low |
| js/missing-rate-limiting@app/routes/index.js:34 | real | NMD → TP | IMPROVE | Medium→Medium |
| js/missing-token-validation@server.js:78 | real | FP → TP | IMPROVE | Medium→Low |
| js/polynomial-redos@app/routes/profile.js:61 | real | TP → NMD | REGRESS | High→Medium |
| js/redos@app/routes/profile.js:59 | real | NMD → TP | IMPROVE | Medium→Medium |
| js/sql-injection@app/data/user-dao.js:91 | real | NMD → TP | IMPROVE | High→Low |
| js/sql-injection@app/data/user-dao.js:104 | real | NMD → TP | IMPROVE | High→Low |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

Δcost `-0.2479` · Δin-tok `+173k` · Δout-tok `-16k` · Δcache-ratio `+0.0192` · Δtime `+231.9` · Δitersμ `+0.02` · Δn_error `+0` · Δn_abstain `-4`
