# Compare — 1.0.0@8a63259 → 1.0.0@b83c870

Δprecision **+9%** · Δrecall **+1%** · 2026-07-09T10:42:01

## Flips: 23 (improve 15 · regress 7 · neutral 1)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| php.lang.security.audit.openssl-decrypt-validate.openssl-decrypt-validate@vulnerabilities/api/src/Token.php:39 | not-real | TP → FP | IMPROVE | Low→Low |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_help.php:20 | real | FP → TP | IMPROVE | High→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_help.php:22 | real | FP → TP | IMPROVE | Medium→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:63 | real | FP → TP | IMPROVE | Medium→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:67 | real | TP → FP | REGRESS | Low→Low |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:14 | real | FP → TP | IMPROVE | Medium→Medium |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:18 | real | FP → TP | IMPROVE | High→Medium |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:22 | real | FP → TP | IMPROVE | High→Medium |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/low.php:35 | not-real | TP → FP | IMPROVE | Low→Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/medium.php:28 | not-real | TP → FP | IMPROVE | Low→Low |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/cryptography/source/ecb_attack.php:92 | not-real | FP → NMD | REGRESS | High→Medium |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/javascript/index.php:43 | not-real | TP → FP | IMPROVE | Low→Low |
| php.lang.security.php-permissive-cors.php-permissive-cors@vulnerabilities/api/public/index.php:11 | not-real | TP → FP | IMPROVE | High→Low |
| cpp/signed-overflow-check@exploitable/undefined_behavior.cpp:15 | not-real | TP → FP | IMPROVE | High→Medium |
| cpp/static-buffer-overflow@practice/if_constexpr.cpp:15 | real | FP → TP | IMPROVE | Medium→Medium |
| cpp/suspicious-sizeof@practice/decay.cpp:5 | not-real | TP → FP | IMPROVE | Low→High |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:16 | not-real | TP → NMD | neutral | Low→Medium |
| js/code-injection@app/data/allocations-dao.js:78 | real | TP → FP | REGRESS | Low→Low |
| js/code-injection@app/routes/contributions.js:33 | real | TP → NMD | REGRESS | High→Medium |
| js/indirect-command-line-injection@Gruntfile.js:166 | not-real | TP → FP | IMPROVE | Low→Low |
| js/missing-token-validation@server.js:78 | real | TP → FP | REGRESS | Low→Low |
| js/sql-injection@app/data/user-dao.js:91 | real | TP → NMD | REGRESS | Low→High |
| js/sql-injection@app/data/user-dao.js:104 | real | TP → NMD | REGRESS | Low→Medium |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

Δcost `+1.3477` · Δin-tok `+159k` · Δout-tok `+22k` · Δcache-ratio `-0.0418` · Δtime `+666.8` · Δitersμ `+0.15` · Δn_error `+0` · Δn_abstain `+5`
