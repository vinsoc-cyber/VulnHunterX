# Compare — 1.0.0@eda2fd0 → 1.0.0@28eab8b

Δprecision **+10%** · Δrecall **+15%** · 2026-07-12T12:21:06

## Flips: 32 (improve 26 · regress 6 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| cpp/path-injection@imgRead.c:132 | not-real | TP → FP | IMPROVE | High→Medium |
| php.lang.security.audit.openssl-decrypt-validate.openssl-decrypt-validate@vulnerabilities/api/src/Token.php:39 | not-real | TP → FP | IMPROVE | Medium→Medium |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_help.php:20 | real | FP → TP | IMPROVE | High→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_help.php:22 | real | FP → TP | IMPROVE | High→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:63 | real | FP → TP | IMPROVE | Medium→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:67 | real | FP → TP | IMPROVE | Medium→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:14 | real | FP → TP | IMPROVE | High→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:18 | real | FP → TP | IMPROVE | Medium→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:22 | real | FP → TP | IMPROVE | High→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:26 | real | FP → TP | IMPROVE | High→Medium |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/high.php:33 | real | FP → TP | IMPROVE | Low→High |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/low.php:32 | real | FP → TP | IMPROVE | Low→High |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/medium.php:34 | real | FP → TP | IMPROVE | Low→High |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/captcha/source/impossible.php:46 | not-real | TP → FP | IMPROVE | High→Medium |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/cryptography/source/ecb_attack.php:92 | not-real | FP → NMD | REGRESS | High→Medium |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/javascript/index.php:43 | not-real | TP → FP | IMPROVE | Low→Low |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/javascript/index.php:57 | not-real | TP → FP | IMPROVE | Low→Low |
| cpp/overflow-buffer@practice/if_constexpr.cpp:15 | real | TP → FP | REGRESS | High→High |
| cpp/signed-overflow-check@exploitable/undefined_behavior.cpp:11 | not-real | TP → FP | IMPROVE | High→Medium |
| cpp/signed-overflow-check@exploitable/undefined_behavior.cpp:15 | not-real | TP → FP | IMPROVE | High→Medium |
| cpp/signed-overflow-check@practice/if_constexpr.cpp:14 | real | TP → FP | REGRESS | High→Medium |
| cpp/static-buffer-overflow@practice/if_constexpr.cpp:15 | real | TP → FP | REGRESS | High→Medium |
| cpp/suspicious-sizeof@practice/decay.cpp:5 | not-real | TP → FP | IMPROVE | Low→High |
| cpp/suspicious-sizeof@practice/guidelines/expressions_and_statements/cautious_pointer_use_decay.cpp:10 | not-real | TP → FP | IMPROVE | Low→High |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:13 | not-real | FP → TP | REGRESS | Medium→Medium |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:16 | not-real | FP → TP | REGRESS | Medium→Low |
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
| cost              | -$2.47         |
| input tokens      | -104k          |
| output tokens     | -53k           |
| cache hit ratio   | +8.5pp         |
| model time        | -7497.4s       |
| iterations (mean) | -0.41          |
| errors            | +0             |
| abstentions       | -4             |
