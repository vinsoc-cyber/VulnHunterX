# Compare — 1.0.0@eda2fd0 → 1.0.0@28eab8b

Δprecision **+12%** · Δrecall **+26%** · 2026-07-12T12:21:06

## Flips: 16 (improve 15 · regress 1 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
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

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | -$1.18         |
| input tokens      | -42k           |
| output tokens     | -25k           |
| cache hit ratio   | +6.3pp         |
| model time        | -4789.4s       |
| iterations (mean) | -0.48          |
| errors            | +0             |
| abstentions       | +1             |
