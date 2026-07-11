# Compare — 1.0.0@b99ed57 → 1.0.0@182d98e

Δprecision **-2%** · Δrecall **+9%** · 2026-07-11T08:37:30

## Flips: 15 (improve 10 · regress 4 · neutral 1)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:67 | real | FP → TP | IMPROVE | Low→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:68 | real | FP → TP | IMPROVE | Low→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:18 | real | FP → TP | IMPROVE | Medium→High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:26 | real | FP → TP | IMPROVE | Low→High |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/low.php:35 | not-real | FP → NMD | REGRESS | Low→High |
| php.lang.security.php-permissive-cors.php-permissive-cors@vulnerabilities/api/gen_openapi.php:6 | not-real | TP → FP | IMPROVE | Medium→Low |
| php.lang.security.php-permissive-cors.php-permissive-cors@vulnerabilities/api/public/index.php:11 | not-real | FP → TP | REGRESS | Low→Medium |
| yaml.github-actions.security.run-shell-injection.run-shell-injection@.github/workflows/docker-image.yml:29 | not-real | FP → TP | REGRESS | Medium→Medium |
| cpp/signed-overflow-check@exploitable/undefined_behavior.cpp:15 | not-real | FP → TP | REGRESS | Medium→High |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:13 | not-real | NMD → FP | IMPROVE | Medium→Medium |
| js/code-injection@app/data/allocations-dao.js:78 | real | FP → NMD | neutral | Low→Medium |
| js/missing-rate-limiting@app/routes/index.js:34 | real | NMD → TP | IMPROVE | High→Medium |
| js/polynomial-redos@app/routes/session.js:181 | real | FP → TP | IMPROVE | Low→Low |
| js/sql-injection@app/data/user-dao.js:91 | real | FP → TP | IMPROVE | Low→Low |
| js/sql-injection@app/data/user-dao.js:104 | real | FP → TP | IMPROVE | Low→High |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | -$0.32         |
| input tokens      | +18k           |
| output tokens     | -8k            |
| cache hit ratio   | +1.2pp         |
| model time        | -321.6s        |
| iterations (mean) | +0             |
| errors            | +0             |
| abstentions       | +0             |
