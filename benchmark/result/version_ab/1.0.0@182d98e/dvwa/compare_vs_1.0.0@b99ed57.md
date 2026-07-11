# Compare — 1.0.0@b99ed57 → 1.0.0@182d98e

Δprecision **-1%** · Δrecall **+10%** · 2026-07-11T08:37:30

## Flips: 8 (improve 5 · regress 3 · neutral 0)

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

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | -$0.24         |
| input tokens      | +10k           |
| output tokens     | -6k            |
| cache hit ratio   | +1.4pp         |
| model time        | +280.8s        |
| iterations (mean) | +0.02          |
| errors            | +0             |
| abstentions       | +1             |
