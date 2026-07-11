# Compare — 1.0.0@b83c870 → 1.0.0@b99ed57

Δprecision **-0%** · Δrecall **-2%** · 2026-07-11T06:46:31

## Flips: 3 (improve 1 · regress 2 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:18 | real | TP → FP | REGRESS | Medium→Medium |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/medium.php:28 | not-real | FP → TP | REGRESS | Low→Low |
| yaml.github-actions.security.run-shell-injection.run-shell-injection@.github/workflows/docker-image.yml:29 | not-real | TP → FP | IMPROVE | High→Medium |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | +$0.19         |
| input tokens      | +18k           |
| output tokens     | +15k           |
| cache hit ratio   | +5.1pp         |
| model time        | +283.7s        |
| iterations (mean) | +0             |
| errors            | +0             |
| abstentions       | +0             |
