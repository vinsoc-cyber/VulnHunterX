# Compare — 1.0.0@b83c870 → 1.0.0@b99ed57

Δprecision **+1%** · Δrecall **-1%** · 2026-07-11T06:46:31

## Flips: 10 (improve 3 · regress 4 · neutral 3)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:18 | real | TP → FP | REGRESS | Medium→Medium |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/medium.php:28 | not-real | FP → TP | REGRESS | Low→Low |
| yaml.github-actions.security.run-shell-injection.run-shell-injection@.github/workflows/docker-image.yml:29 | not-real | TP → FP | IMPROVE | High→Medium |
| cpp/overflow-buffer@practice/if_constexpr.cpp:15 | real | FP → TP | IMPROVE | Medium→Medium |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:13 | not-real | TP → NMD | neutral | Low→Medium |
| js/code-injection@app/routes/contributions.js:33 | real | NMD → TP | IMPROVE | Medium→High |
| js/missing-rate-limiting@app/routes/index.js:34 | real | TP → NMD | REGRESS | Medium→High |
| js/polynomial-redos@app/routes/session.js:181 | real | TP → FP | REGRESS | Low→Low |
| js/sql-injection@app/data/user-dao.js:91 | real | NMD → FP | neutral | High→Low |
| js/sql-injection@app/data/user-dao.js:104 | real | NMD → FP | neutral | Medium→Low |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | -$0.25         |
| input tokens      | -35k           |
| output tokens     | +7k            |
| cache hit ratio   | +4.3pp         |
| model time        | +738.9s        |
| iterations (mean) | -0.05          |
| errors            | +0             |
| abstentions       | -1             |
