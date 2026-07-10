# Compare — 1.0.0@795e4fd → 1.0.0@8a63259

Δprecision **+0%** · Δrecall **+1%** · 2026-07-10T01:45:04

## Flips: 5 (improve 3 · regress 2 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/cryptography/source/ecb_attack.php:92 | not-real | TP → FP | IMPROVE | Low→High |
| php.lang.security.unlink-use.unlink-use@vulnerabilities/upload/source/impossible.php:54 | not-real | TP → FP | IMPROVE | Low→High |
| cpp/suspicious-sizeof@practice/decay.cpp:5 | not-real | FP → TP | REGRESS | High→Low |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:13 | not-real | FP → TP | REGRESS | Medium→Low |
| js/polynomial-redos@app/routes/profile.js:61 | real | NMD → TP | IMPROVE | Medium→Medium |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | -$1.23         |
| input tokens      | -197k          |
| output tokens     | -16k           |
| cache hit ratio   | +3.7pp         |
| model time        | -8821.9s       |
| iterations (mean) | -0.26          |
| errors            | +0             |
| abstentions       | -1             |
