# Compare — 1.0.0@795e4fd → 1.0.0@8a63259

Δprecision **+4%** · Δrecall **+0%** · 2026-07-10T01:45:04

## Flips: 2 (improve 2 · regress 0 · neutral 0)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/cryptography/source/ecb_attack.php:92 | not-real | TP → FP | IMPROVE | Low→High |
| php.lang.security.unlink-use.unlink-use@vulnerabilities/upload/source/impossible.php:54 | not-real | TP → FP | IMPROVE | Low→High |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | -$0.69         |
| input tokens      | -167k          |
| output tokens     | -10k           |
| cache hit ratio   | +0.5pp         |
| model time        | -5367.2s       |
| iterations (mean) | -0.34          |
| errors            | +0             |
| abstentions       | +0             |
