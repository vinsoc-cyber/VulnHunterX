# Compare — 1.0.0@eda2fd0 → 1.0.0@795e4fd

Δprecision **-0%** · Δrecall **+7%** · 2026-07-03T12:17:58

## Flips: 8 (improve 5 · regress 3 · neutral 0)

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
