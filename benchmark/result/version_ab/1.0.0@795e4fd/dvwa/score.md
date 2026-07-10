# Score — 1.0.0@795e4fd

Model `gpt-5.5` · temp `0` · panel `sha256:7d1c6808c…` · 2026-07-01T06:47:34

precision **77%** · recall **81%** · TP 44 (real 34, false-alarm 10) · real 42 · not-real 29 · NMD 0 · err 0 · $11.0933
_resources:_ 1.34M in / 275k out · cache 64% · 10450.4s model-time · iters μ3.45

| finding | truth | verdict | grade | conf |
|---|---|---|---|---|
| javascript.browser.security.eval-detected.eval-detected@vulnerabilities/javascript/source/high.js:1 | not-real | FP | CORRECT | High |
| javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp@vulnerabilities/javascript/source/high.js:1 | not-real | FP | CORRECT | High |
| javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp@vulnerabilities/javascript/source/high.js:1 | not-real | FP | CORRECT | High |
| php.lang.security.audit.openssl-decrypt-validate.openssl-decrypt-validate@vulnerabilities/api/src/Token.php:39 | not-real | TP | FALSE-ALARM | Low |
| php.lang.security.eval-use.eval-use@vulnerabilities/view_help.php:20 | real | TP | CORRECT | Medium |
| php.lang.security.eval-use.eval-use@vulnerabilities/view_help.php:22 | real | TP | CORRECT | High |
| php.lang.security.exec-use.exec-use@vulnerabilities/api/src/HealthController.php:88 | real | TP | CORRECT | High |
| php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/high.php:26 | real | TP | CORRECT | High |
| php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/high.php:30 | real | TP | CORRECT | High |
| php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/impossible.php:22 | not-real | FP | CORRECT | High |
| php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/impossible.php:26 | not-real | FP | CORRECT | High |
| php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/low.php:10 | real | TP | CORRECT | High |
| php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/low.php:14 | real | TP | CORRECT | High |
| php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/medium.php:19 | real | TP | CORRECT | High |
| php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/medium.php:23 | real | TP | CORRECT | High |
| php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/api/src/HealthController.php:88 | real | TP | CORRECT | High |
| php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/high.php:26 | real | TP | CORRECT | High |
| php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/high.php:30 | real | TP | CORRECT | High |
| php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/impossible.php:22 | not-real | FP | CORRECT | High |
| php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/impossible.php:26 | not-real | FP | CORRECT | High |
| php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/low.php:10 | real | TP | CORRECT | High |
| php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/low.php:14 | real | TP | CORRECT | High |
| php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/medium.php:19 | real | TP | CORRECT | High |
| php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/medium.php:23 | real | TP | CORRECT | High |
| php.lang.security.injection.tainted-filename.tainted-filename@instructions.php:26 | not-real | FP | CORRECT | High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/fi/source/high.php:7 | not-real | FP | CORRECT | Medium |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_help.php:20 | real | FP | MISS | Medium |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_help.php:22 | real | FP | MISS | Medium |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:14 | real | FP | MISS | High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:18 | real | FP | MISS | High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:22 | real | FP | MISS | High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:26 | real | FP | MISS | High |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:63 | real | FP | MISS | Medium |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:67 | real | TP | CORRECT | Low |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:68 | real | FP | MISS | Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/low.php:22 | not-real | FP | CORRECT | High |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/low.php:35 | not-real | TP | FALSE-ALARM | Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/low.php:79 | real | TP | CORRECT | Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/medium.php:21 | not-real | FP | CORRECT | High |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/medium.php:28 | not-real | TP | FALSE-ALARM | Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/medium.php:71 | real | TP | CORRECT | Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/brute/source/low.php:12 | real | TP | CORRECT | High |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/high.php:11 | real | TP | CORRECT | High |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/high.php:33 | real | TP | CORRECT | Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/low.php:11 | real | TP | CORRECT | High |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/low.php:32 | real | TP | CORRECT | Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/medium.php:34 | real | TP | CORRECT | Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli/source/low.php:10 | real | TP | CORRECT | High |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli/source/low.php:31 | real | TP | CORRECT | High |
| php.lang.security.md5-loose-equality.md5-loose-equality@login.php:41 | not-real | FP | CORRECT | High |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/brute/source/high.php:22 | not-real | FP | CORRECT | High |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/brute/source/low.php:15 | not-real | FP | CORRECT | High |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/brute/source/medium.php:17 | not-real | FP | CORRECT | High |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/captcha/source/impossible.php:46 | not-real | TP | FALSE-ALARM | High |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/cryptography/source/ecb_attack.php:92 | not-real | TP | FALSE-ALARM | Low |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/csrf/test_credentials.php:23 | not-real | FP | CORRECT | High |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/javascript/index.php:43 | not-real | TP | FALSE-ALARM | Low |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/javascript/index.php:57 | not-real | FP | CORRECT | High |
| php.lang.security.php-permissive-cors.php-permissive-cors@vulnerabilities/api/gen_openapi.php:6 | not-real | TP | FALSE-ALARM | High |
| php.lang.security.php-permissive-cors.php-permissive-cors@vulnerabilities/api/public/index.php:11 | not-real | TP | FALSE-ALARM | High |
| php.lang.security.phpinfo-use.phpinfo-use@phpinfo.php:8 | real | TP | CORRECT | Medium |
| php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/high.php:26 | real | TP | CORRECT | High |
| php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/high.php:30 | real | TP | CORRECT | High |
| php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/impossible.php:22 | not-real | FP | CORRECT | Medium |
| php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/impossible.php:26 | not-real | FP | CORRECT | Medium |
| php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/low.php:10 | real | TP | CORRECT | High |
| php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/low.php:14 | real | TP | CORRECT | High |
| php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/medium.php:19 | real | TP | CORRECT | High |
| php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/medium.php:23 | real | TP | CORRECT | High |
| php.lang.security.unlink-use.unlink-use@vulnerabilities/upload/source/impossible.php:54 | not-real | TP | FALSE-ALARM | Low |
| yaml.github-actions.security.run-shell-injection.run-shell-injection@.github/workflows/docker-image.yml:29 | not-real | TP | FALSE-ALARM | Medium |
