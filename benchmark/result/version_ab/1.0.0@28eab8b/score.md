# Score — 1.0.0@28eab8b

Model `gpt-5.5` · temp `0` · 2026-07-12T12:21:06

precision **92%** · recall **95%** · TP 91 (real 84, false-alarm 7) · real 88 · not-real 37 · NMD 1 · err 0 · $14.5812
_resources:_ 1.72M in / 377k out · cache 69% · 8712.1s model-time · iters μ2.49

| target | finding | truth | verdict | grade | conf |
|---|---|---|---|---|---|
| dvcp | cpp/double-free@imgRead.c:62 | real | TP | CORRECT | High |
| dvcp | cpp/invalid-pointer-deref@imgRead.c:91 | real | TP | CORRECT | High |
| dvcp | cpp/invalid-pointer-deref@imgRead.c:95 | real | TP | CORRECT | High |
| dvcp | cpp/path-injection@imgRead.c:132 | not-real | FP | CORRECT | Medium |
| dvcp | cpp/use-after-free@imgRead.c:67 | real | TP | CORRECT | High |
| dvwa | javascript.browser.security.eval-detected.eval-detected@vulnerabilities/javascript/source/high.js:1 | not-real | FP | CORRECT | High |
| dvwa | javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp@vulnerabilities/javascript/source/high.js:1 | not-real | FP | CORRECT | High |
| dvwa | javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp@vulnerabilities/javascript/source/high.js:1 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.audit.openssl-decrypt-validate.openssl-decrypt-validate@vulnerabilities/api/src/Token.php:39 | not-real | FP | CORRECT | Medium |
| dvwa | php.lang.security.eval-use.eval-use@vulnerabilities/view_help.php:20 | real | TP | CORRECT | Medium |
| dvwa | php.lang.security.eval-use.eval-use@vulnerabilities/view_help.php:22 | real | TP | CORRECT | High |
| dvwa | php.lang.security.exec-use.exec-use@vulnerabilities/api/src/HealthController.php:88 | real | TP | CORRECT | High |
| dvwa | php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/high.php:26 | real | TP | CORRECT | High |
| dvwa | php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/high.php:30 | real | TP | CORRECT | High |
| dvwa | php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/impossible.php:22 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/impossible.php:26 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/low.php:10 | real | TP | CORRECT | High |
| dvwa | php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/low.php:14 | real | TP | CORRECT | High |
| dvwa | php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/medium.php:19 | real | TP | CORRECT | High |
| dvwa | php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/medium.php:23 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/api/src/HealthController.php:88 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/high.php:26 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/high.php:30 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/impossible.php:22 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/impossible.php:26 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/low.php:10 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/low.php:14 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/medium.php:19 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-exec.tainted-exec@vulnerabilities/exec/source/medium.php:23 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-filename.tainted-filename@instructions.php:26 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/fi/source/high.php:7 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_help.php:20 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_help.php:22 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:14 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:18 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:22 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source_all.php:26 | real | TP | CORRECT | Medium |
| dvwa | php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:63 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:67 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:68 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/low.php:22 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/low.php:35 | not-real | TP | FALSE-ALARM | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/low.php:79 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/medium.php:21 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/medium.php:28 | not-real | TP | FALSE-ALARM | Low |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/medium.php:71 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/brute/source/low.php:12 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/high.php:11 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/high.php:33 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/low.php:11 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/low.php:32 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli_blind/source/medium.php:34 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli/source/low.php:10 | real | TP | CORRECT | High |
| dvwa | php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/sqli/source/low.php:31 | real | TP | CORRECT | High |
| dvwa | php.lang.security.md5-loose-equality.md5-loose-equality@login.php:41 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/brute/source/high.php:22 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/brute/source/low.php:15 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/brute/source/medium.php:17 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/captcha/source/impossible.php:46 | not-real | FP | CORRECT | Medium |
| dvwa | php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/cryptography/source/ecb_attack.php:92 | not-real | NMD | abstain | Medium |
| dvwa | php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/csrf/test_credentials.php:23 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/javascript/index.php:43 | not-real | FP | CORRECT | Low |
| dvwa | php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/javascript/index.php:57 | not-real | FP | CORRECT | Low |
| dvwa | php.lang.security.php-permissive-cors.php-permissive-cors@vulnerabilities/api/gen_openapi.php:6 | not-real | TP | FALSE-ALARM | Medium |
| dvwa | php.lang.security.php-permissive-cors.php-permissive-cors@vulnerabilities/api/public/index.php:11 | not-real | TP | FALSE-ALARM | Medium |
| dvwa | php.lang.security.phpinfo-use.phpinfo-use@phpinfo.php:8 | real | TP | CORRECT | Medium |
| dvwa | php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/high.php:26 | real | TP | CORRECT | High |
| dvwa | php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/high.php:30 | real | TP | CORRECT | High |
| dvwa | php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/impossible.php:22 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/impossible.php:26 | not-real | FP | CORRECT | High |
| dvwa | php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/low.php:10 | real | TP | CORRECT | High |
| dvwa | php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/low.php:14 | real | TP | CORRECT | High |
| dvwa | php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/medium.php:19 | real | TP | CORRECT | High |
| dvwa | php.lang.security.tainted-exec.tainted-exec@vulnerabilities/exec/source/medium.php:23 | real | TP | CORRECT | High |
| dvwa | php.lang.security.unlink-use.unlink-use@vulnerabilities/upload/source/impossible.php:54 | not-real | FP | CORRECT | High |
| dvwa | yaml.github-actions.security.run-shell-injection.run-shell-injection@.github/workflows/docker-image.yml:29 | not-real | TP | FALSE-ALARM | Medium |
| insecure-coding-examples | cpp/dangerous-cin@exploit/wargames/launch_bigger.cpp:19 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/dangerous-cin@exploit/wargames/launch.cpp:19 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/dangerous-function-overflow@exploit/wargames/launch.c:19 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/dangerous-function-overflow@exploitable/stack_buffer_overflow.c:13 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/double-free@exploitable/double_free.c:15 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/non-constant-format@exploit/format/direct_access.c:7 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/non-constant-format@exploit/format/exploitable.c:66 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/non-constant-format@exploit/format/exploitable_simple.c:12 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/non-constant-format@exploitable/uncontrolled_format_string.c:14 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/overflow-buffer@exploitable/global_buffer_overflow.c:9 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/overflow-buffer@practice/if_constexpr.cpp:15 | real | FP | MISS | High |
| insecure-coding-examples | cpp/signed-overflow-check@exploitable/signed_integer_overflow.c:16 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/signed-overflow-check@exploitable/undefined_behavior.cpp:11 | not-real | FP | CORRECT | Medium |
| insecure-coding-examples | cpp/signed-overflow-check@exploitable/undefined_behavior.cpp:15 | not-real | FP | CORRECT | Medium |
| insecure-coding-examples | cpp/signed-overflow-check@practice/if_constexpr.cpp:14 | real | FP | MISS | Medium |
| insecure-coding-examples | cpp/static-buffer-overflow@practice/if_constexpr.cpp:15 | real | FP | MISS | Medium |
| insecure-coding-examples | cpp/suspicious-sizeof@practice/decay.cpp:5 | not-real | FP | CORRECT | High |
| insecure-coding-examples | cpp/suspicious-sizeof@practice/guidelines/expressions_and_statements/cautious_pointer_use_decay.cpp:10 | not-real | FP | CORRECT | High |
| insecure-coding-examples | cpp/tainted-format-string@exploit/format/direct_access.c:7 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/tainted-format-string@exploit/format/exploitable.c:66 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/tainted-format-string@exploit/format/exploitable_simple.c:12 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/tainted-format-string@exploitable/uncontrolled_format_string.c:14 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:13 | not-real | TP | FALSE-ALARM | Medium |
| insecure-coding-examples | cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:16 | not-real | TP | FALSE-ALARM | Low |
| insecure-coding-examples | cpp/unbounded-write@exploit/format/exploitable.c:64 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/unbounded-write@exploit/format/exploitable_simple.c:11 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/unbounded-write@exploit/wargames/launch.c:19 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/unbounded-write@exploitable/heap_buffer_overflow.c:14 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/unbounded-write@exploitable/heap_buffer_overflow_cwe.c:14 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/unbounded-write@exploitable/stack_buffer_overflow.c:13 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/unbounded-write@exploitable/stack_buffer_overflow_cwe.c:13 | real | TP | CORRECT | High |
| insecure-coding-examples | cpp/use-after-free@exploitable/use_after_free.c:19 | real | TP | CORRECT | High |
| nodegoat | js/clear-text-cookie@server.js:78 | real | TP | CORRECT | High |
| nodegoat | js/code-injection@app/data/allocations-dao.js:78 | real | TP | CORRECT | High |
| nodegoat | js/code-injection@app/routes/contributions.js:32 | real | TP | CORRECT | High |
| nodegoat | js/code-injection@app/routes/contributions.js:33 | real | TP | CORRECT | High |
| nodegoat | js/code-injection@app/routes/contributions.js:34 | real | TP | CORRECT | High |
| nodegoat | js/indirect-command-line-injection@Gruntfile.js:166 | not-real | FP | CORRECT | Low |
| nodegoat | js/log-injection@app/routes/session.js:64 | real | TP | CORRECT | High |
| nodegoat | js/missing-rate-limiting@app/routes/index.js:34 | real | TP | CORRECT | Medium |
| nodegoat | js/missing-token-validation@server.js:78 | real | FP | MISS | Low |
| nodegoat | js/polynomial-redos@app/routes/profile.js:61 | real | TP | CORRECT | High |
| nodegoat | js/polynomial-redos@app/routes/session.js:181 | real | TP | CORRECT | High |
| nodegoat | js/redos@app/routes/profile.js:59 | real | TP | CORRECT | High |
| nodegoat | js/request-forgery@app/routes/research.js:16 | real | TP | CORRECT | High |
| nodegoat | js/server-side-unvalidated-url-redirection@app/routes/index.js:72 | real | TP | CORRECT | High |
| nodegoat | js/session-fixation@app/routes/index.js:34 | real | TP | CORRECT | High |
| nodegoat | js/sql-injection@app/data/user-dao.js:104 | real | TP | CORRECT | Medium |
| nodegoat | js/sql-injection@app/data/user-dao.js:91 | real | TP | CORRECT | High |

## Per target — correctness
| target | precision | recall | TP (real/FA) | real | not-real | NMD | err | panel |
|---|---|---|---|---|---|---|---|---|
| dvcp | 100% | 100% | 4 (4/0) | 4 | 1 | 0 | 0 | sha256:eebf118bd… |
| dvwa | 89% | 100% | 47 (42/5) | 42 | 29 | 1 | 0 | sha256:7d1c6808c… |
| insecure-coding-examples | 92% | 88% | 25 (23/2) | 26 | 6 | 0 | 0 | sha256:9cdeda155… |
| nodegoat | 100% | 94% | 15 (15/0) | 16 | 1 | 0 | 0 | sha256:1179d5607… |

## Per target — resources
| target | in-tok | out-tok | cache% | time(s) | itersμ | cost |
|---|---|---|---|---|---|---|
| dvcp | 27k | 7k | 21% | 169.9 | 1.2 | $0.3358 |
| dvwa | 1.19M | 262k | 69% | 6036.1 | 2.96 | $10.1076 |
| insecure-coding-examples | 162k | 45k | 75% | 1050.2 | 1.31 | $1.5952 |
| nodegoat | 346k | 63k | 69% | 1456.0 | 3.12 | $2.5426 |
