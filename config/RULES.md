# SAST Security Scan Rules

This document is a reference inventory of every static-analysis rule set VulnHunterX runs, the profiles that select them, and how their findings reach the LLM verification stage. It is sourced from [rule_categories.yaml](rule_categories.yaml), [codeql-custom/](codeql-custom/), [semgrep-custom/](semgrep-custom/), and [prompts/](prompts/). For the surrounding pipeline architecture, see the [Pipeline Stages](../README.md#pipeline-stages) section of the README.

## 1. Overview

Stage 2 of the pipeline runs three SAST engines in parallel: **CodeQL** (database-driven taint analysis), **Semgrep**, and **OpenGrep** (Semgrep-compatible fork). The `--profile` flag picks a named bundle from [rule_categories.yaml](rule_categories.yaml) that controls (a) which built-in CodeQL suite is selected, (b) which Semgrep registry packs are pulled, and (c) whether the local custom CodeQL/Semgrep rule trees under `config/codeql-custom/` and `config/semgrep-custom/` are layered on top.

Each emitted SARIF finding is then routed in [verification/](../src/vuln_hunter_x/verification/) to a guided-question template in [prompts/](prompts/) using a 3-tier match (exact `ruleId` → normalized/prefix → `CWE` tag via [`cwe_question_map`](rule_categories.yaml)). The LLM verdict is `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `NEEDS_MORE_DATA`.

## 2. Rule Profiles

CLI: `vuln-hunter-x analyze --profile <name>`. From least to most coverage:

| Profile | CodeQL suite | Semgrep universal packs | Language-specific packs | Custom rules | When to use |
|---|---|---|---|---|---|
| `standard` (default) | `security-extended` | `auto` | — | — | Fast baseline scan; mirrors a typical CodeQL Actions run. |
| `extended` | `security-extended` | `auto`, `p/security-audit`, `p/secrets` | — | — | Adds broad audit + secrets detection without the quality-rule noise. |
| `maximum` | `security-and-quality` | + `p/owasp-top-ten` | — | — | OWASP coverage on top of the full quality-and-security suite. |
| `extended-registry` | `security-and-quality` | + `p/cwe-top-25`, `p/gitleaks`, `p/jwt`, `p/insecure-transport` | python (`p/python`, `p/django`, `p/flask`); js (`p/javascript`, `p/nodejs`, `p/eslint-plugin-security`); ts (`p/typescript`, `p/nodejs`); java (`p/java`); php (`p/php`); go (`p/gosec`) | — | Broadest public-registry coverage without project-local rules. |
| `full` | `security-and-quality` | (same 8 universal packs) | (same per-language packs) | **+ `codeql-custom/<lang>/`** **+ `semgrep-custom/<lang>.yaml`** | Maximum coverage including project-specific queries for CWEs the registry misses. Use for release gates and audits. |

Rule counts captured during the Stage-2 audit are inlined as comments in [rule_categories.yaml](rule_categories.yaml); they drift over time. Re-verify with `python scripts/audit_rule_coverage.py --probe-tools`.

## 3. Custom CodeQL Queries

Layered onto CodeQL via the `full` profile (`include_custom_codeql: true`). The `@id` field takes the form `<lang>/<name>` so the verification engine can match findings to guided questions of the same key. When no exact match is found, the routing falls back to the `external/cwe/cwe-*` tag via [`cwe_question_map`](rule_categories.yaml).

All five language packs ship working queries — totals are sourced directly from each query's `@id` / `@kind` / `@security-severity` / `external/cwe/cwe-*` header.
<!-- ql_tables_begin -->
### C/C++ — [codeql-custom/cpp/src/](codeql-custom/cpp/src/) (16 rules)

| `@id` | CWE | Kind | Severity | Description |
|---|---|---|---|---|
| `cpp/command-injection` | CWE-78/CWE-77 | path-problem | 9.0 | User-controlled data reaching `system`, `popen`, `execl`, `execv`, `execlp`, or `execvp` without sanitisation lets an attacker inject shell metacharacters or override the executed program (CWE-78). |
| `cpp/csv-formula-injection` | CWE-1236 | path-problem | 6.5 | Writing user input to a CSV/TSV file via `fputs` / `fprintf` / `fwrite` without escaping leading `=`, `+`, `-`, `@`, tab, or carriage-return characters enables formula injection: a victim opening the file in Excel / LibreOffice / Google Sheets will execute the formula. |
| `cpp/dangling-pointer` | CWE-825 | problem | 7.5 | A pointer that captures the address of a local variable becomes dangling once that variable's scope ends. |
| `cpp/exception-unsafe` | CWE-755 | problem | 6.0 | A bare new/malloc/fopen acquisition followed by code that may throw, without the resource owned by an RAII type (smart pointer, std::lock_guard, etc.), leaks the resource if the intermediate code throws. |
| `cpp/format-string-injection` | CWE-134 | problem | 7.0 | A printf-family call whose format-string argument is not a string literal AND whose containing function lacks `__attribute__((format(printf, ...)))` annotation is a structurally dangerous design — even if no taint reaches it today, any future change can turn it into CWE-134. |
| `cpp/input-validation` | CWE-129/CWE-125 | path-problem | 8.0 | An externally controlled integer used as an array subscript without a preceding upper-bound comparison against the array's size. |
| `cpp/integer-truncation` | CWE-197/CWE-190 | path-problem | 7.5 | A tainted (externally controlled) integer of wide type (size_t / uint64_t / long long) cast or implicitly converted to a narrower type that is then used as an array index, buffer size, or memory-copy length. |
| `cpp/missing-return-value-check` | CWE-252/CWE-253 | problem | 6.5 | Functions that signal failure via their return value (malloc / calloc / realloc / fopen / mmap / read / write / socket / recv / send) must have that value compared to an error sentinel before subsequent use. |
| `cpp/null-pointer-deref` | CWE-476 | problem | 7.5 | A pointer returned from malloc / calloc / realloc that is dereferenced without first being compared against NULL is a guaranteed crash on allocation failure (CWE-476) and on attacker-influenced size-zero / out-of-memory paths can be promoted into a DoS or worse. |
| `cpp/out-of-bounds-read` | CWE-125/CWE-129 | path-problem | 7.0 | An array or buffer read whose index / length parameter is tainted by an external source (argv, getenv, read, recv, scanf) and does not pass through a bounding check before reaching the array-access / memcpy sink is a CWE-125 candidate. |
| `cpp/signed-overflow` | CWE-190 | problem | 5.5 | Left-shifting a signed integer whose result does not fit in its destination type is undefined behaviour in C and C++11 (5.8p2). |
| `cpp/timing-unsafe-comparison` | CWE-208 | problem | 6.5 | `memcmp` / `strcmp` / `strncmp` / `==` short-circuit on the first differing byte, leaking secret content via response time. |
| `cpp/uncontrolled-resource` | CWE-770/CWE-400 | path-problem | 7.5 | An allocation or loop bound driven by an external (taint) source without an intervening upper-bound comparison is a denial-of-service primitive (CWE-770 / CWE-400). |
| `cpp/untrusted-search-path` | CWE-426/CWE-829 | problem | 7.0 | `system`, `execvp`, `execlp`, `execvpe`, or `posix_spawnp` executed with a relative-path or bare-name program is resolved against `$PATH`. |
| `cpp/use-after-move` | CWE-672 | problem | 7.5 | An object used after being moved-from holds an unspecified state and reading its value, or calling non-trivial methods other than assignment / destruction, is undefined behaviour. |
| `cpp/use-of-uninitialized-variable` | CWE-457/CWE-200 | problem | 7.0 | A struct allocated via `malloc` (not `calloc` / `new` / value initialisation) has indeterminate contents until each field is written. |

### Java — [codeql-custom/java/src/](codeql-custom/java/src/) (10 rules)

| `@id` | CWE | Kind | Severity | Description |
|---|---|---|---|---|
| `java/certificate-validation-disabled` | CWE-295/CWE-297 | problem | 8.5 | A `X509TrustManager` whose `checkClientTrusted` or `checkServerTrusted` body is empty, OR a `HostnameVerifier` whose `verify` returns `true` unconditionally, disables TLS authentication and exposes the connection to MITM. |
| `java/csv-formula-injection` | CWE-1236 | path-problem | 6.0 | User input written to a CSV/XLSX cell without escaping a leading `=`/`+`/`-`/`@` is interpreted as a formula when a victim opens the file in Excel, LibreOffice, or Google Sheets. |
| `java/incorrect-authorization` | CWE-639/CWE-285 | problem | 7.5 | A Spring controller handler reads a path/query parameter and passes it directly to a Spring Data repository `findById` / `getOne` / `getReferenceById` without any filter on the authenticated user. |
| `java/log4j-injection-ext` | CWE-117/CWE-20 | path-problem | 9.0 | Tainted user input reaches a Log4j 2.x logging call. On vulnerable Log4j versions (pre-2.17 or with `formatMsgNoLookups=false`), the logger expands `${jndi:...}` substitutions in the message string, enabling RCE (Log4Shell, CVE-2021-44228). |
| `java/mass-assignment` | CWE-915 | problem | 7.0 | A Spring controller method that binds `@RequestBody` or `@ModelAttribute` directly to a JPA entity class containing `@Id`, `@Version`, or `@Column(updatable=false)` fields allows attackers to override those fields by including them in the request body. |
| `java/overflow-destination` | CWE-805/CWE-806 | path-problem | 6.5 | `System.arraycopy(src, srcPos, dst, dstPos, length)` throws ArrayIndexOutOfBoundsException if any computed index is out of bounds. |
| `java/spring-actuator-exposed` | CWE-250/CWE-200 | problem | 8.0 | `management.endpoints.web.exposure.include=*` (or contains `env`/`heapdump`/`shutdown`/`loggers`) without matching `exclude` exposes sensitive runtime introspection to anyone who can reach the management port — including environment variables, heap dumps, and (when wired) shutdown. |
| `java/ssrf-ext` | CWE-918 | path-problem | 8.6 | A `RemoteFlowSource` (HTTP request parameter, header, body, etc.) reaches a `URL` / `URI` constructor or an outbound HTTP client call (`HttpURLConnection.openConnection`, `WebClient.uri`, Apache HttpClient `execute`) without validation against an allow-list of trusted destinations. |
| `java/timing-unsafe-comparison` | CWE-208 | problem | 6.5 | `String.equals`, `Arrays.equals`, and `==` are not constant-time and short-circuit on the first differing byte. |
| `java/zip-slip` | CWE-22 | path-problem | 8.5 | Extracting `ZipEntry.getName()` into a `File`, `Path`, or `FileOutputStream` without first verifying that the resolved path stays within a base directory allows the ZipSlip attack (CVE-2018-1002) — entries named `../../etc/passwd` overwrite arbitrary files. |

### JavaScript / TypeScript — [codeql-custom/javascript/src/](codeql-custom/javascript/src/) (14 rules)

| `@id` | CWE | Kind | Severity | Description |
|---|---|---|---|---|
| `js/command-injection` | CWE-78 | path-problem | 9.8 | User-controlled data passed to `child_process.exec` / `execSync`, or to `spawn` / `spawnSync` / `execFile` / `execFileSync` with `shell: true`, lets an attacker inject shell metacharacters and execute arbitrary OS commands. |
| `js/csv-formula-injection` | CWE-1236 | path-problem | 6.0 | User input written to a CSV-style output without escaping leading `=`/`+`/`-`/`@` is interpreted as a formula in Excel / LibreOffice / Google Sheets, enabling DDE / HYPERLINK / WEBSERVICE payload execution. |
| `js/event-handler-injection` | CWE-95/CWE-79 | path-problem | 7.5 | Setting `element.onclick` / `element.setAttribute('onclick', ...)` (or any `on*` handler attribute) to a tainted string makes the browser parse it as JavaScript on first event — a distinct XSS sink from innerHTML. |
| `js/input-validation` | CWE-693 | problem | 5.0 | An Express application that never calls `app.use(helmet())` ships without standard security response headers (CSP, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, etc.). |
| `js/insecure-cookie` | CWE-1004/CWE-1275 | problem | 6.5 | `res.cookie(name, value, opts)` or `cookie.serialize` called without `httpOnly: true` (CWE-1004) or without `sameSite: 'lax' \| 'strict'` (CWE-1275) on a cookie that looks session-bearing exposes the cookie to JS-based theft and CSRF. |
| `js/insecure-websocket` | CWE-319 | problem | 7.0 | `new WebSocket('ws://...')` (or a tainted URL not validated to start with `wss://`) transmits frames in cleartext, allowing network attackers to read or modify messages. |
| `js/missing-authentication` | CWE-306/CWE-862 | problem | 7.0 | An Express route handler (`app.METHOD(path, handler)`) whose middleware chain does NOT pass through any recognised authentication middleware (`passport.authenticate`, `requireAuth`, `ensureLoggedIn`, `verifyToken`, etc.) exposes the endpoint to unauthenticated callers. |
| `js/nosql-injection` | CWE-943 | path-problem | 8.8 | User-controlled data passed directly into a MongoDB / Mongoose query (find / findOne / update / deleteOne) allows operator injection. |
| `js/path-traversal` | CWE-22 | path-problem | 7.5 | A user-controlled string flows into an `fs` path argument (readFile, writeFile, createReadStream, createWriteStream, unlink, …) without being resolved against — and confined within — a fixed base directory. |
| `js/prototype-pollution-ext` | CWE-1321 | path-problem | 8.2 | Writing `obj[key] = value` where `key` is user-controlled can set `__proto__` / `constructor` / `prototype` and poison `Object.prototype`. |
| `js/ssrf` | CWE-918 | path-problem | 8.6 | An HTTP request constructed from a remote source (req.query, req.body, req.params, etc.) without strict allow-list validation lets an attacker pivot to internal services (cloud metadata, localhost, RFC1918), exfiltrate data, or scan the internal network. |
| `js/timing-unsafe-comparison` | CWE-208 | problem | 6.0 | `==` / `===` / `!==` short-circuit on the first differing character. Use `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))` for any HMAC / signature / token / API key comparison. |
| `js/unrestricted-file-upload` | CWE-434 | path-problem | 7.5 | An uploaded file's name or path (from multer/formidable/busboy: req.file.filename, req.file.path, req.files[i].originalname) is written to disk via fs.writeFile / fs.createWriteStream without validating the extension against an allow-list. |
| `js/untrusted-module-loading` | CWE-829/CWE-470 | path-problem | 9.0 | `require(s)` or `import(s)` where `s` is attacker-influenced loads arbitrary code into the running Node process, equivalent to RCE. |

### Python — [codeql-custom/python/src/](codeql-custom/python/src/) (11 rules)

| `@id` | CWE | Kind | Severity | Description |
|---|---|---|---|---|
| `py/async-race-condition` | CWE-362 | problem | 5.5 | An `async def` that reads-then-writes a module-level mutable (dict / list / set / Counter) without holding an `asyncio.Lock` can lose updates when interleaved between awaits. |
| `py/csrf` | CWE-352 | problem | 7.0 | `@csrf_exempt` disables CSRF protection for a view. When that view also reads `request.POST` / `request.body`, the application is exposed to CSRF unless authentication is by other means (token in header, mTLS). |
| `py/csv-formula-injection` | CWE-1236 | path-problem | 6.0 | User input written to a CSV / XLSX cell via `csv.writer`, `pandas.to_csv`, `openpyxl`, or `xlsxwriter` without escaping leading `=`/`+`/`-`/`@` characters is interpreted as a formula in Excel / LibreOffice. |
| `py/django-raw-sql` | CWE-89 | path-problem | 9.0 | Django ORM normally parameterises queries safely, but `Model.objects.raw(s)`, `cursor.execute(s)`, `RawSQL(s)`, and `QuerySet.extra(where=[s])` accept arbitrary SQL. |
| `py/incorrect-authorization` | CWE-639/CWE-285 | problem | 7.5 | `Model.objects.get(pk=request.GET['id'])` (or via `request.POST` / `kwargs`) without filtering by the authenticated user lets anyone fetch any user's record (CWE-639). |
| `py/mass-assignment` | CWE-915 | problem | 7.5 | A `ModelForm.Meta.fields = '__all__'` or DRF `ModelSerializer.Meta.fields = '__all__'` allows any field on the model — including `is_staff`, `is_superuser`, `password`, `user`, `created_by`, `pk` — to be set from the request body. |
| `py/missing-access-control` | CWE-862 | problem | 6.5 | A view function registered to a sensitive-looking path (e.g. `/admin`, `/users/...`) that has no `@login_required`, `@permission_required`, `@user_passes_test`, FastAPI `Depends(get_current_user)`, Flask-Security `@auth_required`, etc. |
| `py/overflow-destination` | CWE-805/CWE-806 | path-problem | 7.0 | `struct.pack_into(fmt, buffer, offset, *values)` and `ctypes.memmove(dst, src, count)` accept raw byte counts that, when sourced from a tainted protocol field without a bound against destination size, overrun the destination buffer (raises an exception or — for memmove — corrupts memory). |
| `py/timing-unsafe-comparison` | CWE-208 | problem | 6.0 | Comparing a secret with `==` short-circuits on the first differing byte. Use `hmac.compare_digest` or `secrets.compare_digest` for any HMAC / signature / token / password digest equality check. |
| `py/unsafe-reflection` | CWE-470 | path-problem | 8.5 | Loading a module or attribute whose name is attacker-controlled lets the attacker pick any importable module — including ones whose side effects achieve RCE (os.system, subprocess.Popen, ctypes loaders). |
| `py/unsafe-string-formatting` | CWE-94/CWE-134 | path-problem | 8.0 | Python's `str.format()` exposes attribute and item access (`{0.__class__.__init__.__globals__[os]}`) inside format specifiers. |

### Go — [codeql-custom/go/src/](codeql-custom/go/src/) (8 rules)

| `@id` | CWE | Kind | Severity | Description |
|---|---|---|---|---|
| `go/cgo-vulnerability` | CWE-242 | problem | 7.0 | Passing untrusted (user-controlled) data directly to a C function via cgo bypasses Go's memory and string safety — the C side may dereference, format, or exec on raw bytes with no bounds or escaping. |
| `go/csv-formula-injection` | CWE-1236 | path-problem | 6.0 | `csv.Writer.Write(record)` or `excelize.SetCellValue(...)` with a value that starts with `=`/`+`/`-`/`@` interprets as a formula when the file is opened in Excel / LibreOffice / Google Sheets. |
| `go/input-validation` | CWE-444 | problem | 7.0 | An `http.Request` handler that reads both `Content-Length` and `Transfer-Encoding: chunked` from the request without rejecting the duplicated framing is exposed to HTTP request smuggling — a layer-7 attack against intermediaries that interpret one and forward the other. |
| `go/insecure-cookie` | CWE-1004/CWE-1275 | problem | 6.5 | An `http.Cookie` literal that carries session/auth state must set `HttpOnly: true` (CWE-1004), `SameSite:` to `http.SameSiteLaxMode` or `http.SameSiteStrictMode` (CWE-1275), and `Secure: true` (CWE-614) for HTTPS-only deployments. |
| `go/missing-return-value-check` | CWE-252 | problem | 6.0 | A function returning `error` whose result is assigned to `_` (or never bound at all) silently swallows failure. |
| `go/sql-injection-ext` | CWE-89 | path-problem | 8.5 | Custom rule supplementing built-in `go/sql-injection` — flags taint reaching `database/sql` Query / Exec via helper-wrapped concatenation builders (Squirrel, manual builders) that the built-in detector misses. |
| `go/template-injection` | CWE-94/CWE-1336 | path-problem | 8.5 | `text/template`'s `Execute` interprets `{{}}` actions and has no HTML escaping. When the TEMPLATE itself (not the data) is attacker-controlled, the attacker can call any method exposed on the data type. |
| `go/timing-unsafe-comparison` | CWE-208 | problem | 6.0 | `bytes.Equal`, `==`, and `strings.EqualFold` short-circuit on first differing byte. |

### C# — [codeql-custom/csharp/src/](codeql-custom/csharp/src/) (5 rules)

These fill gaps the comprehensive built-in `csharp-security-extended` suite leaves open (it already ships `cs/sql-injection`, `cs/command-line-injection`, `cs/path-injection`, `cs/zipslip`, `cs/unsafe-deserialization`, `cs/ldap-injection`, `cs/web/xss`, and more — those are not duplicated here).

| `@id` | CWE | Kind | Severity | Description |
|---|---|---|---|---|
| `cs/ssrf` | CWE-918 | path-problem | 8.6 | A `RemoteFlowSource` reaches an outbound HTTP call (`WebRequest.Create`, `HttpClient.GetAsync`/`SendAsync`/..., `new HttpRequestMessage`) without an allow-list of trusted destinations. The built-in suite has no SSRF query. |
| `cs/certificate-validation-disabled` | CWE-295 | problem | 7.4 | A `ServerCertificateValidationCallback` / `ServerCertificateCustomValidationCallback` / `RemoteCertificateValidationCallback` that unconditionally returns `true` disables TLS authentication (MITM). |
| `cs/csv-formula-injection` | CWE-1236 | path-problem | 6.5 | A `RemoteFlowSource` written into CSV/spreadsheet output via `StreamWriter`/`TextWriter`/`File.WriteAllText` without neutralising a leading `=`/`+`/`-`/`@` executes as a formula in Excel/LibreOffice. |
| `cs/weak-hash` | CWE-327/CWE-328 | problem | 7.5 | Constructing an MD5 or SHA-1 hash object (`MD5.Create()`, `new SHA1Managed()`, `new HMACMD5()`) for security purposes — both are collision-vulnerable. |
| `cs/timing-unsafe-comparison` | CWE-208 | problem | 5.9 | A secret (token / HMAC / signature / password / API key) compared with `==`, `Equals`, or `SequenceEqual` short-circuits on the first differing byte; use `CryptographicOperations.FixedTimeEquals`. |
<!-- ql_tables_end -->

## 4. Custom Semgrep / OpenGrep Rules

Layered onto Semgrep/OpenGrep via the `full` profile through `custom_semgrep_path: "config/semgrep-custom/${LANG}.yaml"`. Each rule sets `metadata.cwe` so findings without exact-id matches route to guided questions via [`cwe_question_map`](rule_categories.yaml) — Semgrep rule IDs cannot use `/`, so they never exact-match a guided-question key.

OpenGrep is a Semgrep fork (LGPL 2.1) and `OpenGrepAnalyzer` is a pure subclass of `SemgrepAnalyzer` ([../src/vuln_hunter_x/opengrep/analyzer.py](../src/vuln_hunter_x/opengrep/analyzer.py)) — both engines consume these YAMLs identically.
<!-- sg_tables_begin -->
### Python — [semgrep-custom/python.yaml](semgrep-custom/python.yaml) (22 rules)

| Rule id | CWE | Severity | Message |
|---|---|---|---|
| `vulnhunterx.python.flask-debug` | CWE-489 | ERROR | Flask app.run(debug=True) enables the Werkzeug interactive debugger which provides shell-level code execution on any unhandled exception. |
| `vulnhunterx.python.unsafe-yaml` | CWE-502 | ERROR | yaml.load() without an explicit SafeLoader / SafeYAML loader deserialises arbitrary Python objects — equivalent to eval() on untrusted input. |
| `vulnhunterx.python.insecure-tls-context` | CWE-295 | ERROR | SSLContext configured with check_hostname disabled or verify_mode set to CERT_NONE allows man-in-the-middle attacks even on https:// requests. |
| `vulnhunterx.python.regex-injection` | CWE-1333 | WARNING | User-controlled value used as a regex pattern — attacker can craft a pattern with catastrophic backtracking (ReDoS) or anchor manipulation. |
| `vulnhunterx.python.weak-hash` | CWE-327/CWE-328 | WARNING | Weak cryptographic hash algorithm (MD5 / SHA-1) — collision and length-extension attacks practical. |
| `vulnhunterx.python.insecure-rng` | CWE-330/CWE-338 | WARNING | The `random` module is not cryptographically secure — predictable from a small amount of output; used inside a function whose name suggests a security context. |
| `vulnhunterx.python.requests-verify-false` | CWE-295 | ERROR | HTTP client called with verify=False disables TLS certificate validation — MITM attacks become trivial on the network path. |
| `vulnhunterx.python.django-debug-prod` | CWE-489/CWE-200 | WARNING | DEBUG = True at module scope in a Django settings file leaks stack traces, query history, and request internals when shipped to production. |
| `vulnhunterx.python.django-allowed-hosts-wildcard` | CWE-200 | WARNING | ALLOWED_HOSTS = ["*"] disables Django's Host-header validation, allowing host-header injection and password-reset poisoning. |
| `vulnhunterx.python.predictable-temp-file` | CWE-377 | WARNING | tempfile.mktemp() / NamedTemporaryFile(delete=False) race-condition primitive — filename is returned but file is not opened atomically. |
| `vulnhunterx.python.shell-true` | CWE-78 | ERROR | subprocess.* with shell=True and a non-literal first argument lets attacker-controlled values reach /bin/sh as shell metacharacters. |
| `vulnhunterx.python.cleartext-password-log` | CWE-532/CWE-200 | WARNING | A variable whose name suggests it is a password, secret, token, or API key is being written to a log or stdout. |
| `vulnhunterx.python.file-upload` | CWE-434 | ERROR | A Werkzeug/Flask uploaded file is saved using its attacker-controlled .filename without secure_filename() or an extension allowlist. |
| `vulnhunterx.python.improper-privilege-management` | CWE-269 | ERROR | A privilege flag (is_superuser / is_staff / is_admin) is assigned a value derived from request data. |
| `vulnhunterx.python.verbose-error` | CWE-209 | WARNING | An exception traceback is returned in the HTTP response body, leaking stack frames, file paths, and internal state. |
| `vulnhunterx.python.cors-misconfiguration` | CWE-942 | ERROR | Flask-CORS configured with origins="*" AND supports_credentials=True reflects any site's authenticated requests. |
| `vulnhunterx.python.download-without-integrity` | CWE-494 | ERROR | A remote script is downloaded and piped straight to a shell (curl/wget ... \| bash) with no integrity check. |
| `vulnhunterx.python.swallowed-exception` | CWE-755 | ERROR | A verify() call is wrapped in try/except whose handler returns True (or passes) — a fail-open authentication bypass. |
| `vulnhunterx.python.ldap-injection` | CWE-90 | ERROR | Request data flows unescaped into an LDAP search filter (taint mode; escape_filter_chars sanitizes). |
| `vulnhunterx.python.template-injection` | CWE-1336/CWE-917 | ERROR | A Jinja2 template is compiled from a non-literal string — SSTI escalates to RCE via gadget expressions. |
| `vulnhunterx.python.nosql-injection` | CWE-943 | ERROR | A MongoDB query uses the $where operator with a non-literal value (server-side JS evaluation). |
| `vulnhunterx.python.xxe` | CWE-611 | ERROR | An lxml XMLParser is created with resolve_entities=True / no_network=False, enabling XXE file disclosure and SSRF. |

### JavaScript / TypeScript — [semgrep-custom/javascript.yaml](semgrep-custom/javascript.yaml) (13 rules)

| Rule id | CWE | Severity | Message |
|---|---|---|---|
| `vulnhunterx.js.prototype-pollution` | CWE-1321 | ERROR | Writing a bracket-indexed property whose key comes from user input can pollute Object.prototype (or any reachable prototype), influencing every object in the runtime. |
| `vulnhunterx.js.electron-node-integration` | CWE-1188 | ERROR | Electron BrowserWindow with `nodeIntegration: true` (or default value pre-v5) exposes full Node.js APIs to renderer code. |
| `vulnhunterx.js.html-injection` | CWE-79 | WARNING | Tainted value assigned to innerHTML / outerHTML / insertAdjacentHTML allows arbitrary HTML & script injection. |
| `vulnhunterx.js.weak-hash` | CWE-327/CWE-328 | WARNING | crypto.createHash with 'md5' / 'sha1' produces collisions cheaply. |
| `vulnhunterx.js.math-random-secret` | CWE-330/CWE-338 | WARNING | Math.random() is a pseudo-random generator seeded predictably — output can be reversed from a few samples. Flagged inside security-named functions. |
| `vulnhunterx.js.jwt-none` | CWE-347 | ERROR | JWT verification configured to accept algorithm 'none' — a forged token with `{"alg":"none"}` will pass without a signature. |
| `vulnhunterx.js.cors-credentials-wildcard` | CWE-942 | ERROR | CORS configured with origin "*" AND credentials: true. Browsers refuse this combination, but the misconfiguration often reveals broken intent. |
| `vulnhunterx.js.react-dangerously-set-html` | CWE-79 | WARNING | dangerouslySetInnerHTML bypasses React's auto-escaping. Matches the `{__html: $X}` object literal where `$X` is not a string literal. |
| `vulnhunterx.js.mongoose-where` | CWE-943 | ERROR | MongoDB $where operator evaluates the value as JavaScript on the server. |
| `vulnhunterx.js.download-without-integrity` | CWE-494 | ERROR | A remote script is downloaded and piped to a shell (curl/wget ... \| bash) via child_process with no integrity check. |
| `vulnhunterx.js.template-injection` | CWE-1336/CWE-917 | ERROR | A template engine (Handlebars/EJS/Pug/Lodash) compiles a non-literal string — server-side template injection. |
| `vulnhunterx.js.regex-injection` | CWE-1333 | WARNING | Request data is used to construct a RegExp (taint mode) — ReDoS / catastrophic backtracking hangs the event loop. |
| `vulnhunterx.js.mass-assignment` | CWE-915 | ERROR | An ORM model is created/updated from the entire req.body — attacker can set non-writable fields (role, isAdmin). |

### Java — [semgrep-custom/java.yaml](semgrep-custom/java.yaml) (16 rules)

| Rule id | CWE | Severity | Message |
|---|---|---|---|
| `vulnhunterx.java.weak-cipher` | CWE-327/CWE-328 | ERROR | Cipher.getInstance with a weak algorithm (DES / 3DES / RC2 / RC4 / Blowfish) or ECB mode. |
| `vulnhunterx.java.weak-hash` | CWE-327/CWE-328 | WARNING | MessageDigest.getInstance with MD5 or SHA-1. |
| `vulnhunterx.java.insecure-rng` | CWE-330/CWE-338 | WARNING | java.util.Random is a Linear Congruential Generator — output is predictable from a small window of samples. Flagged inside security-named methods. |
| `vulnhunterx.java.spring-csrf-disabled` | CWE-352 | WARNING | Spring Security HttpSecurity.csrf().disable() turns off CSRF protection for state-changing endpoints. |
| `vulnhunterx.java.xml-no-secure-features` | CWE-611 | ERROR | DocumentBuilderFactory created without explicitly disabling external entity expansion (XXE-prone defaults). |
| `vulnhunterx.java.hardcoded-jwt-secret` | CWE-798/CWE-259 | ERROR | JWT signing key is a string literal embedded in source. |
| `vulnhunterx.java.open-redirect` | CWE-601 | WARNING | Redirect target read directly from a request parameter without an allowlist check enables open-redirect (phishing pivot, OAuth token theft). |
| `vulnhunterx.java.file-upload` | CWE-434 | ERROR | A Spring MultipartFile is written to disk using its attacker-controlled getOriginalFilename() with no extension allowlist. |
| `vulnhunterx.java.improper-privilege-management` | CWE-269 | WARNING | System.setSecurityManager(null) removes the JVM access-control layer — subsequent code runs with no permission checks. |
| `vulnhunterx.java.resource-exhaustion` | CWE-400/CWE-770 | WARNING | The full request body is read into memory with no size cap (getInputStream().readAllBytes() / IOUtils). |
| `vulnhunterx.java.security-headers-disabled` | CWE-693 | WARNING | Spring Security secure-header defaults are explicitly disabled (frame options / HSTS / content-type options). |
| `vulnhunterx.java.verbose-error` | CWE-209 | WARNING | An exception's stack trace or message is written into the HTTP response, leaking internal state. |
| `vulnhunterx.java.cors-misconfiguration` | CWE-942 | ERROR | @CrossOrigin / CorsConfiguration allows origin "*" together with credentials. |
| `vulnhunterx.java.template-injection` | CWE-1336/CWE-917 | ERROR | A FreeMarker/Velocity template is built/evaluated from a dynamic string/reader — SSTI escalates to RCE. |
| `vulnhunterx.java.nosql-injection` | CWE-943 | ERROR | A MongoDB query is built from a non-literal string via BasicQuery / Document.parse (operator injection). |
| `vulnhunterx.java.regex-injection` | CWE-1333 | WARNING | Request data is compiled into a regular expression (taint mode; Pattern.quote sanitizes) — ReDoS. |

### Go — [semgrep-custom/go.yaml](semgrep-custom/go.yaml) (17 rules)

| Rule id | CWE | Severity | Message |
|---|---|---|---|
| `vulnhunterx.go.goroutine-leak` | CWE-405 | WARNING | Goroutine started inside a request/handler scope writes to an unbuffered channel without a select+timeout — if the receiver never reads, the goroutine blocks forever and leaks. |
| `vulnhunterx.go.panic-in-handler` | CWE-248 | WARNING | net/http handler can panic on a code path not wrapped by recover(). |
| `vulnhunterx.go.unsafe-pointer` | CWE-704 | WARNING | unsafe.Pointer cast between unrelated types bypasses Go's type system and can cause memory corruption, out-of-bounds reads, or undefined behaviour. |
| `vulnhunterx.go.weak-hash` | CWE-327/CWE-328 | WARNING | crypto/md5 and crypto/sha1 are vulnerable to collision and length-extension attacks. |
| `vulnhunterx.go.math-rand-secret` | CWE-330/CWE-338 | WARNING | math/rand is a deterministic PRNG seeded predictably. Flagged inside security-named functions. |
| `vulnhunterx.go.insecure-skip-verify` | CWE-295 | ERROR | tls.Config with InsecureSkipVerify: true disables TLS certificate validation — MITM attacks become trivial on the network path. |
| `vulnhunterx.go.world-writable-file` | CWE-732/CWE-276 | WARNING | File created with world-writable mode (0o666 / 0o777 / 0o646). |
| `vulnhunterx.go.hardcoded-jwt-secret` | CWE-798/CWE-259 | ERROR | JWT signing key is a string/byte-slice literal embedded in source. |
| `vulnhunterx.go.file-upload` | CWE-434 | ERROR | An uploaded file's attacker-controlled FileHeader.Filename is used as the destination path for os.Create / os.OpenFile. |
| `vulnhunterx.go.improper-privilege-management` | CWE-269 | WARNING | Escalation via syscall.Setuid/Setgid(0) or creation of a setuid/setgid-bit file (0o4xxx / 0o6xxx). |
| `vulnhunterx.go.resource-exhaustion` | CWE-400/CWE-770 | WARNING | io.ReadAll / ioutil.ReadAll on r.Body with no http.MaxBytesReader cap — unbounded body read. |
| `vulnhunterx.go.verbose-error` | CWE-209 | WARNING | http.Error is called with err.Error(), writing the raw internal error message to the client. |
| `vulnhunterx.go.download-without-integrity` | CWE-494 | ERROR | A remote script is downloaded and piped to a shell (exec.Command sh -c "curl ... \| sh") with no integrity check. |
| `vulnhunterx.go.xpath-injection` | CWE-643 | ERROR | Request data flows into an XPath expression compiled/evaluated by antchfx (taint mode). |
| `vulnhunterx.go.nosql-injection` | CWE-943 | ERROR | A MongoDB query is built with the $where operator (server-side JavaScript evaluation). |
| `vulnhunterx.go.regex-injection` | CWE-1333 | WARNING | Request data is compiled as a regex pattern (taint mode; regexp.QuoteMeta sanitizes) — ReDoS. |
| `vulnhunterx.go.open-redirect` | CWE-601 | WARNING | The http.Redirect target is derived from request data with no allowlist check (taint mode). |

### PHP — [semgrep-custom/php.yaml](semgrep-custom/php.yaml) (14 rules)

| Rule id | CWE | Severity | Message |
|---|---|---|---|
| `vulnhunterx.php.type-juggling` | CWE-1025 | WARNING | Loose comparison (== / !=) on a value derived from user input can be bypassed via PHP type juggling — e.g. `"0e1" == "0e2"` is true. |
| `vulnhunterx.php.extract-injection` | CWE-1062 | ERROR | extract() called on a user-controlled array allows an attacker to overwrite arbitrary local variables (including authorisation flags). |
| `vulnhunterx.php.variable-variables` | CWE-621 | WARNING | Variable-variable assignment ($$name = ...) near user-input access can allow an attacker to overwrite arbitrary variables in the current scope. |
| `vulnhunterx.php.file-inclusion` | CWE-98 | ERROR | include / require with a user-controlled path enables Local or Remote File Inclusion (LFI/RFI). |
| `vulnhunterx.php.weak-hash` | CWE-327/CWE-328 | WARNING | MD5 / SHA-1 are collision-vulnerable. |
| `vulnhunterx.php.insecure-rand` | CWE-330/CWE-338 | WARNING | rand() / mt_rand() are not cryptographically secure — flagged inside security-named functions. |
| `vulnhunterx.php.predictable-tempnam` | CWE-377 | WARNING | tempnam() in /tmp returns a predictable filename that an attacker with local access can pre-create or rebind. |
| `vulnhunterx.php.file-upload` | CWE-434 | ERROR | move_uploaded_file() writes the upload to a destination built from the attacker-controlled $_FILES[..]['name'] with no allowlist. |
| `vulnhunterx.php.ldap-injection` | CWE-90 | ERROR | Request data ($_GET/$_POST) flows unescaped into an LDAP search filter (taint mode; ldap_escape sanitizes). |
| `vulnhunterx.php.xpath-injection` | CWE-643 | ERROR | Request data flows into a DOMXPath query/evaluate expression (taint mode). |
| `vulnhunterx.php.xxe` | CWE-611 | ERROR | XML is parsed with the LIBXML_NOENT flag, which substitutes external entities — XXE file disclosure and SSRF. |
| `vulnhunterx.php.open-redirect` | CWE-601 | WARNING | A Location redirect header is built from $_GET/$_POST/$_REQUEST with no allowlist check. |
| `vulnhunterx.php.mass-assignment` | CWE-915 | ERROR | A Laravel Eloquent model is created/filled/updated from the entire request input ($request->all()). |
| `vulnhunterx.php.ssrf` | CWE-918 | ERROR | Request data flows into an outbound fetch URL (file_get_contents / fopen / curl) with no host/scheme allowlist (taint mode). |

### C / C++ — [semgrep-custom/cpp.yaml](semgrep-custom/cpp.yaml) (4 rules)

| Rule id | CWE | Severity | Message |
|---|---|---|---|
| `vulnhunterx.cpp.weak-hash` | CWE-327/CWE-328 | WARNING | OpenSSL MD5 / SHA1 entry points are collision-vulnerable. |
| `vulnhunterx.cpp.insecure-rng` | CWE-330/CWE-338 | WARNING | rand() / random() / lrand48() / drand48() are not cryptographically secure — flagged inside security-named functions. |
| `vulnhunterx.cpp.unsafe-functions` | CWE-676 | WARNING | Use of an unsafe C string function (strcpy / strcat / gets / sprintf with no length bound). |
| `vulnhunterx.cpp.hardcoded-password` | CWE-259/CWE-798 | ERROR | A string literal assigned to a variable named like a credential (password / passwd / pwd / secret / api_key / token) is a hardcoded secret. |

### C# — [semgrep-custom/csharp.yaml](semgrep-custom/csharp.yaml) (14 rules)

Structural / config / ASP.NET-idiom patterns. Taint-driven CWEs are handled by the built-in `csharp-security-extended` suite and `codeql-custom/csharp/` and are not duplicated here.

| Rule id | CWE | Severity | Message |
|---|---|---|---|
| `vulnhunterx.csharp.weak-cipher` | CWE-327/CWE-328 | ERROR | Broken symmetric cipher (DES / TripleDES / RC2) or ECB mode. |
| `vulnhunterx.csharp.insecure-rng` | CWE-330/CWE-338 | WARNING | `System.Random` used in a security-named method — predictable PRNG. |
| `vulnhunterx.csharp.cert-validation-disabled` | CWE-295 | ERROR | Certificate validation callback accepts all certs / `DangerousAcceptAnyServerCertificateValidator`. |
| `vulnhunterx.csharp.ef-raw-sql` | CWE-89 | ERROR | EF Core `FromSqlRaw`/`ExecuteSqlRaw` built by interpolation/concatenation. |
| `vulnhunterx.csharp.dangerous-deserializer` | CWE-502 | ERROR | `BinaryFormatter`/`SoapFormatter`/`NetDataContractSerializer`/`LosFormatter` — RCE-prone. |
| `vulnhunterx.csharp.insecure-cookie` | CWE-1004/CWE-614 | WARNING | Cookie created with `HttpOnly = false` or `Secure = false`. |
| `vulnhunterx.csharp.xxe-prone-xml` | CWE-611 | ERROR | XML parser set to `DtdProcessing.Parse` or given an `XmlUrlResolver` — XXE. |
| `vulnhunterx.csharp.hardcoded-connection-secret` | CWE-798/CWE-259 | ERROR | DB connection string with an embedded password literal. |
| `vulnhunterx.csharp.cors-permissive` | CWE-942 | ERROR | CORS policy allowing any origin together with credentials. |
| `vulnhunterx.csharp.developer-exception-page` | CWE-209 | WARNING | `UseDeveloperExceptionPage()` not gated behind `env.IsDevelopment()`. |
| `vulnhunterx.csharp.antiforgery-disabled` | CWE-352 | WARNING | `[IgnoreAntiforgeryToken]` / antiforgery validation disabled. |
| `vulnhunterx.csharp.open-redirect` | CWE-601 | WARNING | Redirect target taken from request input without an allow-list / `IsLocalUrl` check. |
| `vulnhunterx.csharp.ldap-injection` | CWE-90 | WARNING | `DirectorySearcher.Filter` / `DirectoryEntry` path built by interpolation. |
| `vulnhunterx.csharp.weak-password-hash` | CWE-916 | WARNING | Fast hash (SHA-256/512/MD5/SHA-1) over a password-named value instead of a KDF. |
<!-- sg_tables_end -->

## 5. Built-in Coverage

Upstream rules are pulled at runtime; their content is maintained by GitHub CodeQL and the Semgrep registry. The profiles reference them by name only.

**CodeQL suites**
- `security-extended` — ~200 queries, default for `standard`/`extended`.
- `security-and-quality` — ~400 queries, includes code-quality alongside security; used by `maximum`/`extended-registry`/`full`.

**Semgrep universal packs (8)** — `auto`, `p/security-audit`, `p/secrets`, `p/owasp-top-ten`, `p/cwe-top-25`, `p/gitleaks`, `p/jwt`, `p/insecure-transport`.

**Semgrep language-specific packs (10)** — `p/python`, `p/django`, `p/flask`, `p/javascript`, `p/nodejs`, `p/typescript`, `p/eslint-plugin-security`, `p/java`, `p/php`, `p/gosec`. C/C++ have no working language-specific registry packs and rely on the universal set.

Approximate rule counts per pack are inline-commented in [rule_categories.yaml](rule_categories.yaml).

## 6. Security Categories & CWE Coverage

Findings can be filtered at verify time with `--category <name>` (repeatable). The 12 categories from [rule_categories.yaml](rule_categories.yaml) — `categories:` — are:

| Category | Description | CWE count |
|---|---|---|
| `injection` | SQL, command, code, LDAP, XPath, template, header injection | 10 |
| `xss` | Cross-site scripting and HTML injection | 3 |
| `auth` | Authentication, authorization, session, CSRF | 6 |
| `crypto` | Weak cryptography, insecure TLS, insufficient key size | 4 |
| `secrets` | Hardcoded credentials, API keys, tokens | 3 |
| `memory-safety` | Buffer overflow, UAF, null-deref, leak (C/C++) | 14 |
| `data-exposure` | Information disclosure, cleartext storage/transmission, log injection | 6 |
| `deserialization` | Unsafe deserialization | 1 |
| `xxe` | XML external entity injection | 1 |
| `ssrf` | Server-side request forgery | 1 |
| `file-security` | Path traversal, file upload, zip slip | 3 |
| `dos` | Resource exhaustion, ReDoS, algorithmic complexity | 4 |

The `cwe_question_map` section in the same file routes **124 CWE IDs** to guided-question suffixes (e.g. `CWE-89 → sql-injection`). Findings missing a CWE tag are always included (conservative).

## 7. Guided-Question Routing

The verification engine (`src/vuln_hunter_x/questions/loader.py`) matches each SARIF `ruleId` to a question template using three tiers, in order:

1. **Exact** — full `<lang>/<name>` match. Custom CodeQL queries (e.g. `cpp/use-after-move`) hit this tier directly.
2. **Normalized / prefix / lang-prefix** — handles registry rules with vendor prefixes.
3. **CWE map fallback** — uses `cwe_question_map[<CWE>]` to derive the question key. This is the route most Semgrep registry findings take.

If all three fail, the generic [`default_questions.yaml`](prompts/default_questions.yaml) is used.

### Per-language question files

| Language | File | Question sets |
|---|---|---|
| C/C++ | [cpp_questions.yaml](prompts/cpp_questions.yaml) | 61 |
| Python | [python_questions.yaml](prompts/python_questions.yaml) | 65 |
| JavaScript/TS | [javascript_questions.yaml](prompts/javascript_questions.yaml) | 54 |
| Go | [go_questions.yaml](prompts/go_questions.yaml) | 53 |
| Java | [java_questions.yaml](prompts/java_questions.yaml) | 57 |
| PHP | [php_questions.yaml](prompts/php_questions.yaml) | 52 |
| C# | [cs_questions.yaml](prompts/cs_questions.yaml) | 45 |
| Fallback | [default_questions.yaml](prompts/default_questions.yaml) | 1 |

## 8. Adding New Rules

**Custom CodeQL query** — drop `<name>.ql` into `config/codeql-custom/<lang>/src/`. Set `@id <lang>/<name>` so it matches a guided-question key (or add the key to `prompts/<lang>_questions.yaml`). Active under `--profile full`.

**Custom Semgrep rule** — append to `config/semgrep-custom/<lang>.yaml`. Always set `metadata.cwe: ["CWE-NNN"]` so CWE-map routing works. Active under `--profile full`.

**New CWE category mapping** — add to `cwe_question_map:` in [rule_categories.yaml](rule_categories.yaml), and add the corresponding key to the per-language `*_questions.yaml`.

Verify wiring:

```bash
python scripts/audit_rule_coverage.py --fail-on-gaps
```

## 9. Audit Tooling

`scripts/audit_rule_coverage.py` produces coverage reports under `output/audit/`:

- **`coverage_matrix.csv`** — rule × CWE × wire-up status across every guided question.
- **`gap_summary.md`** — Priority A/B/C breakdown of unwired rules and missing questions.
- **`missing_cwe_map_entries.yaml`** — drop-in patch fragment for `cwe_question_map` when gaps exist.

Flags:

- `--probe-tools` — additionally invoke installed CodeQL/Semgrep binaries to confirm registry packs still resolve and built-in rules still emit expected CWE tags.
- `--fail-on-gaps` — exit non-zero when gaps are found; suitable for CI gating.
