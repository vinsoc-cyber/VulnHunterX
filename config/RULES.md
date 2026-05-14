# SAST Security Scan Rules

This document is a reference inventory of every static-analysis rule set VulnHunterX runs, the profiles that select them, and how their findings reach the LLM verification stage. It is sourced from [rule_categories.yaml](rule_categories.yaml), [codeql-custom/](codeql-custom/), [semgrep-custom/](semgrep-custom/), and [prompts/](prompts/). For the surrounding pipeline architecture, see [CLAUDE.md](../CLAUDE.md).

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

Layered onto CodeQL via the `full` profile (`include_custom_codeql: true`). The `@id` field must take the form `<lang>/<name>` so the verification engine can match findings to guided questions of the same key.

### C/C++ — [codeql-custom/cpp/src/](codeql-custom/cpp/src/)

| `@id` | CWE | Severity (security) | Precision | Description |
|---|---|---|---|---|
| `cpp/alloca-in-loop` | CWE-674 | warning (6.0) | high | `alloca()` inside a loop body — uncontrolled stack growth per iteration. |
| `cpp/dangling-pointer` | CWE-825 | warning (7.5) | medium | Pointer captures address of a local that goes out of scope. |
| `cpp/exception-unsafe` | CWE-755 | warning (6.0) | low | Bare `new`/`malloc`/`fopen` not owned by an RAII type — leaks on throw. |
| `cpp/stack-address-escape` | CWE-562 | error (8.0) | high | `return &local` returns a dangling pointer to a stack variable. |
| `cpp/use-after-move` | CWE-672 | warning (7.5) | medium | Variable read after `std::move` — value is unspecified. |

### Go — [codeql-custom/go/src/](codeql-custom/go/src/)

| `@id` | CWE | Severity (security) | Precision | Description |
|---|---|---|---|---|
| `go/cgo-vulnerability` | CWE-242 | warning (7.0) | low | User-controlled data passed across cgo boundary bypasses Go memory/string safety. |

### Java, JavaScript, Python
The `codeql-custom/{java,javascript,python}/src/` trees ship `suite.qls` stubs but no `.ql` files yet — these languages rely on the upstream CodeQL suite plus custom Semgrep rules.

## 4. Custom Semgrep / OpenGrep Rules

Layered onto Semgrep/OpenGrep via the `full` profile through `custom_semgrep_path: "config/semgrep-custom/${LANG}.yaml"`. Each rule sets `metadata.cwe` so findings without exact-id matches still route to guided questions via [`cwe_question_map`](rule_categories.yaml).

### Python — [semgrep-custom/python.yaml](semgrep-custom/python.yaml)

| Rule id | CWE | Severity | Message |
|---|---|---|---|
| `vulnhunterx.python.flask-debug` | CWE-489 | ERROR | `Flask app.run(debug=True)` enables the Werkzeug interactive debugger — shell-level RCE on exceptions. |
| `vulnhunterx.python.unsafe-yaml` | CWE-502 | ERROR | `yaml.load()` without `SafeLoader` deserializes arbitrary Python objects (eval-equivalent). |
| `vulnhunterx.python.insecure-tls-context` | CWE-295 | ERROR | `SSLContext` with `check_hostname=False` or `verify_mode=CERT_NONE` permits MITM. |
| `vulnhunterx.python.regex-injection` | CWE-1333 | WARNING | User-controlled regex pattern enables catastrophic backtracking (ReDoS). |

### JavaScript / TypeScript — [semgrep-custom/javascript.yaml](semgrep-custom/javascript.yaml)

| Rule id | CWE | Severity | Message |
|---|---|---|---|
| `vulnhunterx.js.prototype-pollution` | CWE-1321 | ERROR | Bracket-indexed property write with user-controlled key pollutes `Object.prototype`. |
| `vulnhunterx.js.electron-node-integration` | CWE-1188 | ERROR | Electron `BrowserWindow` with `nodeIntegration: true` exposes Node APIs to renderer. |
| `vulnhunterx.js.html-injection` | CWE-79 | WARNING | Tainted value assigned to `innerHTML`/`outerHTML`/`insertAdjacentHTML`. |

### Go — [semgrep-custom/go.yaml](semgrep-custom/go.yaml)

| Rule id | CWE | Severity | Message |
|---|---|---|---|
| `vulnhunterx.go.goroutine-leak` | CWE-405 | WARNING | Goroutine writes to unbuffered channel without a bounded receiver — blocks forever. |
| `vulnhunterx.go.panic-in-handler` | CWE-248 | WARNING | `net/http` handler path can panic without a `recover()` wrapper. |
| `vulnhunterx.go.unsafe-pointer` | CWE-704 | WARNING | `unsafe.Pointer` cast between unrelated types bypasses type safety. |

### PHP — [semgrep-custom/php.yaml](semgrep-custom/php.yaml)

| Rule id | CWE | Severity | Message |
|---|---|---|---|
| `vulnhunterx.php.type-juggling` | CWE-1025 | WARNING | Loose `==`/`!=` on user input bypassed via PHP type juggling (e.g. `"0e1" == "0e2"`). |
| `vulnhunterx.php.extract-injection` | CWE-1062 | ERROR | `extract()` on user-controlled array overwrites arbitrary local variables. |
| `vulnhunterx.php.variable-variables` | CWE-621 | WARNING | Variable-variable assignment (`$$name = ...`) near user input overwrites scope. |
| `vulnhunterx.php.file-inclusion` | CWE-98 | ERROR | `include`/`require` with user-controlled path enables LFI/RFI. |

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

The `cwe_question_map` section in the same file routes **103 CWE IDs** to guided-question suffixes (e.g. `CWE-89 → sql-injection`). Findings missing a CWE tag are always included (conservative).

## 7. Guided-Question Routing

The verification engine (`src/vuln_hunter_x/questions/loader.py`) matches each SARIF `ruleId` to a question template using three tiers, in order:

1. **Exact** — full `<lang>/<name>` match. Custom CodeQL queries (e.g. `cpp/use-after-move`) hit this tier directly.
2. **Normalized / prefix / lang-prefix** — handles registry rules with vendor prefixes.
3. **CWE map fallback** — uses `cwe_question_map[<CWE>]` to derive the question key. This is the route most Semgrep registry findings take.

If all three fail, the generic [`default_questions.yaml`](prompts/default_questions.yaml) is used.

### Per-language question files

| Language | File | Question sets |
|---|---|---|
| C/C++ | [cpp_questions.yaml](prompts/cpp_questions.yaml) | 59 |
| Python | [python_questions.yaml](prompts/python_questions.yaml) | 56 |
| JavaScript/TS | [javascript_questions.yaml](prompts/javascript_questions.yaml) | 51 |
| Go | [go_questions.yaml](prompts/go_questions.yaml) | 50 |
| Java | [java_questions.yaml](prompts/java_questions.yaml) | 50 |
| PHP | [php_questions.yaml](prompts/php_questions.yaml) | 50 |
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
