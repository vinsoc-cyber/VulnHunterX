# Changelog

All notable changes to VulnHunterX are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **C# / .NET language support** to full parity with the other languages:
  CLI wiring, tree-sitter context extraction (`.cs`), CodeQL
  `csharp-security-extended` analysis, a custom CodeQL pack
  (`config/codeql-custom/csharp/`, 5 gap-filling queries), custom Semgrep
  rules (`config/semgrep-custom/csharp.yaml`, 14 rules), a guided-question
  bank (`config/prompts/cs_questions.yaml`, 45 sets), and the `p/csharp`
  registry pack in the standard/extended-registry/full profiles. C#
  databases use CodeQL's **buildless** extractor (`--build-mode none`) by
  default, so no `dotnet build` is required; pass `--build-command` for full
  fidelity.
- **`scan` command** — one-shot pipeline (`prepare → analyze → verify →
  report`) that composes the existing per-stage commands. Continues with
  source-only analysis when the CodeQL database build fails but the chosen
  analyzer (`semgrep`/`opengrep`/`both`/`all`) can run without a database.
- **`interactive` (alias `wizard`) command** — a guided wizard that runs an
  environment prerequisite check up front (exits if no analyzer is
  installed), validates each answer as it is entered (path existence,
  analyzer availability, a live LLM-provider connectivity test), and then
  dispatches a full `scan`.
- Optional shell completion via `argcomplete`, installable with the new
  `[cli]` extra (`pip install "vuln-hunter-x[cli]"`).

### Fixed
- Corrected drifted rule/question counts in the README and `config/RULES.md`,
  and added the previously-undocumented Semgrep rules (`js/dom-xss-sink`,
  `go/hardcoded-symmetric-key`, `go/permissive-cors`) to the inventory.

## [1.0.0] - 2026-06-12

### Added
- DeepSeek as an LLM provider, with model/tier support wired into the
  CLI and benchmark runner.
- Custom-rule expansion across all supported languages, layered onto
  the built-in suites: CWE Top 25 gaps (file upload, privilege
  management, resource exhaustion), OWASP 2025 categories (security
  misconfiguration, supply-chain, exceptional conditions), new CWE
  classes (LDAP injection, XPath injection, SSTI), and cross-language
  symmetry for NoSQL injection, ReDoS, XXE, open redirect,
  mass-assignment, and SSRF. Golden fixtures back the custom rules.
- ContextProvider can now fetch full function bodies and callee
  implementations on demand, deepening multi-turn verification context.
- Fuzzing corpus support and crash triage: ASan/UBSan parsing,
  crash deduplication, and severity classification.
- Dataset / approach registry pattern in the benchmark harness. Adding
  a new dataset or benchmark approach is now a single-file change via
  `@register_adapter` / `@register_approach`.
- `--dataset-option NAME=VALUE` and `--approach-option NAME=VALUE` CLI
  flags. Per-dataset and per-approach knobs are validated against each
  registered class's `option_schema`; unknown keys warn instead of
  silently being dropped.
- `benchmarks/datasets.yaml` — single install manifest read by both
  `run_benchmark.py` and `setup_datasets.py`.
- Multi-key Ollama Cloud support: `OLLAMA_API_KEYS=k1,k2,k3` with
  round-robin rotation and per-key cooldown on rate-limit errors
  (`src/vuln_hunter_x/llm/key_pool.py`, 21 new tests).
- Ollama Cloud (ollama.com) as an LLM provider, auto-detected by
  endpoint or `:cloud` model tag.
- `SnippetContextProvider` — production-grade fallback ContextProvider
  used when CodeQL CSVs are unavailable; restores multi-turn context
  expansion in benchmark and CSV-less production runs.
- `SyntheticContextProvider` answers `caller` / `struct` / `free_sites`
  queries from the snippet itself, with `<unavailable: ...>` sentinel
  for genuinely out-of-scope requests.
- Iteration × confidence calibration buckets and force-decision
  telemetry in the benchmark report.
- Negative-sample rebalancing for DiverseVul (`negative_fraction`
  option), stratified per CWE.
- Second-opinion pass: single-turn high-confidence FP verdicts and
  force-decision-defaulted FPs are re-prompted with an audit checklist.
- `RealVulnAdapter` and `OwaspBenchmarkAdapter` (Java + Python) for
  real-CVE benchmarking beyond DiverseVul / Juliet.
- Custom CodeQL and Semgrep rules for C++ / Go / JS / PHP / Python,
  layered onto the built-in suites by the `full` profile.
- Statistical metrics and tests for benchmark evaluation (bootstrap
  CIs, McNemar's test, paired comparisons).
- Per-language guided questions for Go, with path-enumeration framing
  for missing-/incorrect-authorization rules across all six languages.
- Parallel verification (`--jobs N`) with configurable per-job and
  global LLM-call concurrency.

### Changed
- Go verification hardened with new security rules and improved context
  extraction.
- JavaScript security-rule handling and context verification refined.
- Vulnerability-analysis prompts and logic refined for correctness rules
  to reduce over-confirmation.
- `litellm.drop_params` is set so gpt-5 / o-series models run correctly
  (they reject non-default `temperature`).
- Verification engine `min_iterations` gate now fires regardless of
  whether a `context_provider` is configured — fixes a silent disable
  that produced premature TP/FP verdicts on memory-safety CWEs.
- Confidence downgrade heuristic is symmetric across TP and FP: a
  verdict that uses pattern-matching language without code citations
  is demoted to Low confidence whichever direction it points.
- JSON-parse fallback returns `Needs More Data` with `parse_failed=True`
  instead of forcing `confidence=Low` and a synthetic FP verdict.
- Force-decision turn's TP-signal vocabulary covers access-control
  CWE language ("no authorization", "no capability check",
  "unprotected", "missing access control", …).
- Default `max_tokens` for verification LLM calls raised from 1500 to
  4096 so 6-question rules with line-cited answers no longer truncate.
- System prompt: `False Positive` requires citing a specific defense
  on every reachable path; absence of evidence is not evidence of
  safety. `Needs More Data` is the preferred verdict over guessing FP.
- DiverseVul CWE→rule selection uses the shared
  `primary_rule_for_langs` helper; the ad-hoc cpp/c prefix check is
  gone.
- LLM client supports anthropic-prefixed model routing and retry with
  exponential backoff via LiteLLM's `retry_strategy=exponential_backoff_retry`.
- `_load_dataset` / `_build_approach` in the benchmark runner are now
  thin registry lookups; `--dataset all` and family aliases (e.g.
  `--dataset owasp`) are discovered from the registry, not hard-coded.

### Fixed
- `rule_categories.yaml` now loads correctly so category filtering
  works as configured.
- Filename collision in verdict-file generation that could cause
  results to overwrite one another.
- CWE sampling and guided-question retrieval in benchmarks.
- Tree-sitter `end_line` extraction for multi-line function signatures
  in Python `functions.ql`.
- Path traversal guard in `ContextProvider` when reading source files
  outside the configured repos directory.
- SARIF parser normalizes `tool.driver.name` to canonical labels so
  CodeQL/Semgrep/OpenGrep findings interoperate.

## [0.1.0] — 2026-04-12

Initial release.

### Added
- 8-stage SAST + LLM-verification pipeline (clone, analyze,
  extract-context, verify, build-sanitized, extract-fuzz-context,
  generate-fuzz-drivers, fuzz-run).
- Multi-language support: C, C++, Python, JavaScript, PHP, Java, Go.
- CodeQL, Semgrep, and OpenGrep SAST backends.
- Per-language guided question banks for LLM verification.
- Rule profiles (`standard`, `extended`, `maximum`, `extended-registry`,
  `full`) with CWE-keyed security categories.
- Dynamic fuzzing harness generation: libFuzzer (.cc), Atheris (.py),
  Jazzer (.java), Jazzer.js (.js), php-fuzzer (.php).
- LLM-assisted fuzz-harness fix loop.
- Initial benchmark harness with SecLLMHolmes, Juliet, DiverseVul.
- Markdown reporting with per-CWE breakdowns, confidence calibration,
  and cost/latency tracking.
