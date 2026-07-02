# VulnHunterX — Refactor, Triage Accuracy, FN Discovery & Web Dashboard

## Context

VulnHunterX reduces SAST false positives (CodeQL/Semgrep/OpenGrep) via LLM triage with guided questions. Exploration (excluding fuzz stages) found a solid pipeline with real weaknesses:

- **Monoliths:** `verification/engine.py` (1,532 lines) and `llm/client.py` (1,342 lines) mix orchestration, calibration, reconciliation, transport, parsing; `cmd_analyze` in `cli/commands.py` is a ~100-line god function.
- **Triage accuracy left on the table:** self-consistency voting exists but defaults to 1 sample (benchmarks in code comments show 95.8% vs 57.1% accuracy at 2-iter vs 1-iter on taint CWEs); force-decision uses brittle keyword matching; missing context CSVs silently degrade (documented 73% TP-loss); truncated LLM JSON becomes NMD with no flag; single model, no ensemble.
- **False-negative surface:** C has **0** custom CodeQL queries and **no** `semgrep-custom/c.yaml` (C++ has only 4 custom Semgrep rules) despite thorough C/C++ memory-safety guided questions; no mechanism to hunt variants of confirmed TPs.
- **UX:** plain `print()` CLI + Markdown/JSON output only; no way to browse, filter, or override verdicts.

**User decisions:** UI = local web dashboard (FastAPI + HTMX, offline). FN focus = C/C++ custom rules + LLM variant analysis. Cost = accuracy at any cost (voting on all findings + second-model ensemble).

**Pre-verified grounding facts:**
- `Config.merge_with_args()` ([core/config.py:285-288](src/vuln_hunter_x/core/config.py#L285-L288)) rebuilds `VerificationConfig` with only `max_iterations`/`force_decision` — **drops `self_consistency_*` and `jobs`** (and `LLMConfig` rebuild drops `num_retries`). Real bug; must be fixed first or voting-by-default won't survive config merging.
- C and C++ share one CodeQL pack: `commands.py` maps `c → cpp`; new queries go in `config/codeql-custom/cpp/src/` with `@id cpp/...`. `questions/loader.py` maps `c → cpp` prefix, so C reuses cpp guided questions.
- `full` profile resolves `config/semgrep-custom/${LANG}.yaml`, so `--lang c` needs a new `c.yaml` (existing `cpp.yaml` declares `[c, cpp]` but is only loaded for `LANG=cpp`).
- `tests/test_custom_semgrep_rules.py` `_LANG_TO_RULES_FILE` = {php, javascript, go, python} — c (and cpp) not fixture-gated today.

---

## Phase 0 — Config merge bug fix (S) — do first

- `core/config.py`: rewrite `merge_with_args` to use `dataclasses.replace` per sub-config so no field is dropped (fixes `self_consistency_samples`, `jobs`, `num_retries`).
- New `tests/test_config_merge.py`: round-trip every `VerificationConfig`/`LLMConfig` field through `merge_with_args`.
- Add characterization test for current `_aggregate_votes` NMD behavior (makes the WS2 fix a visible diff).

## Workstream 1 — Refactoring (incremental; re-export shims keep all 44 test files green until final cleanup)

### 1A. Split `verification/engine.py` (~1,532 → ~450 lines) (M)
New modules in `verification/`:
- **`reconciler.py`** — module functions; entry `reconcile_conflicting_verdicts()`; moves `_reconcile_conflicting_verdicts`, `_same_issue`, path helpers, `_MAX_DISTINCT_RULES_FOR_CROSS`. Pinned by `tests/test_triage_reconciliation.py`.
- **`calibration.py`** — `CalibrationPipeline` = ordered list of `Callable[[Verdict], Verdict]`; moves the 4 downgrade post-processors + their regexes/markers, preserving current order. Pinned by `tests/test_calibration_fixes.py` (763 lines).
- **`second_opinion.py`** — `decide_challenge(...) -> ChallengeDecision | None` for arms A–D; also moves `_SECOND_OPINION_PROMPT`/`_TP_CHALLENGE_PROMPT` out of `llm/client.py` (fixes engine reaching into client internals).
- **`result_store.py`** — `ResultStore(output_dir).save(result)`; moves `save_results`, `_verdict_filename`, `_is_test_path`/`_is_nonproduction_path` classifiers (also used by `cli/commands.py`).
- **`prefetch.py`** — `build_prefetched_context(...)`; moves `_build_prefetch_requests`, `_extract_sink_callees`, `_extract_source_types`, NOTE-injection block.

### 1B. Split `llm/client.py` (~1,342 → 4 modules + thin facade) (M)
- **`transport.py`** — provider routing, `_completion`, key-pool rotation; exposes `complete(messages) -> CompletionResult` dataclass (kills 7-tuple threading and 3 duplicated usage-accounting blocks). Must call `litellm.completion(...)` as module attribute (tests monkeypatch it). **Fix real bug:** `request_second_opinion` calls `litellm.completion` directly, bypassing the key pool — route through `_completion`.
- **`parsing.py`** — `parse_response`, confidence normalization maps (pure functions).
- **`conversation.py`** — multi-turn `analyze`, `request_second_opinion`, `_force_decision_turn`.
- **`voting.py`** — `analyze_with_voting`, `_aggregate_votes`.
- `client.py` keeps `LLMClient` facade with identical public API (many tests construct it directly).

### 1C. `cmd_analyze` extraction (S)
In `cli/commands.py`: extract `_resolve_local_path_target`, `_resolve_rule_profile`, `_dispatch_analyzer` (dict of tool → runner lists replaces `both`/`all` duplication). `cmd_analyze` becomes ~15 lines.

### 1D. Unify context providers (S)
New `context/base.py` with `AdditionalContextSource` Protocol (`get_additional_context`, `has_context_for_repo`, `clear_cache`). Both existing providers already conform; replace `isinstance(..., ContextProvider)` check in engine and fix the typing lie in `analyze()`.

## Workstream 2 — Triage accuracy

New `Verdict` fields (all backward-compatible defaults in `to_dict`/`from_dict`, `core/types.py`): `votes: []`, `ensemble: {}`, `needs_human_review: false`, `human_review_reason: ""`, `context_available: true`.

### WS2-1. Voting by default + quorum fix + early stop (M)
- Default `self_consistency_samples: 3` (constant in `core/constants.py`; requires Phase 0).
- **Fix NMD-weight-0 vote-flip** in `_aggregate_votes`: partition decided (TP/FP) vs abstentions (NMD/Error); if decided < ceil(n/2) → verdict NMD + `needs_human_review` (`voting_quorum_not_met`); winner among decided by summed confidence as today; any abstention caps confidence label at Medium.
- **Early stop:** after 2 identical High-confidence non-forced samples, skip the rest (~33% token savings on easy findings).
- Populate `votes[]` per sample; rewrite NMD cases in `tests/test_self_consistency_voting.py`.

### WS2-2. Second-model ensemble (L)
- `LLMConfig`: `ensemble_provider/ensemble_model/ensemble_max_tokens` (+ env `ENSEMBLE_LLM_PROVIDER/MODEL`); active iff `ensemble_model` set; ship example in `config/confirm_findings.yaml`.
- New `verification/ensemble.py` — `EnsembleAdjudicator.review(...)`: single-shot call to the secondary model with the finding, initial prompt, and primary transcript.
- **Triggers:** final confidence Low/Medium; voting disagreement or quorum-NMD; force-decision sentinel; context-unavailable FP.
- **Resolution policy:** agree → keep (promote Medium→High if secondary agrees at High). Disagree on dangerous CWEs (access-control + taint sets from `questions/loader.py` + memory-safety 119/125/416/476/787) → **TP wins**, confidence Low, human-review flag. Disagree on C/C++ pattern-class correctness CWEs → **NMD** + human review (avoids inflating FPs on the over-confirmation class). Populate `ensemble{}`; render in markdown report + human-review queue.
- New `tests/test_ensemble_adjudicator.py` (mock both clients; trigger × agreement × CWE-class matrix).

### WS2-3. Semantic adjudication replaces keyword force-decision (M)
- New `llm/adjudication.py`: dedicated adjudication turn over the transcript (strict JSON, TP/FP only, must cite file:line evidence).
- New flow: force-prompt → still NMD → **adjudication call** → keyword heuristic only as last-resort fallback (tagged `[keyword-fallback]` + `needs_human_review`). Keep `"[Forced decision:"` sentinel byte-identical for fallback verdicts (tests + arm B match on it); add `"[Adjudicated:"` sentinel and teach arm B to match both.

### WS2-4. Context resilience (M)
- `context/provider.py`: `_CSV_SCHEMAS` required-column validation in `_load_csv`; warn with missing columns instead of silent `[]`; new `context_health(repo, lang) -> ContextHealth`.
- `cmd_verify`: pre-flight context-health warning block + `--strict-context` abort flag.
- When falling back to `SnippetContextProvider`, inject explicit NOTE to the LLM: cross-file context unavailable — do NOT conclude FP from absent evidence; return `"[Context unavailable: ...]"` for unfulfillable requests.
- **Never force-decide FP when `context_available=False`** → convert to NMD + `needs_human_review` (`fp_without_context`); TP still allowed (snippet evidence stands alone).

### WS2-5. Truncation handling (S)
On `truncated` parse: retry once with `max_tokens*2` (cap 16384); then one continuation turn ("re-emit ONLY the final JSON"); still failing → NMD + `needs_human_review` (`truncated_response`). Implement once as `transport.complete_with_truncation_retry` (shared by analyze/force-decision/second-opinion).

### WS2-6. min_iterations ungating + wrong-language CWE fallback (S)
- `questions/loader.py`: taint-CWE min-iterations override applies to **all** languages (drop `_FRAMEWORK_LANGS` gate — cost concern void under new budget).
- `_match_by_cwe`: only take any-language suffix fallback when language is unknown; otherwise fall through to `default` questions (CWE min-iter override still applies afterwards). Update `tests/test_cwe_question_matching.py`.

### WS2-7. Structured verdict output (M)
- New `llm/schema.py` with `VERDICT_RESPONSE_SCHEMA`; `transport` passes `response_format` json_schema where supported (`litellm.get_supported_openai_params`), degrades to json_object → nothing; retry once without on rejection. `_parse_response` becomes the safety net; shrinks the WS2-3 fallback surface.

## Workstream 3 — False-negative discovery

### 3A. C/C++ custom rules (M)
**CodeQL** (add to `config/codeql-custom/cpp/src/`, `@id cpp/...`, header style per existing `use-after-move.ql`; compile-gated by `tests/test_custom_codeql_queries.py`):
1. `malloc-use-after-free.ql` (CWE-416), 2. `double-free.ql` (CWE-415), 3. `unchecked-malloc-deref.ql` (CWE-476), 4. `alloc-size-overflow.ql` (CWE-190/789), 5. `unchecked-return-alloc-io.ql` (CWE-252); optional `memcpy-size-mismatch.ql` (CWE-120).

**Semgrep** — new `config/semgrep-custom/c.yaml` (`languages: [c]`, ids `vulnhunterx.c.<suffix>`, `metadata.cwe` routes via `cwe_question_map`):
6. `unsafe-string-fn` (CWE-676/120), 7. `format-string-taint` (CWE-134), 8. `fixed-tmp-path` (CWE-377), 9. `system-nonconst` (CWE-78), 10. `memcpy-strlen` (CWE-120); duplicate `unsafe-functions` + `insecure-rng` from `cpp.yaml` so C repos aren't blind.

**Wiring/tests:** fixture pairs `tests/fixtures/security-rules/c/<suffix>/{vuln.c,clean.c}`; add `"c": "c.yaml"` to `_LANG_TO_RULES_FILE` (backfilling `"cpp"` is a separate decision — large fixture burden). No `cwe_question_map` edits needed (chosen CWEs already mapped). `full` profile picks both up automatically.

### 3B. Variant-analysis stage (L)
New package `src/vuln_hunter_x/variants/` + CLI `hunt-variants`:
- **`patterns.py`** — `PatternAbstract{source_type, sink_api, missing_guard, cwe_ids, parent_rule_id, lang}` from high-confidence TP verdicts.
- **`candidate_search.py`** — grep `functions.csv` source_code / repo for the sink API → real `{file, line, snippet}` candidate sites.
- **`prompts.py` + `hunter.py`** — LLM **selects among grep-provided numbered sites only** (anti-hallucination: reject any file:line not in the provided set; re-read file and require sink token in window before accepting; dedup against existing findings via engine's `_norm_path` helpers).
- Survivors → synthetic `Finding(tool="llm-variant", tags=["llm-variant", "variant-of:<parent_rule_id>"], rule_id=parent's)` → existing `VerificationEngine.verify_findings` → persisted like `cmd_verify` into `verification_results/`.
- **Config** `variants:` block: `enabled: false`, `max_variants_per_tp: 5`, `max_candidate_sites: 40`, `max_total_variants: 50`, `min_parent_confidence: high`, optional cheaper `model` for shortlisting.
- Add thin `LLMClient.complete(messages)` single-shot wrapper (shortlisting isn't multi-turn).
- `cmd_scan`: optional stage after verify, gated by `--hunt-variants` / `variants.enabled`.
- Tests: mocked-LLM unit tests for abstraction, search, dedup, hallucination rejection; integration with monkeypatched `complete`.

## Workstream 4 — Local web dashboard (M–L)

New package `src/vuln_hunter_x/dashboard/` (FastAPI + Jinja2 + vendored htmx — no CDN, no build toolchain, localhost only):
- **Deps:** `pyproject.toml` optional group `dashboard = [fastapi, uvicorn, jinja2, python-multipart]`; `cmd_dashboard` imports lazily with install hint on `ImportError`.
- **Files:** `app.py` (`create_app(output_dir, repos_dir)`), `loaders.py` (`list_repos` globbing `output/*/*/verification_results`, `load_verdicts` reusing `Verdict.from_dict` / `MarkdownReportGenerator.from_verdict_files`, `write_override`), `templates/` (`index/repo/finding/_table/_charts`), `static/` (vendored `htmx.min.js`, css).
- **Routes:** `GET /` repo cards with summary counts; `GET /repo/{lang}/{name}` findings table with server-side filters (verdict/CWE/confidence/tool) via htmx partial swap; `GET /finding/{lang}/{name}/{id}` detail — snippet via `reporting.markdown._extract_code_snippet` from `repos_dir`, dataflow, reasoning, answers, cost, override form (`id` = verdict filename stem); `POST .../override`.
- **Override audit trail:** write `human_review{verdict, note, timestamp, reviewer, original_verdict}` + append-only `human_review_history[]` into the result JSON without mutating original fields; atomic write (temp + `os.replace`).
- **Charts:** server-rendered inline SVG (verdict distribution, CWE top-N, confidence histogram) — offline.
- **CLI:** `dashboard` subcommand (`--host 127.0.0.1 --port 8000 --output-dir --repos-dir`).
- Tests: FastAPI `TestClient` behind `pytest.importorskip("fastapi")` — index list, filters, detail snippet, override preserves original + grows history, invalid form leaves JSON unchanged.

---

## Rollout order

| Step | Item | Effort |
|---|---|---|
| 1 | Phase 0 config-merge fix + characterization tests | S |
| 2 | 1B-partial: `llm/parsing.py` + `transport.py` (+ key-pool bypass fix) | M |
| 3 | 1A engine split (parallel with 2) | M |
| 4 | 1B-rest: conversation/voting split, client facade | M |
| 5 | 1C `cmd_analyze` helpers + 1D context Protocol | S |
| 6 | WS2-6 min_iterations + CWE fallback (independent, anytime) | S |
| 7 | WS2-5 truncation retry + `needs_human_review` field | S |
| 8 | WS2-7 structured output | M |
| 9 | WS2-4 context resilience | M |
| 10 | WS2-1 voting default + quorum + early stop | M |
| 11 | WS2-3 adjudication turn | M |
| 12 | WS2-2 ensemble | L |
| 13 | 3A C/C++ rules (independent — can start anytime) | M |
| 14 | 4 dashboard read-only → charts → override → CLI | M–L |
| 15 | 3B variant analysis (after 10–12 stabilize TP JSON shape; benefits from 13) | L |
| 16 | Shim removal + test-import cleanup | S |

Refactors precede accuracy work because WS2-1/2/3 touch code currently entangled in the monoliths. 3A and 14 are independent and can run in parallel with anything.

## Verification

- Every step: `pytest tests/`, `ruff check src/`, `mypy src/` green (per repo policy).
- Behavior pins: `test_calibration_fixes.py`, `test_self_consistency_voting.py`, `test_triage_reconciliation.py`, `test_verification_engine.py`, `test_llm_client.py`, `test_cwe_question_matching.py` — updated only where behavior intentionally changes (quorum, fallback, min-iter).
- Rules: `pytest tests/test_custom_semgrep_rules.py tests/test_custom_codeql_queries.py` (needs opengrep/codeql binaries); smoke `vuln-hunter-x scan --local-path <c-repo> --lang c --profile full --tool all`.
- Triage regression: rerun the existing benchmark harness (`tests/test_benchmark_*` adapters) on a previously-scanned repo comparing verdict distribution before/after voting+ensemble; expect fewer 1-iter High FPs on taint/access-control CWEs and `needs_human_review` populated instead of silent keyword-forced verdicts.
- Dashboard: `vuln-hunter-x dashboard` against an existing `output/` tree; verify filters, snippet rendering, and that an override round-trips (POST → JSON has `human_review_history`, original verdict intact).
- Variants: dry-run `hunt-variants --dry-run` on a repo with confirmed TPs; confirm candidates all map to real file:lines and dedup against existing SARIF findings.
