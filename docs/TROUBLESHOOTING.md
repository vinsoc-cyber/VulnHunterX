# Troubleshooting

Failure modes organized by pipeline stage. For provider-specific issues see
[LLM_PROVIDERS.md](LLM_PROVIDERS.md); for quick answers see [FAQ.md](FAQ.md).

Start with:

```bash
vuln-hunter-x check-env     # verifies CodeQL, Semgrep/OpenGrep, tree-sitter, LLM key
vuln-hunter-x info          # prints the resolved provider/model/paths
```

## Stage 1 — `prepare` (clone, CodeQL DB, context)

| Symptom | Cause / fix |
|---|---|
| `CodeQL CLI not found` | Add CodeQL to `PATH` or set `CODEQL_PATH` in `.env`. |
| `could not resolve module cpp` (or other lang) | Context query pack not installed: `codeql pack install config/queries/tools/<lang>`. |
| `Database is already finalized` | Harmless info message — analysis continues. |
| CodeQL DB build fails for C/C++ | The build command is wrong/missing. Set `build_command` in `repos.yaml` or `--build-command`. As a fallback, use `--backend treesitter` to extract context syntactically without a DB. |
| Context CSVs empty / stale | Re-extract with `prepare --skip-clone --skip-db --force --repo <name>`. |

The `--backend` choice (`auto` / `codeql` / `treesitter`) controls context extraction. `codeql`
gives the richest context (incl. C/C++ `free_sites`, `destructors`, `field_writes`); `treesitter`
is the fallback when no DB could be built. Both emit the same CSV layout, so downstream stages are
identical. See the [README backend table](../README.md#context-extraction-backends---backend).

## Stage 2 — `analyze` (SAST → SARIF)

| Symptom | Cause / fix |
|---|---|
| `Semgrep CLI not found` | `pip install semgrep` or set `SEMGREP_PATH`. |
| **Semgrep/OpenGrep "0 results"** | Registry `p/...` packs need semgrep.dev network access and return nothing offline. The analyzer logs the resolved command (INFO) and warns when rules load but match nothing. For reliable **offline** coverage use `--profile full` (loads in-repo `config/semgrep-custom/<lang>.yaml`). |
| No findings at all | Wrong `--lang`, or the profile's pack doesn't cover the language. Confirm with `--profile full` and check the per-language pack in [RULE_PROFILES.md](RULE_PROFILES.md). |
| Too many findings to verify | Narrow with `--category <cat>` (repeatable) or cap with `verify --limit N`. |

## Stage 3 — `verify` (LLM verification)

| Symptom | Cause / fix |
|---|---|
| `... API key not configured` | Set the matching key in `.env`; check `LLM_PROVIDER`/`LLM_MODEL`. |
| HTTP 429 / rate limit | Lower `verify -j`; for Ollama Cloud add keys to `OLLAMA_API_KEYS`. |
| Many `Needs More Data` verdicts | Context was insufficient. Prefer `--backend codeql` at prepare time, widen the scan, or raise `--max-iterations`. Some NMD is expected and healthy. |
| Truncated / invalid JSON from the model | Raise `max_tokens` in `config/confirm_findings.yaml`; inspect with `--log-file`. |
| Verdicts look like pattern-matching | Expected guard behavior downgrades these to Low confidence; review Low-confidence verdicts manually (see [INTERPRETING_RESULTS.md](INTERPRETING_RESULTS.md)). |
| Want to see the reasoning | `verify --log-file output/llm_conversations.md` persists every prompt/response. |

## Stage 4 — `report`

| Symptom | Cause / fix |
|---|---|
| `report` finds no results | Point `--results-dir` at the right `verification_results/` dir, or pass `--repo`/`--lang` to auto-discover. |
| Want only English (or Vietnamese) | `--lang-report en` / `vi` / `all`. |

## Stages 5–8 — fuzz (C/C++ and other languages)

| Symptom | Cause / fix |
|---|---|
| Sanitizer build fails | Ensure `clang`/`clang++` are installed and the `build_command` succeeds without sanitizers first. |
| Harness won't compile | Use `generate-fuzz-drivers --llm-fix` to run the LLM repair loop (adds missing includes, casts). |
| No crashes found | Expected for true-negative or hard-to-reach targets; increase fuzz time or provide a seed corpus. |

Full fuzzing guide: [FUZZING.md](FUZZING.md).

## Still stuck?

- Re-run with `-v` (verbose) to see resolved commands and LLM I/O.
- Check `benchmark.log` / `output/llm_conversations.md` for the full trail.
- Confirm rule→question wiring with `python scripts/audit_rule_coverage.py`.
