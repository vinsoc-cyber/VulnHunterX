# FAQ

Short answers to common questions. Deeper coverage is linked per item.

### What does VulnHunterX actually do?
It runs SAST engines (CodeQL, Semgrep, OpenGrep) to find candidate vulnerabilities, then makes an
LLM triage each one with rule-specific guided questions and multi-turn context expansion, emitting
a True Positive / False Positive / Needs More Data verdict with a calibrated confidence score. The
goal is to suppress SAST false positives without discarding real bugs. See
[METHODOLOGY.md](METHODOLOGY.md).

### Do I need an expensive LLM?
No — and that's a headline result. A $0 local/pass-through model with the guided-question pipeline
matches or beats GPT-4.1-mini and GPT-5 on F1 across the benchmarks. See
[Results](../README.md#results) and [LLM_PROVIDERS.md](LLM_PROVIDERS.md).

### Why did my findings/verdicts change between runs?
Three usual causes: (1) a different `--profile` or tool changed the SAST findings; (2) a different
model or `temperature` changed the LLM's reasoning; (3) `temperature > 0` introduces run-to-run
variance. For reproducible triage, pin the model and keep `temperature: 0.2` (or lower) in
`config/confirm_findings.yaml`.

### How do I see *why* the LLM reached a verdict?
Read the verdict JSON's `answers` and `data_flow` fields
([INTERPRETING_RESULTS.md](INTERPRETING_RESULTS.md)), or capture the full conversation:

```bash
vuln-hunter-x verify --repo myrepo --log-file output/llm_conversations.md
```

### What does "Needs More Data" mean — is it a failure?
No. It means the model couldn't answer a required question from the available context, even after
multi-turn expansion, and declined to guess. That refusal is what keeps precision honest. Provide
richer context (`--backend codeql`, wider scan) or review those findings manually.

### What's the difference between precision and "FP-reduction"?
Precision is how often a "True Positive" call is correct; FP-reduction is what fraction of the raw
SAST false positives the LLM removed. A noisy dataset can show modest precision but huge
FP-reduction. Full metric glossary in [INTERPRETING_RESULTS.md](INTERPRETING_RESULTS.md).

### Which `--profile` should I use?
`standard` for fast everyday scans; `full` for maximum coverage and reliable offline runs (it
loads the in-repo custom rules — registry packs need network access). See
[RULE_PROFILES.md](RULE_PROFILES.md).

### Semgrep/OpenGrep found 0 results — why?
Registry `p/...` packs require semgrep.dev network access and return nothing offline. Use
`--profile full` for the bundled offline rules. See
[TROUBLESHOOTING.md](TROUBLESHOOTING.md#stage-2--analyze-sast--sarif).

### Can I run it without CodeQL?
Stages 1–3 lean on CodeQL, but context extraction has a tree-sitter fallback (`--backend
treesitter`) for repos where the DB won't build, and Semgrep/OpenGrep can run independently. CodeQL
still gives the richest context (especially C/C++ memory-safety), so prefer it when available.

### Does it support my language?
C, C++, Python, JavaScript/TypeScript, Java, Go, and PHP for static analysis + LLM verification.
Fuzz confirmation (stages 5–8) is most mature for C/C++ with templates for Python/Java/JS/PHP. See
[FUZZING.md](FUZZING.md).

### How do I add my own rule?
Drop a CodeQL `.ql` into `config/codeql-custom/<lang>/src/` (with `@id <lang>/<name>`) or a Semgrep
rule into `config/semgrep-custom/<lang>.yaml` (with `metadata.cwe`), then run under `--profile
full`. Verify wiring with `python scripts/audit_rule_coverage.py --fail-on-gaps`. See
[RULE_PROFILES.md](RULE_PROFILES.md) and [config/RULES.md](../config/RULES.md).

### Is it fast enough for inline CI on every commit?
Verification is batch-speed (seconds per finding), not real-time. Use `--limit` + a small model on
PRs and run `--profile full` nightly. See [CI_CD.md](CI_CD.md).

### Can an attacker fool the LLM via crafted code/comments?
It's a real risk (prompt-injection through analyzed source). Mitigations: evidence-binding
(verdicts must cite `file:line`), confidence downgrades for unsupported reasoning, and a
second-opinion re-audit on suspicious high-confidence FPs. Treat verdicts as triage assistance,
not ground truth — especially on untrusted code.
