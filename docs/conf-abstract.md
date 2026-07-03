# From Noise to 0-Day: LLM-Guided SAST Triage That Cut False Positives 91% and Found Real Bugs in Libraries

<!-- Alternative titles:
  - "Your Scanner Cried Wolf 600 Times: Teaching an LLM to Find the Bugs Hiding in SAST Noise"
  - "1,400 Questions Later: Multi-Turn LLM Triage, an 87% Precision Jump, and 5 Confirmed Vulnerabilities"
  - "The 62% You Ignore: LLM Triage That Turned a Wall of SAST Alerts into 5 Real Bugs"
  - "From 38% to 87% Precision: What Guided LLM Triage Does, and Doesn't Do, for Static Analysis" (understated / academic)
-->



## Abstract

Static analysis at scale runs into the same problem everywhere: the tools work, but a large fraction of what they report is noise. On the OWASP Python Benchmark, raw CodeQL and Semgrep output sits at 37.7% precision, so roughly two of every three alerts are false. Teams learn to stop reading, and genuine bugs get lost in the queue.

VulnHunterX is an open-source pipeline that puts an LLM behind the SAST tools to triage each finding. Rather than asking the model "is this a bug," it routes the finding to a set of about 1,400 CWE-specific questions, lets the model pull in more context on demand (callers, callees, struct definitions, sanitizers) over several conversational turns from a pre-extracted context store, and requires a calibrated verdict: true positive, false positive, or an explicit "needs more data."

We measured it on five public benchmarks (Juliet, OWASP Python, OWASP Java, SecLLMHolmes, DiverseVul) across six models. With DeepSeek doing the reasoning, OWASP-Python precision goes from 37.7% to 87.3%, OWASP-Java from 61% to 87.6%, and SecLLMHolmes from 52% to 82%, while recall stays between 95% and 98%. False positives drop by 78–91% without losing real findings.

We then ran it against widely deployed software in C and Python: the FLAC and Vorbis audio codecs, libevent, and two Python tools, Gradio and Safety. It surfaced five previously-unreported vulnerabilities that we confirmed with proof-of-concept, including a TOCTOU race in FLAC, an unbounded `alloca()` stack overflow in libvorbis, and a full SSRF in Gradio 6.9.0. Each started as a single line in a large pile of SAST output. We walk the FLAC race through in full, from raw alert to a working exploit.

The talk is not a highlight reel. We also show where the approach underperforms: guided questions beat zero-shot on real web code, a $16 GPT-5 run was no more accurate than a $0.40 DeepSeek run, and the same pipeline moves 22 precision points on model choice alone.

---

## What attendees will learn

- How to wire the pipeline together: SAST to SARIF to context extraction to multi-turn guided verification to a calibrated verdict. The code is released.
- A repeatable way to hunt bugs in real projects. Point the pipeline at a target and get back a short, evidence-backed list instead of thousands of raw alerts. This is the same workflow that produced five confirmed vulnerabilities in FLAC, Vorbis, libevent, Gradio, and Safety.
- Where guided questions help and where they hurt. On synthetic Juliet, DeepSeek scored 81% with the full pipeline versus 89–94% zero-shot or generic; on realistic OWASP-Python the ordering reverses.
- The cost picture. GPT-5 gave no accuracy gain over DeepSeek at roughly 40x the cost ($16.75 vs $0.40 per run); local Ollama models cost nothing to run but trail on precision (65% vs 87%).
- Why "needs more data" matters. An abstaining triager beats a confident wrong one, and the confidence labels calibrate: high-confidence verdicts were 92% accurate on Juliet, low-confidence 81%.
- Where it breaks: cross-file context loss, framework sanitizers the model can't see, over-scoped questions, and the failure modes we're working on next.

---

## Confirmed vulnerabilities we'll disclose

Five previously-unreported vulnerabilities the pipeline surfaced from raw SAST output and we confirmed with working PoCs, across C libraries and Python tooling. All are under coordinated disclosure with upstream maintainers, and on-stage detail respects fix and embargo timelines.

| Project | Confirmed bug | CWE | Key location / pattern | Impact |
|---|---|---|---|---|
| flac | TOCTOU race condition | CWE-367 | `grabbag__file_change_stats(filename, ...)`: `stat(filename, &st)` checks the file, then `flac_chmod(filename, mode)` acts on the name without holding an fd | Local attacker controlling the parent directory swaps the file for a symlink, causing chmod of arbitrary files (e.g. `/etc/shadow`) as the elevated user. Reachable from 2 production paths. PoC succeeded on attempt 7. |
| vorbis | Stack overflow via `alloca()` in loop | CWE-770 | `ov_crosslap()` in `lib/vorbisfile.c`: loop does `lappcm[i] = alloca(...)`; `channels` comes from the file header with no upper bound | Crafted `.ogg` (`channels=255`, `blocksize=8192`) allocates about 4.17 MB onto a 1 MB worker stack, a DoS in small-stack decode contexts such as media players and game engines. |
| libevent | Compiler-elided `memset()` | CWE-14 | `sha1.c`: `memset(block, 0, sizeof(block))` and `memset(context, 0, sizeof(*context))` on buffers never read again, so dead-store elimination removes them at `-O1+` | SHA-1 input blocks, hash state, and counters persist on the stack after return. A memory-read primitive (core dump, `/proc/pid/mem`, swap) can recover secrets. Higher impact in nginx, memcached, Tor. |
| gradio | Full SSRF via user-controlled URL | CWE-918 | `gradio/image_utils.py` `extract_svg_content()`: `httpx.get(image_file)` on an HTTP-like URL with no SSRF guard; the sibling path uses `safehttpx`, but this one was missed | User-controlled `.svg` URL on a Gallery/Image component makes the server fetch arbitrary addresses, including internal IPs and the cloud metadata endpoint `169.254.169.254`. Confirmed on Gradio 6.9.0. |
| safety | Credential leak via URL sanitization | CWE-295 | `safety/tool/uv/command.py` `before()` (l.72): prefix check is only `startswith("https://pkgs.safetycli.com")`, bypassable by a lookalike attacker domain | Bypassed check embeds a live JWT into an attacker URL and leaks it via the `Authorization` header on a `uv` request. CI/CD argument injection can harvest roughly 24-hour Safety Platform tokens. |

### Confirmation methodology

Triage produces a lead; confirmation makes it a fact. For each candidate worth pursuing we did three things. First, the pipeline emitted a machine-readable evidence trail: source, sink, the missing guard, and the conditions needed to trigger. Second, we reviewed that trail against the code by hand and dropped anything that wasn't reachable. Third, we built a minimal proof-of-concept: a crafted input file (the `channels=255` `.ogg` for Vorbis), a local filesystem race harness (FLAC), a compiled binary inspected at `-O1+` to confirm the dead-store elimination (libevent), or a live request against a running instance (Gradio, Safety). PoC generation was LLM-assisted and iterative; the FLAC race reproduced on the seventh attempt. A finding is only called confirmed once a PoC reproduces the impact. Anything short of that stays a candidate. The dynamic-harness internals are out of scope here.

---

## Responsible disclosure and honesty

- The five vulnerabilities above are confirmed with PoCs and under coordinated disclosure. We present them within maintainer-agreed timelines. Anything else surfaced in third-party code is labelled a triaged candidate with an evidence trail, not a confirmed CVE, and we keep that distinction clear.
- The talk is about the triage and discovery pipeline, the part that turns thousands of alerts into a short list worth reviewing. PoC confirmation is shown as the result, not as a tutorial on dynamic testing.
- Every benchmark number is reproducible from the released harness. We show confidence intervals and the runs where the tool did worse.

---

## Talk outline (40 min)

| Time | Section | Backed by |
|---|---|---|
| 0–5 | The SAST false-positive problem (37.7% precision baseline) | `matrix_20260604_151302`, `20260519_141614` |
| 5–15 | Architecture: guided questions, multi-turn context expansion, calibration | pipeline stages |
| 15–25 | Benchmarks: 5 datasets, 6 models; precision 37→87%, recall 95–98%, FP reduction 78–91% | all `matrix_*` + `summary.json` |
| 25–32 | Bugs in real software: 5 confirmed vulns (FLAC, Vorbis, libevent, Gradio, Safety); FLAC TOCTOU walked through | `output/*`, disclosure set |
| 32–37 | Ablations: guided vs generic vs zero-shot; model and cost trade-offs; the Juliet reversal | `matrix_20260601_232426`, `matrix_20260531_180948` |
| 37–40 | Failure modes, roadmap, tool and data release | `output/`, roadmap |

---

## Supporting data (for reviewers and speaker reference)

### Precision lift, VulnHunterX (DeepSeek) vs raw SAST

| Dataset | Raw SAST precision | VulnHunterX precision | FP reduction | Recall (held) |
|---|---|---|---|---|
| OWASP-Python | 37.7% | 87.3% | 91.4% | 98.2% |
| OWASP-Java | 61.0% | 87.6% | 78.6% | 96.7% |
| SecLLMHolmes | 52.3% | 82.1% | 79.4% | 87.5% |
| Juliet (C/C++) | 50.0% | 81.4–86.3% | 78–82% | 95.0% |

### Model spread on one dataset (OWASP-Python, full pipeline)

DeepSeek 87.3%, GPT-4.1-mini 82.7%, Qwen3-Coder-480b 65.3%. Same pipeline, a 22-point precision swing on model choice alone.

### Ablation: full pipeline vs generic questions vs zero-shot (DeepSeek)

| Dataset | zero-shot | full (guided) | Takeaway |
|---|---|---|---|
| Juliet (synthetic) | 89.4% | 81.4% | Guided questions over-scope on pattern data |
| OWASP-Python (realistic) | 77.3% | 87.3% | Guided context wins on real web code |

### Aggregate workload reduction

Across 17 real codebases and 1,203 static findings: 334 true positive, 670 false positive, 199 needs-more-data. Raw SAST would have handed all 1,203 to an analyst. The pipeline returns a 334-item queue and sets aside 199 for human review, cutting items needing any attention by about 44% and confident-review load by about 72%.

### Cost and latency

About 10k tokens per finding, roughly $0.40 per benchmark run and p95 of 46–62s per finding with DeepSeek; $0 on local Ollama; GPT-5 about $16.75 per run for no measurable accuracy gain.
