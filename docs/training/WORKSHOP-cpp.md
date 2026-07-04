# Workshop — Self-Scan a Vulnerable C++ Repo (30 min)

A hands-on, copy-paste companion to [LESSON.md](LESSON.md). You will scan a real
deliberately-vulnerable C++ repository with VulnHunterX, using a **free Ollama
Cloud** model for the LLM triage step (no local GPU, no OpenAI bill). Then you'll
take a second repo home and score your own scan against a published answer key.

> **Windows users:** do everything inside **WSL2** or a Linux Docker container
> (`wsl --install`, then open Ubuntu). CodeQL build-tracing and the C/C++
> toolchain behave best on Linux/macOS.

**Workshop target:** `insecure-coding-examples` (C/C++) — reliable `cmake` build,
one bug per file, strong CodeQL coverage.
**Homework target:** `dvcp` (Damn Vulnerable C Program) — a single-file `gcc`
build that never fails, with a full published answer key.

| Step | Topic | Min |
|---|---|---|
| 0 | Setup recap | 3 |
| 1 | Register Ollama Cloud for triage | 5 |
| 2 | Clone + prepare (Stage 1) | 5 |
| 3 | Analyze (Stage 2) | 3 |
| 4 | Verify with the LLM (Stage 3) | 8 |
| 5 | Read & score the report (Stage 4) | 6 |
| — | Homework | take-home |

---

## Step 0 — Setup recap (3 min)

```bash
git clone https://github.com/vinsoc-cyber/VulnHunterX.git && cd VulnHunterX
uv venv --python python3.12 .venv && source .venv/bin/activate
uv pip install -e ".[dev]"          # or: python3.12 -m venv .venv && pip install -e ".[dev]"

cp env.example .env                 # we'll edit this next, for Ollama Cloud
```

Prerequisites: Python 3.12+, [CodeQL CLI 2.15+](https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/),
a C/C++ toolchain (`gcc`/`clang`, `cmake`, `make`). Semgrep is optional
but recommended (`--tool both`).

---

## Step 1 — Register Ollama Cloud for triage (5 min)

We use **Ollama Cloud** so everyone has a working LLM with no local model download
and no credit card.

1. Go to **https://ollama.com**, create a free account, and sign in.
2. Open your account → **API keys** → **Create key**. Copy the key (starts with a
   long token). Treat it like a password.
3. Edit `.env` and set the Ollama Cloud variables:

   ```bash
   LLM_PROVIDER=ollama
   OLLAMA_API_BASE=https://ollama.com
   OLLAMA_API_KEYS=<paste-your-key-here>     # NOTE: plural KEYS (comma-separated pool)
   LLM_MODEL=ollama/gpt-oss:120b-cloud       # any cloud model tag; the :cloud suffix matters
   ```

   > ⚠️ **It must be `OLLAMA_API_KEYS` (plural).** VulnHunterX reads the
   > comma-separated *pool* `OLLAMA_API_KEYS`; the singular `OLLAMA_API_KEY` is
   > **not** used. If you have several keys, separate them with commas and the tool
   > round-robins them (with per-key cooldown on rate limits).
   >
   > The **`:cloud` suffix** (or an `ollama.com` base URL) is how VulnHunterX
   > detects Cloud mode and attaches your bearer token. Pick any cloud-enabled
   > model tag Ollama lists for your account.

4. Verify the whole toolchain, including a live LLM smoke-test:

   ```bash
   vuln-hunter-x check-env
   ```

   Fix anything red:

   | Symptom | Fix |
   |---|---|
   | `CodeQL CLI not found` | Add to `PATH` or set `CODEQL_PATH` in `.env` |
   | `Semgrep not found` | Set `SEMGREP_PATH`, or skip (`--tool codeql`) |
   | Ollama key rejected | Re-check `OLLAMA_API_KEYS` (plural) and the `:cloud` model tag |

---

## Step 2 — Clone + prepare (Stage 1) (5 min)

```bash
vuln-hunter-x prepare \
  --url https://github.com/patricia-gallardo/insecure-coding-examples.git \
  --lang cpp \
  --build-command "mkdir -p build && cd build && cmake .. && make || true"
```

What this produces:

- `repos/cpp/insecure-coding-examples/` — the cloned source
- `output/cpp/insecure-coding-examples/database/` — the CodeQL database
- `output/cpp/insecure-coding-examples/context/` — AST-derived **context CSVs**
  (`functions.csv`, `callers.csv`, `structs.csv`, `free_sites.csv`, …)

> The trailing `|| true` lets a partial build succeed — CodeQL only needs to trace
> what compiled, and the example files compile independently. This is exactly the
> "keep the build green" point from the lesson.

---

## Step 3 — Analyze (Stage 2) (3 min)

```bash
vuln-hunter-x analyze \
  --repo insecure-coding-examples --lang cpp \
  --tool both --profile full
```

- `--tool both` runs **CodeQL + Semgrep**.
- `--profile full` loads the in-repo custom rules (`config/semgrep-custom/cpp.yaml`
  + `config/codeql-custom/cpp/`) — reliable **offline**, no semgrep.dev needed.

Output: one or more `*.sarif` files in `output/cpp/insecure-coding-examples/`.
Peek at how many raw findings you got:

```bash
ls -1 output/cpp/insecure-coding-examples/*.sarif
```

---

## Step 4 — Verify with the LLM (Stage 3) (8 min)

```bash
vuln-hunter-x verify \
  --repo insecure-coding-examples --lang cpp \
  --limit 8 --verbose
```

- Uses the Ollama Cloud model from your `.env`.
- `--limit 8` keeps it fast and cheap while you learn.
- `--verbose` shows the guided questions, the LLM's answers, and any
  **Needs-More-Data → fetch context → re-ask** turns.

Watch for: a finding that starts as `NEEDS_MORE_DATA`, the engine fetching a
`free_sites` or `caller` slice, and the model then committing to a verdict with a
confidence score. That's the multi-turn loop from the lesson, live.

> Want to compare LLMs? Re-run verify with a different `--provider/--model` without
> re-building anything:
> `vuln-hunter-x verify --repo insecure-coding-examples --lang cpp --provider openai --model gpt-4o --limit 8`

---

## Step 5 — Read & score the report (Stage 4) (6 min)

```bash
cat output/cpp/insecure-coding-examples/verification_results/report.md
# (report_vi.md is the Vietnamese version)
```

Find **one True Positive** and **one False Positive**. Note the confidence and the
reasoning. Then score the scan against the ground truth below.

### Answer key — `insecure-coding-examples` (workshop)

One bug per file under `exploitable/`. *(Source: `docs/benchmarks/ground-truth-baselines.md` §3.)*

| File | Class | CWE | Tier |
|---|---|---|---|
| `stack_buffer_overflow.c` | stack overflow via `gets` | CWE-121/242 | easy |
| `heap_buffer_overflow.c` | heap overflow via `strcpy(malloc, argv[1])` | CWE-122 | easy |
| `global_buffer_overflow.c` | global OOB read | CWE-119/125 | easy |
| `buffer_underflow.c` | buffer underflow | CWE-124 | medium |
| `container_overflow.cpp` | STL OOB (`vector.data()[6]`) | CWE-125 | medium |
| `signed_integer_overflow*.c` | signed overflow (×3) | CWE-190 | medium |
| `unsigned_integer_wraparound*.c` | unsigned wraparound (×3) | CWE-190 | medium |
| `numeric_truncation*.c` | wide→narrow truncation (×3) | CWE-197 | medium |
| `double_free.c` | double-free | CWE-415 | easy |
| `use_after_free.c` | use-after-free | CWE-416 | medium |
| `uncontrolled_format_string.c` | `printf(argv[1], argv[2])` | CWE-134 | easy |
| `incorrect_type_conversion.c` | bad cast | CWE-704 | medium |
| `disappearing_memset.c` | compiler-removed `memset` | CWE-14 | **hard (expect miss)** |
| `dangling_pointer.cpp` | dangling `string_view` to temporary | CWE-416 | **hard (expect miss)** |
| `temporary_capture.cpp` | lambda captures temporary by ref | lifetime | **hard (expect miss)** |
| `infinite_loop.cpp` | `while(true)` no exit | CWE-835 | easy |

**How to score:** map each report finding's `(file, CWE)` to a row.
**Recall** = ground-truth rows any tool detected. Separate *detection misses*
(no rule fired) from *triage misses* (fired but verified FP/NMD). Expect strong
results on the easy/medium syntactic classes and misses on the **hard-tier C++
lifetime/UB** classes — that's the documented, honest limitation.

---

## Homework — scan `dvcp` and score yourself

Run the full pipeline on the **Damn Vulnerable C Program** (single-file `gcc`
build — it never fails to compile):

```bash
vuln-hunter-x scan \
  --url https://github.com/hardik05/Damn_Vulnerable_C_Program.git \
  --lang c \
  --build-command "gcc -g -o dvcp imgRead.c" \
  --tool both --profile full --limit 15

cat output/c/Damn_Vulnerable_C_Program/verification_results/report.md
```

Then score your report against the ground truth and **write up: which bugs were
detected, which were triaged correctly, and which were missed (and why).**

### Answer key — `dvcp` (homework)

All bugs live on one `ProcessImage()` path, gated by fields of a crafted input
file. Line numbers per `imgRead.c`. *(Source: `docs/benchmarks/ground-truth-baselines.md` §2.)*

| # | Class | CWE | Line(s) | Tier |
|---|---|---|---|---|
| 1 | Integer overflow → undersized alloc | CWE-190 | `54-55` | medium |
| 2 | Heap buffer overflow (`memcpy` into undersized buf) | CWE-122/787 | `58` | medium |
| 3 | Double-free | CWE-415 | `59` + `62` | medium |
| 4 | Use-after-free | CWE-416 | `67` | medium |
| 5 | Integer underflow → large alloc | CWE-191 | `74` | medium |
| 6 | Heap buffer overflow (second buffer) | CWE-122/787 | `79` | medium |
| 7 | Divide-by-zero | CWE-369 | `82` | easy |
| 8 | Out-of-bounds read (stack) | CWE-125 | `90` | medium |
| 9 | Out-of-bounds read (heap) | CWE-125 | `91` | medium |
| 10 | Out-of-bounds write (stack) | CWE-787 | `94` | medium |
| 11 | Out-of-bounds write (heap) | CWE-787 | `95` | medium |
| 12 | Memory leak | CWE-401 | `99` | medium |
| 13 | Stack exhaustion (infinite recursion) | CWE-674 | `107` | easy |
| 14 | Heap exhaustion (unbounded `malloc` loop) | CWE-400/789 | `113-114` | easy |

**Expected outcome (documented baseline):** double-free, UAF, and OOB read/write
are detected; the **integer-overflow chain (#1, #5), divide-by-zero (#7), the leak
(#12), and the exhaustion bugs (#13, #14) are missed** — that's the primary recall
gap for this target, and a good discussion point in your write-up. Note also: the
repo ships several identical copies of the program (`dvcp.c`, `imgRead.c`,
`linux/`, `windows/`, `libAFL/`), so dedupe by basename when counting.

---

## Cheat sheet

| Command | What it does |
|---|---|
| `vuln-hunter-x interactive` | Guided wizard — friendliest entry point |
| `vuln-hunter-x scan ...` | Full pipeline (prepare → analyze → verify → report) |
| `vuln-hunter-x prepare ...` | Clone + CodeQL DB + context CSVs |
| `vuln-hunter-x analyze ...` | Run CodeQL / Semgrep → SARIF |
| `vuln-hunter-x verify ...` | LLM triage of SARIF → verdicts |
| `vuln-hunter-x report ...` | Regenerate the Markdown report |
| `vuln-hunter-x check-env` | Verify the toolchain + LLM |

Common flags: `--tool {codeql,semgrep,both}`,
`--profile {standard,extended,maximum,extended-registry,full}`,
`--provider`, `--model`, `--limit N`, `--max-iterations N`, `-j/--jobs N`,
`--dry-run`.
