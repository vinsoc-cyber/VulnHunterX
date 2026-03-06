# Copilot Instructions for VulnHunterX

## 1) Scope and precedence
- These instructions apply to this repository only.
- If repository docs conflict with generic guidance, follow repository docs first.
- Primary sources: `CLAUDE.md`, `README.md`, and code in `src/vuln_hunter_x/`.

## 2) Repository essentials (architecture guardrails)
- Preserve the stage pipeline contract:
  1. `clone`
  2. `analyze` (CodeQL and/or Semgrep)
  3. `extract-context`
  4. `verify`
  5-8. Optional C/C++ fuzz stages (`build-sanitized`, `extract-fuzz-context`, `generate-fuzz-drivers`, `fuzz-run`)
- Do not introduce changes that break:
  - SARIF discovery under `output/<lang>/<repo>/`.
  - Context CSV flow used by multi-turn verification.
  - Verification consumption of all `*.sarif` files (CodeQL and Semgrep).
- Keep behavior aligned with current CLI semantics and data flow.

## 3) Development workflow commands
- Setup:
  - `uv venv --python python3.12 .venv && source .venv/bin/activate`
  - `pip install -e ".[dev]"`
- Validation baseline:
  - Tests: `pytest tests/` (or narrower targeted tests first)
  - Lint: `ruff check src/`
  - Type check: `mypy src/`

## 4) Coding standards (Python-first)
- Type hints are required for all new and modified functions.
- Prefer clear contracts, explicit return types, and narrow exception handling.
- Avoid bare `except:` and avoid swallowing exceptions silently.
- Avoid mutable default arguments.
- Keep changes minimal and scoped; do not refactor unrelated modules.
- Preserve existing style patterns unless there is a clear local convention change.

## 5) Security baseline

Security is not a bolt-on phase — apply these principles continuously when writing or reviewing code in this repository.

### 5.1) Security philosophy
- **Secure by default**: Assume hostile input, untrusted environments, and determined adversaries.
- **Defense in depth**: Never rely on a single security control; layer protections.
- **Least privilege**: Request only the permissions and access needed.
- **Fail secure**: When something goes wrong, fail closed (deny), not open (allow).
- **Readable security code**: Obscure security logic gets removed by the next developer; keep it clear.

### 5.2) Subprocess safety
- Always use **list argv**: `subprocess.run([tool_path, "arg1", "arg2", ...], ...)`. Never `shell=True` or string interpolation into shell commands.
- Set an explicit **timeout** on every `subprocess.run()` / `subprocess.Popen()` call (e.g., `timeout=3600` for analysis, `timeout=600` for queries).
- Never insert user-supplied or config-supplied strings directly into a shell script body. If a shell script is generated (e.g., `build_sanitized.py`), treat the interpolated command as a high-risk surface and document the trust boundary.
- Validate external tool paths (`CODEQL_PATH`, `SEMGREP_PATH`) are actual executables before invocation.

### 5.3) Path handling
- Use `pathlib.Path.resolve()` to canonicalize paths before reading or writing.
- Enforce **repo-boundary validation**: when a file path originates from external data (e.g., SARIF `artifactLocation`), verify the resolved path stays within the expected repo or output directory. Use `os.path.commonpath()` or equivalent to confirm containment.
- For ZIP extraction, validate each member path against the target directory before extracting (prevent Zip Slip — see `benchmarks/scripts/setup_datasets.py` for the existing pattern).
- Read/write only under configured `output/` and `repos/` directories; never follow symlinks outside these boundaries without explicit validation.

### 5.4) Input validation and deserialization
- Always use `yaml.safe_load()` — never `yaml.load()` (unsafe deserialization).
- When loading JSON from external tools (SARIF files, CodeQL output), apply **type guards** after parsing: `isinstance(data, dict)`, `isinstance(runs, list)`, etc.
- Never use `eval()`, `exec()`, `compile()`, or `pickle.loads()` on untrusted data.
- Validate CLI arguments with `argparse` choices and type constraints (already done — preserve this pattern).
- For CSV files from pre-extracted context, use `csv.DictReader()` (safe); but never trust CSV content for path construction without validation.

### 5.5) Secrets and credentials
- Load secrets exclusively from environment variables via `load_dotenv()` + `os.environ.get()`. Never hardcode API keys, tokens, or credentials.
- Document required secrets in `env.example`; keep `.env` in `.gitignore`.
- Never log secrets. In verbose mode (`--verbose`), be aware that LLM prompts/responses may contain code snippets from target repos — truncate or redact if the context could include credentials found in source code.
- Never pass API keys as subprocess arguments (visible in `ps` output).

### 5.6) Error handling (security perspective)
- Catch **specific** exception types (`json.JSONDecodeError`, `FileNotFoundError`, `subprocess.TimeoutExpired`, etc.) — not bare `except Exception`.
- When a fallback is acceptable (e.g., return empty list on CSV read failure), log a warning before returning the default so failures are visible.
- Never expose internal paths, stack traces, or system details in user-facing error messages.
- In security-critical paths (SARIF parsing, LLM response parsing), prefer failing loudly over silently returning empty data.

### 5.7) SARIF data flow security (VulnHunterX-specific)
The pipeline processes SARIF files from external tools (CodeQL, Semgrep) through context extraction to LLM verification. Apply these guardrails:
- **SARIF → Finding**: Type-guard all fields extracted from SARIF JSON. Do not assume structure; degrade gracefully on missing fields.
- **Finding → File lookup**: File paths from SARIF `artifactLocation` are attacker-influenceable (crafted SARIF). Always resolve and validate against repo root before opening files.
- **Context → LLM prompt**: Code snippets and finding messages are inserted into LLM prompts verbatim. While the LLM is a read-only consumer (no code execution from its output), be aware of prompt injection risks when processing untrusted SARIF content.
- **LLM → Verdict**: Parse LLM JSON responses with `json.loads()` and validate expected keys/types. Never execute or `eval()` LLM output.
- Keep data-flow reasoning explicit when changing verification or parsing logic.

## 6) Change execution policy
- Implement the smallest viable diff that solves the requested issue.
- Do not change public behavior unless requested.
- Do not fix unrelated issues in the same patch.
- Update docs when behavior or CLI contracts change.

## 7) Verification policy (required)
After code edits:
- Run targeted tests relevant to changed files first.
- If `src/` code changed, also run:
  - `ruff check src/`
  - `mypy src/`
- Escalate to broader `pytest tests/` when impact is cross-module or uncertain.

## 8) Response/reporting format
- For multi-step tasks, provide a short plan, then implement.
- Summarize what changed, where, and what was validated.
- For security-sensitive tasks, always include a **Security Notes** section.

## 9) Explicit non-portable exclusions
Do not rely on Claude-specific mechanics in this repository guidance:
- Task/subagent orchestration commands.
- Persistent Claude memory update workflows.
- Artifact-edit specific Claude tool semantics.
- Slash-command workflow creation conventions.
- Rules copied from unrelated repositories (for example, mcp-offsec-specific conventions).

## 10) Claude-to-Copilot mapping (MVP)
- Security persona and threat checks -> apply as coding/review checklist.
- Python severity and anti-pattern rules -> apply as implementation review rubric.
- uv reproducibility guidance -> apply where compatible with existing repo workflow.
- Claude runtime/tool instructions -> excluded; replace with direct behavioral guidance.

## 11) Language-specific security patterns

### 11.1) Python (primary language)
- Use `subprocess.run()` with **list arguments** and `shell=False` (the default). Never pass a single string with `shell=True`.
- Use `pathlib` for path manipulation; call `.resolve()` before comparing or opening.
- Use `secrets` module for cryptographic randomness, not `random`.
- Never call `eval()`, `exec()`, `pickle.loads()`, or `yaml.load()` on untrusted data.
- Use `subprocess` with explicit `timeout` parameters — every external call must be bounded.
- Apply type hints on all security-critical function signatures for clarity and static analysis.
- Prefer `with` statements for file handles, network connections, and locks to ensure cleanup.

### 11.2) C/C++ (fuzz stages 5–8)
- Use bounds-checked functions (`strncpy`, `snprintf` over `strcpy`, `sprintf`).
- Check all return values, especially for memory allocation (`malloc`, `calloc`).
- Prefer RAII and smart pointers over raw memory management in C++ code.
- Be vigilant about integer overflow/underflow, especially in size calculations.
- Use AddressSanitizer (ASan) and UBSan during development and fuzz testing — this is already the pattern in `build_sanitized.py`.
- Initialize all variables; avoid use-after-free and double-free.
- When generating or reviewing fuzz driver code, validate all pointer arithmetic and array indexing.

## 12) Security coding workflow

### 12.1) Threat-aware development
When writing or modifying security-sensitive code:
1. **Identify trust boundaries**: What data is external/untrusted? (SARIF files, config YAML, environment variables, LLM responses, target repo source code.)
2. **Threat model briefly**: What could go wrong? Think STRIDE — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.
3. **Write secure code as default**: Apply §5 patterns during implementation, not as an afterthought.
4. **Annotate security decisions**: Add a brief comment explaining *why* a security choice was made (e.g., `# safe_load to prevent arbitrary object instantiation`, `# resolve() + commonpath to prevent path traversal`).
5. **Flag concerns**: If a requirement has security implications, proactively raise them rather than guessing.

### 12.2) Post-generation security checklist
After generating or modifying any CLI command, analyzer, context extractor, or verification step, verify:
1. Secrets loaded from environment (not hardcoded)?
2. Subprocess uses list argv with explicit timeout (no `shell=True`)?
3. Paths resolved and validated within expected boundaries?
4. Errors caught with specific exception types and logged (not silenced)?
5. Output sanitized — no secrets, API keys, or excessive internal detail in logs?
6. SARIF-derived data type-guarded before use?

### 12.3) Security in output and reporting
- For security-sensitive tasks, always include a **Security Notes** section in your response summarizing: key security controls applied, assumptions, limitations, and any recommended hardening.
- Do not write security theater — no useless controls that add complexity without protection.
- Security controls should be proportional to the actual threat; do not over-engineer.

## 13) Dependency and supply chain
- `pyproject.toml` is the **single source of truth** for all dependencies.
- Pin major versions, allow minor updates (e.g., `>=X.Y,<X+1.0`).
- Separate production dependencies from `[project.optional-dependencies] dev = [...]`.
- **Supply chain safety**: Before adding any dependency, verify it exists on PyPI, check download count and last publish date.
- **No hallucinated packages**: If unsure whether a package exists, say so explicitly rather than inventing a name.
- Never copy-paste or vendor library source code; always install via package manager.
- Be cautious with transitive dependencies that perform deserialization or native code execution.
- Virtual environment is required (`uv venv` or `python -m venv`).
