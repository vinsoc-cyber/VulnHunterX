# Fix #118 — Anchored Code Slice + Quote-and-Confirm Guard — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the verifier prompt show code with correct absolute line-number gutters and the flagged line marked, plus a quote-and-confirm guard, so real bugs stop being dismissed because the model can't locate the flagged line.

**Architecture:** A stateless renderer (`render_code_for_prompt`) turns a raw slice + its absolute start line + the flagged line into a numbered, marked block. The absolute start line (`CodeContext.start_line`) is threaded from the engine through the LLM client into the prompt builder via one new default-safe `context_start_line` param. The system prompt gains a "Step 0: locate & quote the flagged line" instruction and splits "construct genuinely absent on a visible line" (False Positive) from "cannot locate the line" (Needs More Data). `CodeContext.code` stays raw, so the regex-based context consumers are untouched.

**Tech Stack:** Python 3, pytest, PyYAML. Spec: `docs/design/2026-06-22-issue118-code-slice-design.md`.

## Global Constraints

- Work on branch `fix/118-anchored-code-slice` (already created off `main`). One commit per task.
- Run tests with `.venv/bin/python -m pytest <path> -v` (pytest-cov is auto-enabled by the repo; a single test still runs fine).
- New source/test files carry the repo header verbatim: `# SPDX-License-Identifier: LGPL-2.1-only` then `# Copyright (c) 2026 VinSOC Cyber`.
- The flagged-line marker is the Unicode arrow `→` (U+2192); keep files UTF-8.
- Keep `CodeContext.code` **raw** — do NOT add numbering inside `extractor.py`.
- The `context_start_line` param defaults to `1` everywhere (backward compatibility for existing positional callers/tests); the three real engine call sites pass `context_result.start_line` explicitly.
- Do NOT touch `_resolve_path` / `repo_name` resolution — explicitly out of scope (separate issue).

---

### Task 1: `render_code_for_prompt` pure renderer

**Files:**
- Modify: `src/vuln_hunter_x/llm/prompts.py` (add module-level function near the existing `_window_around_line`, which Task 2 removes)
- Test: `tests/test_prompt_code_numbering.py` (create)

**Interfaces:**
- Consumes: nothing (pure stdlib).
- Produces: `render_code_for_prompt(code: str, start_line: int, flagged_line: int, window: int | None = None) -> str` — returns the slice with each line prefixed by its absolute number; flagged line prefixed `→ `, others `  `; a `// NOTE:` header when the flagged line is outside the slice; an optional `// [snippet windowed …]` header when `window` trims the slice.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_prompt_code_numbering.py`:

```python
# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Unit tests for absolute-line-number rendering of verifier code slices."""

from vuln_hunter_x.llm.prompts import render_code_for_prompt


def test_numbers_lines_with_absolute_offset_and_marks_flagged():
    code = "int a;\nfree(buff1);\nreturn a;"
    out = render_code_for_prompt(code, start_line=60, flagged_line=61)
    assert "→ 61: free(buff1);" in out
    assert "  60: int a;" in out
    assert "  62: return a;" in out


def test_flagged_line_outside_slice_emits_note_and_no_marker():
    out = render_code_for_prompt("int a;\nint b;", start_line=10, flagged_line=99)
    assert "NOTE: flagged line 99 is NOT within this slice (lines 10-11)" in out
    assert "→" not in out


def test_window_trims_around_flagged_line_keeping_absolute_numbers():
    code = "\n".join(f"line{n}" for n in range(1, 21))  # file lines 1..20
    out = render_code_for_prompt(code, start_line=1, flagged_line=10, window=2)
    assert "→ 10: line10" in out
    assert "  8: line8" in out
    assert "  12: line12" in out
    assert "line7" not in out
    assert "line13" not in out
    assert "windowed around flagged line 10" in out


def test_empty_code_returns_unchanged():
    assert render_code_for_prompt("", start_line=5, flagged_line=5) == ""


def test_marks_first_line_when_flagged_is_start():
    out = render_code_for_prompt("a();\nb();", start_line=42, flagged_line=42)
    assert "→ 42: a();" in out
    assert "  43: b();" in out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_prompt_code_numbering.py -v`
Expected: FAIL — `ImportError: cannot import name 'render_code_for_prompt'`.

- [ ] **Step 3: Implement the renderer**

In `src/vuln_hunter_x/llm/prompts.py`, add this function at module level (place it just above the existing `_window_around_line` definition; that helper is removed in Task 2):

```python
def render_code_for_prompt(
    code: str,
    start_line: int,
    flagged_line: int,
    window: int | None = None,
) -> str:
    """Render a code slice with absolute line-number gutters, marking the
    flagged line so the verifier never has to count lines to locate it.

    Args:
        code: Raw source slice (no line numbers).
        start_line: Absolute file line number of the slice's FIRST line.
        flagged_line: Absolute file line number the finding points at.
        window: If set (>0), keep only ±window lines around the flagged line
            before numbering. Replaces the old ``_window_around_line`` helper.

    Returns:
        The slice with each line prefixed by its absolute line number; the
        flagged line marked with a leading arrow. When the flagged line is not
        within the slice, a NOTE header is prepended and no line is marked.
    """
    lines = code.splitlines()
    if not lines:
        return code
    if start_line < 1:
        start_line = 1
    end_line = start_line + len(lines) - 1

    window_note = ""
    if window is not None and window > 0 and start_line <= flagged_line <= end_line:
        lo = max(start_line, flagged_line - window)
        hi = min(end_line, flagged_line + window)
        if lo > start_line or hi < end_line:
            window_note = (
                f"// [snippet windowed around flagged line {flagged_line} "
                f"(showing lines {lo}-{hi} of {start_line}-{end_line})]\n"
            )
            lines = lines[lo - start_line : hi - start_line + 1]
            start_line, end_line = lo, hi

    out_note = ""
    if not start_line <= flagged_line <= end_line:
        out_note = (
            f"// NOTE: flagged line {flagged_line} is NOT within this slice "
            f"(lines {start_line}-{end_line}); request the enclosing function "
            f"if you cannot confirm the construct.\n"
        )

    rendered = []
    for i, text in enumerate(lines):
        n = start_line + i
        marker = "→" if n == flagged_line else " "
        rendered.append(f"{marker} {n}: {text}")
    return out_note + window_note + "\n".join(rendered)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_prompt_code_numbering.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add src/vuln_hunter_x/llm/prompts.py tests/test_prompt_code_numbering.py
git commit -m "feat(#118): add render_code_for_prompt absolute-line-number renderer"
```

---

### Task 2: Wire the renderer into `build_user_prompt`; remove `_window_around_line`

**Files:**
- Modify: `src/vuln_hunter_x/llm/prompts.py:224-242` (`build_user_prompt`) and remove `_window_around_line` (`prompts.py:18-44`)
- Test: `tests/test_prompt_code_numbering.py` (add one integration test)

**Interfaces:**
- Consumes: `render_code_for_prompt(...)` from Task 1; `finding.start_line: int`, `questions.snippet_window_lines: int | None`.
- Produces: `PromptBuilder.build_user_prompt(finding, context, questions, func_name, context_start_line: int = 1) -> str` — embeds the numbered/marked code in `<code_under_review>`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_prompt_code_numbering.py`:

```python
from vuln_hunter_x.core.types import Finding, GuidedQuestions
from vuln_hunter_x.llm.prompts import PromptBuilder


def test_build_user_prompt_numbers_and_marks_flagged_line():
    builder = PromptBuilder()
    finding = Finding(
        rule_id="cpp/double-free",
        message="double free of buff1",
        file="imgRead.c",
        start_line=62,
        end_line=62,
        repo_name="dvcp",
        lang="cpp",
    )
    questions = GuidedQuestions(
        rule_id="cpp/double-free",
        short_description="double free",
        questions=["Is buff1 freed twice?"],
        context_hint="",
    )
    # Slice starts at file line 61, so line 62 is "free(buff1);".
    code = "void ProcessImage() {\nfree(buff1);\n}"
    prompt = builder.build_user_prompt(
        finding, code, questions, "ProcessImage", context_start_line=61
    )
    assert "→ 62: free(buff1);" in prompt
    assert "  61: void ProcessImage() {" in prompt
    assert "cpp/double-free" in prompt  # existing finding metadata still present
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_prompt_code_numbering.py::test_build_user_prompt_numbers_and_marks_flagged_line -v`
Expected: FAIL — `TypeError: build_user_prompt() got an unexpected keyword argument 'context_start_line'`.

- [ ] **Step 3: Update `build_user_prompt` and delete `_window_around_line`**

Replace `build_user_prompt` (`prompts.py:224-242`) with:

```python
    def build_user_prompt(
        self,
        finding: Finding,
        context: str,
        questions: GuidedQuestions,
        func_name: str,
        context_start_line: int = 1,
    ) -> str:
        """Build the user prompt for the LLM.

        ``context`` is the raw code slice; ``context_start_line`` is its
        absolute first-line number. The slice is rendered with absolute
        line-number gutters and the flagged line marked so the model can
        locate it without counting.
        """
        context = render_code_for_prompt(
            context,
            start_line=context_start_line,
            flagged_line=finding.start_line,
            window=questions.snippet_window_lines or None,
        )
        questions_text = "\n".join(f"{i + 1}. {q}" for i, q in enumerate(questions.questions))
        return self._build_prompt(finding, context, questions, func_name, questions_text)
```

Then delete the now-unused `_window_around_line` function (`prompts.py:18-44`, the `def _window_around_line(...)` block and its trailing blank line).

- [ ] **Step 4: Run the prompt tests AND the existing framework tests**

Run: `.venv/bin/python -m pytest tests/test_prompt_code_numbering.py tests/test_framework.py -v`
Expected: PASS. (`test_framework.py::test_build_user_prompt` and `::test_user_prompt_includes_tool_and_lang` still pass — they assert on rule_id/message/questions/headers, not raw code, and the new param defaults to 1.)

- [ ] **Step 5: Commit**

```bash
git add src/vuln_hunter_x/llm/prompts.py tests/test_prompt_code_numbering.py
git commit -m "feat(#118): render numbered code in build_user_prompt; remove _window_around_line"
```

---

### Task 3: Thread `context_start_line` through the LLM client and engine

**Files:**
- Modify: `src/vuln_hunter_x/llm/client.py` — `analyze` (313), `analyze_with_voting` (729), `request_second_opinion` (957)
- Modify: `src/vuln_hunter_x/verification/engine.py` — call sites at 1219, 1244, 1322
- Test: `tests/test_prompt_code_numbering.py` (add a signature guard test)

**Interfaces:**
- Consumes: `PromptBuilder.build_user_prompt(..., context_start_line)` from Task 2; `CodeContext.start_line: int`.
- Produces: `LLMClient.analyze`, `LLMClient.analyze_with_voting`, `LLMClient.request_second_opinion` each accept `context_start_line: int = 1` and forward it.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_prompt_code_numbering.py`:

```python
import inspect

from vuln_hunter_x.llm.client import LLMClient


def test_client_methods_accept_context_start_line():
    for name in ("analyze", "analyze_with_voting", "request_second_opinion"):
        params = inspect.signature(getattr(LLMClient, name)).parameters
        assert "context_start_line" in params, f"{name} missing context_start_line"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_prompt_code_numbering.py::test_client_methods_accept_context_start_line -v`
Expected: FAIL — `AssertionError: analyze missing context_start_line`.

- [ ] **Step 3: Add and forward the param in `client.py`**

In `analyze` (signature ends at `temperature: float | None = None,` on line 326), add a final parameter:

```python
        temperature: float | None = None,
        context_start_line: int = 1,
    ) -> Verdict:
```

Change the `build_user_prompt` call (line 352) to forward it:

```python
        user_prompt = self.prompt_builder.build_user_prompt(
            finding, context, questions, func_name, context_start_line
        )
```

In `analyze_with_voting`, add `context_start_line: int = 1,` to the keyword-only block (after `prefetched_context: dict[str, str] | None = None,` on line 745), and add `context_start_line=context_start_line,` to BOTH `self.analyze(...)` calls (the `samples == 1` call at 780-791 and the loop call at 799-811).

In `request_second_opinion`, add `context_start_line: int = 1,` to the signature (after `challenge_prompt: str | None = None,` on line 969) and forward it in the `build_user_prompt` call (line 985-987):

```python
        user_prompt = self.prompt_builder.build_user_prompt(
            finding, context, questions, func_name, context_start_line
        )
```

- [ ] **Step 4: Pass the anchor from the engine**

In `src/vuln_hunter_x/verification/engine.py`, add `context_start_line=context_result.start_line,` to each of the three calls, immediately after the `context=context_result.code,` line:

- `analyze_with_voting(...)` — after line 1221
- `analyze(...)` — after line 1246
- `request_second_opinion(...)` — after line 1324

Example (the `analyze` call):

```python
            verdict = self.llm_client.analyze(
                finding=finding,
                context=context_result.code,
                context_start_line=context_result.start_line,
                questions=questions,
                func_name=context_result.function_name,
                ...
```

- [ ] **Step 5: Run the new test plus the full client/engine regression suite**

Run: `.venv/bin/python -m pytest tests/test_prompt_code_numbering.py tests/test_framework.py tests/test_llm_client.py tests/test_llm_client_pool.py tests/test_verification_engine.py tests/test_parallel_verification.py tests/test_triage_reconciliation.py -v`
Expected: PASS (no regressions; the signature guard passes).

- [ ] **Step 6: Commit**

```bash
git add src/vuln_hunter_x/llm/client.py src/vuln_hunter_x/verification/engine.py tests/test_prompt_code_numbering.py
git commit -m "feat(#118): thread context_start_line from engine through LLM client"
```

---

### Task 4: Quote-and-confirm guard in the system prompt

**Files:**
- Modify: `config/prompts/system_prompt.yaml` (methodology block lines 19-20; RULE-SCOPE DISCIPLINE lines 58-60) — the loaded source of truth
- Modify: `src/vuln_hunter_x/llm/prompts.py` — `DEFAULT_SYSTEM_PROMPT` (methodology lines 52-53; RULE-SCOPE DISCIPLINE lines 86-87) — the fallback
- Test: `tests/test_prompt_code_numbering.py`

**Interfaces:**
- Consumes: `PromptBuilder.get_system_prompt(tool_name, lang)` (loads the YAML).
- Produces: rendered system prompt containing the "Step 0 — LOCATE the flagged line" instruction and the FP-vs-NMD split.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_prompt_code_numbering.py`:

```python
from vuln_hunter_x.llm.prompts import DEFAULT_SYSTEM_PROMPT


def test_system_prompt_has_locate_and_quote_guard():
    sp = PromptBuilder().get_system_prompt(tool_name="CodeQL", lang="cpp")
    assert "LOCATE the flagged line" in sp
    assert "Needs More Data" in sp


def test_default_system_prompt_constant_has_guard():
    assert "LOCATE the flagged line" in DEFAULT_SYSTEM_PROMPT
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest "tests/test_prompt_code_numbering.py::test_system_prompt_has_locate_and_quote_guard" "tests/test_prompt_code_numbering.py::test_default_system_prompt_constant_has_guard" -v`
Expected: FAIL — `AssertionError` (guard text absent).

- [ ] **Step 3: Edit `config/prompts/system_prompt.yaml`**

Insert Step 0 — replace lines 19-20:

old:
```
  ANALYSIS METHODOLOGY — follow these steps IN ORDER:
  1. IDENTIFY the vulnerability class from the rule ID and description.
```
new:
```
  ANALYSIS METHODOLOGY — follow these steps IN ORDER:
  0. LOCATE the flagged line: find it by its line number in the numbered code
     block, quote its exact text, and confirm the construct the rule describes is
     present on THAT line. The code is shown with absolute line-number gutters and
     the flagged line marked with a leading arrow. If the flagged line is NOT
     present in the provided code (or is marked as outside the slice), do NOT
     answer False Positive — return "Needs More Data" and request the enclosing
     function / correct slice.
  1. IDENTIFY the vulnerability class from the rule ID and description.
```

Split the FP/NMD case — replace lines 59-60:

old:
```
  - Your verdict must address the SPECIFIC vulnerability the reported rule (the Rule shown in the finding) describes — not some other issue you happen to notice. First confirm the construct that rule looks for is actually present at the flagged line.
  - If the reported construct is NOT present (e.g. an integer-multiplication rule whose flagged line has no multiplication), the correct verdict is "False Positive" (or "Needs More Data"). If you find a DIFFERENT kind of problem (e.g. you notice a path-traversal concern under an integer-overflow rule), that does NOT make this finding a True Positive — the reported rule did not claim it. Mark "False Positive" for the reported rule; do not relabel.
```
new:
```
  - Your verdict must address the SPECIFIC vulnerability the reported rule (the Rule shown in the finding) describes — not some other issue you happen to notice. First confirm the construct that rule looks for is actually present at the flagged line you located in step 0.
  - Distinguish two cases that look alike but get OPPOSITE verdicts: (a) you can SEE the flagged line and the rule's construct is genuinely absent from it (e.g. an integer-multiplication rule whose flagged line has no multiplication) → "False Positive"; (b) you canNOT locate the flagged line in the provided code, or it is marked as outside the slice → "Needs More Data" and request the enclosing function — never "False Positive" merely because the construct is not visible. If you find a DIFFERENT kind of problem (e.g. a path-traversal concern under an integer-overflow rule), that does NOT make this finding a True Positive — the reported rule did not claim it; mark "False Positive" for the reported rule, do not relabel.
```

- [ ] **Step 4: Mirror the edits in `DEFAULT_SYSTEM_PROMPT` (`prompts.py`)**

Apply the SAME two changes to the built-in fallback string. Replace the methodology header + step 1 (lines 52-53):

old:
```
ANALYSIS METHODOLOGY — follow these steps IN ORDER:
1. IDENTIFY the vulnerability class from the rule ID and description.
```
new:
```
ANALYSIS METHODOLOGY — follow these steps IN ORDER:
0. LOCATE the flagged line: find it by its line number in the numbered code
   block, quote its exact text, and confirm the construct the rule describes is
   present on THAT line. The code is shown with absolute line-number gutters and
   the flagged line marked with a leading arrow. If the flagged line is NOT
   present in the provided code (or is marked as outside the slice), do NOT
   answer False Positive — return "Needs More Data" and request the enclosing
   function / correct slice.
1. IDENTIFY the vulnerability class from the rule ID and description.
```

Replace the RULE-SCOPE DISCIPLINE bullets (lines 86-87):

old:
```
- Your verdict must address the SPECIFIC vulnerability the reported rule (the Rule shown in the finding) describes — not some other issue you happen to notice. First confirm the construct that rule looks for is actually present at the flagged line.
- If the reported construct is NOT present (e.g. an integer-multiplication rule whose flagged line has no multiplication), the correct verdict is "False Positive" (or "Needs More Data"). If you find a DIFFERENT kind of problem (e.g. you notice a path-traversal concern under an integer-overflow rule), that does NOT make this finding a True Positive — the reported rule did not claim it. Mark "False Positive" for the reported rule; do not relabel.
```
new:
```
- Your verdict must address the SPECIFIC vulnerability the reported rule (the Rule shown in the finding) describes — not some other issue you happen to notice. First confirm the construct that rule looks for is actually present at the flagged line you located in step 0.
- Distinguish two cases that look alike but get OPPOSITE verdicts: (a) you can SEE the flagged line and the rule's construct is genuinely absent from it (e.g. an integer-multiplication rule whose flagged line has no multiplication) → "False Positive"; (b) you canNOT locate the flagged line in the provided code, or it is marked as outside the slice → "Needs More Data" and request the enclosing function — never "False Positive" merely because the construct is not visible. If you find a DIFFERENT kind of problem (e.g. a path-traversal concern under an integer-overflow rule), that does NOT make this finding a True Positive — the reported rule did not claim it; mark "False Positive" for the reported rule, do not relabel.
```

- [ ] **Step 5: Run the guard tests plus the full suite**

Run: `.venv/bin/python -m pytest tests/test_prompt_code_numbering.py tests/test_framework.py -v`
Expected: PASS (guard present in both the YAML-loaded prompt and the constant).

- [ ] **Step 6: Commit**

```bash
git add config/prompts/system_prompt.yaml src/vuln_hunter_x/llm/prompts.py tests/test_prompt_code_numbering.py
git commit -m "feat(#118): add Step-0 locate-and-quote guard; split FP vs NMD on unlocatable line"
```

---

### Task 5: Behavioral acceptance — re-run the 6 issue-#118 findings

> Main-session acceptance step (not a unit test). Requires the LLM proxy in `.env` to be live. This is the spec's "Done when": the 6 findings must no longer be dismissed on wrong-line grounds.

**The 6 findings (verdicts live in `output/<lang>/<app>/verification_results/summary_*.json`):**
- `c/dvcp` — `imgRead.c:62` (`cpp/double-free`)
- `php/dvwa` — `vulnerabilities/sqli_blind/source/high.php:33`, `medium.php:34`, `low.php:32` (`tainted-sql-string`)
- `javascript/nodegoat` — `app/routes/server.js:78` (`js/missing-token-validation`)
- `python/bad-python-extract` — `server.py:93` (`py/flask-debug`)

- [ ] **Step 1: Run the full deterministic suite once more**

Run: `.venv/bin/python -m pytest tests/ -q`
Expected: PASS (whole suite green before any LLM spend).

- [ ] **Step 2: Confirm the verify CLI invocation**

Run: `.venv/bin/vuln-hunter-x verify --help`
Note the flags for re-verifying against existing prepared output (`output/<lang>/<app>` already holds SARIF + context + CodeQL DBs). Capture the verdict JSON to a fresh path (do not overwrite the committed pre-fix `summary_*.json`).

- [ ] **Step 3: Re-verify the four affected apps**

Re-run verification for `c/dvcp`, `php/dvwa`, `javascript/nodegoat`, `python/bad-python-extract` using the invocation from Step 2. (Per the project notes: one `verify` process per app, `-j 4`; do not `pkill -f 'vuln-hunter-x verify'` from a launch script — it self-matches.)

- [ ] **Step 4: Check the 6 verdicts**

For each of the 6 file:line findings, read the new `verdicts[]` entry. Confirm NONE is dismissed with wrong-line reasoning (e.g. "the flagged line is an array read, not a free"). Acceptance = each is now True Positive, or Needs More Data requesting the correct slice — not a wrong-line False Positive. Record the before/after verdict + reasoning for each.

- [ ] **Step 5: Write the result note and commit**

Save a short before/after table to `docs/design/2026-06-22-issue118-rerun-results.md` and commit:

```bash
git add docs/design/2026-06-22-issue118-rerun-results.md
git commit -m "test(#118): re-run results for the 6 anchored-slice findings"
```

---

## Self-Review

**Spec coverage:**
- Component 1 (renderer) → Task 1. ✓
- Component 2 (thread anchor, default-safe param) → Task 2 (`build_user_prompt`) + Task 3 (client + engine). ✓
- Component 3 (guard: Step 0 + FP/NMD split, YAML + default) → Task 4. ✓
- Remove `_window_around_line` → Task 2. ✓
- Keep `CodeContext.code` raw → Global Constraints + never edited. ✓
- Deterministic tests (numbering, out-of-slice, window, guard text, regression) → Tasks 1-4. ✓
- Behavioral re-run of the 6 → Task 5. ✓
- Out of scope (`_resolve_path`) → Global Constraints. ✓

**Placeholder scan:** No TBD/TODO; every code/edit step shows complete content and exact old/new strings.

**Type consistency:** `render_code_for_prompt(code, start_line, flagged_line, window=None)` is defined in Task 1 and called identically in Task 2. `context_start_line: int = 1` is introduced in Task 2 (`build_user_prompt`) and forwarded with the same name in Task 3 (`analyze`, `analyze_with_voting`, `request_second_opinion`) and from the engine. `CodeContext.start_line` and `Finding.start_line` match the definitions in `core/types.py`.
