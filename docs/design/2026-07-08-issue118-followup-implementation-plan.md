# Verifier Slice Containment + Honest NMD — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `795e4fd`'s #118 fix actually correct — guarantee the verifier's code slice contains the flagged line, and stop the force-decision path from keyword-forcing an unseen-line NMD into a True Positive.

**Architecture:** Two surgical changes. (A) `ContextExtractor.get_context` gains a containment predicate: an enclosing-"function" slice is used only when it actually contains the flagged line, else it falls through to the existing `±context_lines` window. (C) `LLMClient._force_decision_turn` stops keyword-counting a terminal NMD into a verdict — it respects a committed TP/FP and preserves NMD (abstain) when the model won't commit.

**Tech Stack:** Python 3, pytest, litellm; the `benchmark/` versionab framework for behavioral A/B.

## Global Constraints

- Test runner: `.venv/bin/python -m pytest --no-cov` (system python lacks the installed package).
- Always add `--ignore tests/test_recall_1192_services.py` (it breaks collection).
- Pre-existing ruff drift in the repo is out of scope — do not fix unrelated lint.
- Surgical changes only. Keep the #118 line-numbering renderer (`render_code_for_prompt`) untouched.
- `engine.py:1294` `arm_b` becomes practically orphaned (no `[Forced decision:` sentinel is emitted after Fix C). **Flag it in a comment; do NOT delete it.**
- Behavioral benchmark config is the default `openai-gpt-5.5-temp0-iter5` (matches the A/B baseline: gpt-5.5, temp 0, iter 5). The new version label is auto-stamped `1.0.0@<sha>`.
- Design doc: `docs/design/2026-07-08-issue118-followup-slice-containment-design.md`. Reference it in code comments.

---

### Task 1: Slice containment guard (`get_context`)

**Files:**
- Modify: `src/vuln_hunter_x/context/extractor.py:105` (the enclosing-function return branch)
- Create: `tests/test_context_extractor.py`

**Interfaces:**
- Consumes: `ContextExtractor(repos_base: Path, output_dir: Path | None = None)`; `ContextExtractor.get_context(file_path: str, line: int, lang: str, context_lines: int = 50, repo_name: str = "") -> CodeContext`. `CodeContext` has `.code: str`, `.function_name: str`, `.start_line: int`, `.end_line: int`.
- Produces: same signature; the post-condition `start_line <= line <= end_line` now holds whenever the file is readable and `1 <= line <= len(file)`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_context_extractor.py`:

```python
"""ContextExtractor.get_context slice-containment tests (issue #118 follow-up)."""
import textwrap
from pathlib import Path

from vuln_hunter_x.context.extractor import ContextExtractor


def _write(tmp_path: Path, lang: str, repo: str, rel: str, content: str) -> None:
    p = tmp_path / lang / repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def test_flagged_line_after_closed_function_is_still_in_slice(tmp_path):
    # Backward regex search finds `helper` (a real C signature) as the enclosing
    # function; its block closes at line 3, but the flagged line is 5. Before the
    # fix get_context returns [1,3] (line 5 omitted); the slice must contain line 5.
    content = textwrap.dedent(
        """\
        void helper(int x) {
            do_thing(x);
        }
        int global_flag = 1;
        dangerous_sink(global_flag);
        """
    )
    _write(tmp_path, "c", "demo", "mod.c", content)
    ex = ContextExtractor(repos_base=tmp_path)
    ctx = ex.get_context("mod.c", 5, "c", repo_name="demo")
    assert ctx.start_line <= 5 <= ctx.end_line


def test_healthy_function_slice_is_unchanged(tmp_path):
    # A function that DOES contain the flagged line keeps its exact bounds.
    content = textwrap.dedent(
        """\
        int main(void) {
            int a = read_input();
            sink(a);
            return 0;
        }
        """
    )
    _write(tmp_path, "c", "demo", "main.c", content)
    ex = ContextExtractor(repos_base=tmp_path)
    ctx = ex.get_context("main.c", 3, "c", repo_name="demo")
    assert (ctx.start_line, ctx.end_line) == (1, 5)
    assert ctx.function_name == "main"


def test_functionless_file_window_contains_flagged_line(tmp_path):
    # No function match anywhere → window fallback, which contains the line.
    content = "\n".join(f"stmt_{i}();" for i in range(1, 41)) + "\n"
    _write(tmp_path, "php", "app", "script.php", content)
    ex = ContextExtractor(repos_base=tmp_path)
    ctx = ex.get_context("script.php", 30, "php", repo_name="app")
    assert ctx.start_line <= 30 <= ctx.end_line


def test_line_past_eof_does_not_claim_containment(tmp_path):
    # Flagged line beyond the file → the slice must not falsely span it
    # (this is the residual case that flows to NMD via Fix C).
    content = "a();\nb();\nc();\n"
    _write(tmp_path, "c", "demo", "short.c", content)
    ex = ContextExtractor(repos_base=tmp_path)
    ctx = ex.get_context("short.c", 999, "c", repo_name="demo")
    assert not (ctx.start_line <= 999 <= ctx.end_line)
```

- [ ] **Step 2: Run the tests to verify the containment test fails**

Run: `.venv/bin/python -m pytest tests/test_context_extractor.py --no-cov -v`
Expected: `test_flagged_line_after_closed_function_is_still_in_slice` **FAILS** (returned slice is `[1,3]`, so `1 <= 5 <= 3` is False). The other three PASS.

- [ ] **Step 3: Add the containment predicate**

In `src/vuln_hunter_x/context/extractor.py`, change the enclosing-function branch (currently at line 105):

```python
        # Use the enclosing-function slice only when it actually contains the
        # flagged line. The regex fallback in _find_function_bounds can match a
        # control-flow keyword (if/while/switch) as a "function" whose block ends
        # before the flagged line, and unlisted languages (e.g. PHP) borrow the C
        # patterns — either way the slice would omit the very line under review,
        # forcing the verifier to guess. Fall through to the window otherwise.
        # See docs/design/2026-07-08-issue118-followup-slice-containment-design.md.
        if (
            func_start is not None
            and func_end is not None
            and func_start + 1 <= line <= func_end + 1
        ):
            code = "\n".join(lines[func_start : func_end + 1])
            return CodeContext(
                code=code,
                function_name=func_name or "<anonymous>",
                start_line=func_start + 1,
                end_line=func_end + 1,
                file_path=file_path,
            )
```

(Only the `if` condition gains the two `func_start + 1 <= line <= func_end + 1` clause and the comment; the `CodeContext` return body is unchanged.)

- [ ] **Step 4: Run the tests to verify all pass**

Run: `.venv/bin/python -m pytest tests/test_context_extractor.py --no-cov -v`
Expected: all four PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vuln_hunter_x/context/extractor.py tests/test_context_extractor.py
git commit -m "fix(context): guarantee the flagged line is inside get_context's slice (#118)

The regex fallback in _find_function_bounds matches if/while/switch as a
function; PHP (unlisted) borrows the C patterns. get_context returned that
block even when it did not contain the flagged line, so the verifier reasoned
over code that omits the very line under review. Use the function slice only
when it contains the flagged line; otherwise fall through to the window."
```

---

### Task 2: Honest NMD in the force-decision turn

**Files:**
- Modify: `src/vuln_hunter_x/llm/client.py:1186-1250` (the NMD keyword block inside `_force_decision_turn`)
- Modify: `tests/test_calibration_fixes.py:458-510` (`TestForcedDecisionAccessControlSignals`)

**Interfaces:**
- Consumes: `LLMClient._force_decision_turn(messages, all_raw_responses, total_tokens_used, total_cost_usd, ...) -> tuple[dict, str, int, float, int, int, int]`; the first tuple element is the parsed verdict dict with keys `verdict` ("True Positive"|"False Positive"|"Needs More Data"), `reasoning`, `parse_failed`.
- Produces: same signature; post-condition — the returned `verdict` is exactly what `_parse_response` produced (a committed TP/FP is respected; NMD/parse-failure is preserved). No `[Forced decision:` string is appended.

- [ ] **Step 1: Rewrite the test class to the new contract (the failing test)**

In `tests/test_calibration_fixes.py`, replace the class `TestForcedDecisionAccessControlSignals` (lines 458-510) with:

```python
class TestForcedDecisionPreservesAbstention:
    """After the explicit force-decision prompt, _force_decision_turn respects
    the model's answer: a committed TP/FP passes through unchanged, and a
    persistent Needs-More-Data is preserved as abstention. It must NOT keyword-
    count the reasoning into a verdict — promoting NMD to TP on taint vocabulary
    ('no validation', 'unsafe') systematically over-confirmed findings the model
    could not actually decide (#119)."""

    def setup_method(self):
        self.client = LLMClient(provider="openai", model="gpt-4o")

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_persistent_nmd_is_preserved_not_forced_to_tp(self, mock_completion):
        # The forced turn still returns NMD with taint-flavored reasoning. Old
        # behavior promoted this to TP; new behavior keeps it NMD.
        nmd_response = (
            '{"verdict": "Needs More Data", "confidence": "Low",'
            ' "reasoning": "No authorization check (e.g., capability test,'
            ' permission check) is present anywhere in the provided code.'
            ' The function is directly callable from unprotected callers.",'
            ' "answers": []}'
        )
        mock_completion.return_value = _make_litellm_response(nmd_response)
        parsed, *_ = self.client._force_decision_turn(
            messages=[{"role": "user", "content": "x"}],
            all_raw_responses=[],
            total_tokens_used=0,
            total_cost_usd=0.0,
        )
        assert parsed["verdict"] == "Needs More Data"
        assert "[Forced decision:" not in parsed.get("reasoning", "")

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_committed_verdict_is_respected(self, mock_completion):
        # When the forced turn commits to a side, it is passed through unchanged.
        fp_response = (
            '{"verdict": "False Positive", "confidence": "Medium",'
            ' "reasoning": "The id is cast with intval() before the query, so the'
            ' tainted-string construct is neutralized.", "answers": []}'
        )
        mock_completion.return_value = _make_litellm_response(fp_response)
        parsed, *_ = self.client._force_decision_turn(
            messages=[{"role": "user", "content": "x"}],
            all_raw_responses=[],
            total_tokens_used=0,
            total_cost_usd=0.0,
        )
        assert parsed["verdict"] == "False Positive"
        assert "[Forced decision:" not in parsed.get("reasoning", "")

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_parse_failure_stays_nmd(self, mock_completion):
        # A truncated / unparseable forced-decision response must stay NMD and
        # never be keyword-counted into a verdict.
        truncated = (
            '{"verdict": "True Positive", "reasoning": "the multiplication is '
            'unsafe, there is no validation and no bounds check, exploitable'
        )
        mock_completion.return_value = _make_litellm_response(truncated)
        parsed, *_ = self.client._force_decision_turn(
            messages=[{"role": "user", "content": "x"}],
            all_raw_responses=[],
            total_tokens_used=0,
            total_cost_usd=0.0,
        )
        assert parsed["verdict"] == "Needs More Data"
        assert parsed.get("parse_failed") is True
        assert "[Forced decision:" not in parsed.get("reasoning", "")
```

- [ ] **Step 2: Run the tests to verify the NMD test fails**

Run: `.venv/bin/python -m pytest tests/test_calibration_fixes.py::TestForcedDecisionPreservesAbstention --no-cov -v`
Expected: `test_persistent_nmd_is_preserved_not_forced_to_tp` **FAILS** (current code promotes to `"True Positive"` and appends `"[Forced decision: evidence leans toward TP]"`). `test_committed_verdict_is_respected` and `test_parse_failure_stays_nmd` PASS.

- [ ] **Step 3: Remove the keyword-promotion block**

In `src/vuln_hunter_x/llm/client.py`, inside `_force_decision_turn`, delete the entire NMD block (currently lines 1186-1250, from the comment `# If still NMD, try to infer direction...` through `... + " [Forced decision: defaulted to FP]"`). The method tail becomes:

```python
        parsed = self._parse_response(raw)
        # The force-decision prompt already asked the model to commit to TP or
        # FP. Respect whatever it returns: a committed verdict, or — if it still
        # answers Needs More Data (or the response was unparseable) — the
        # abstention. We deliberately do NOT keyword-count the reasoning into a
        # verdict: promoting NMD to TP on taint vocabulary ("no validation",
        # "unsafe") systematically over-confirms findings the model could not
        # actually decide (#119). See
        # docs/design/2026-07-08-issue118-followup-slice-containment-design.md.
        return (
            parsed,
            raw,
            total_tokens_used,
            total_cost_usd,
            total_input_tokens,
            total_output_tokens,
            total_cached_input_tokens,
        )
```

- [ ] **Step 4: Flag `arm_b` as orphaned (comment only, do not delete)**

In `src/vuln_hunter_x/verification/engine.py`, just above the `arm_b = ...` line (currently 1294), add:

```python
        # NOTE (2026-07-08): arm_b is now practically dead — _force_decision_turn
        # no longer emits the "[Forced decision:" sentinel after the #118 follow-up
        # (honest NMD). Kept intentionally; removal is a separate follow-up.
        arm_b = is_fp and "[Forced decision:" in reasoning_text
```

- [ ] **Step 5: Run the force-decision tests to verify all pass**

Run: `.venv/bin/python -m pytest tests/test_calibration_fixes.py::TestForcedDecisionPreservesAbstention --no-cov -v`
Expected: all three PASS.

- [ ] **Step 6: Confirm no other test references the old class name**

Run: `grep -rn "TestForcedDecisionAccessControlSignals\|promotes_tp" tests/`
Expected: no matches (if any appear, update them to the new class/method names).

- [ ] **Step 7: Commit**

```bash
git add src/vuln_hunter_x/llm/client.py src/vuln_hunter_x/verification/engine.py tests/test_calibration_fixes.py
git commit -m "fix(llm): respect a post-force NMD instead of keyword-forcing TP (#119)

_force_decision_turn counted taint vocabulary ('unsafe', 'no validation') to
promote a terminal Needs-More-Data into a True Positive tagged '[Forced
decision: evidence leans toward TP]'. On off-slice findings this is over-
confirmation on code the model never saw. Respect a committed TP/FP; preserve
NMD (abstain) otherwise. arm_b flagged orphaned (kept)."
```

---

### Task 3: Regression sweep of the blast radius

**Files:** none created; fix any fallout in test files only.

- [ ] **Step 1: Run the affected test files**

Run:
```bash
.venv/bin/python -m pytest --no-cov -q \
  tests/test_context_extractor.py \
  tests/test_calibration_fixes.py \
  tests/test_llm_client.py \
  tests/test_registry_contract.py \
  tests/test_prompt_code_numbering.py \
  tests/test_context_provider.py \
  tests/test_treesitter_extractor.py \
  tests/test_framework.py \
  tests/test_parallel_verification.py \
  --ignore tests/test_recall_1192_services.py
```
Expected: all pass. If any test asserts the old keyword-forced TP or the `[Forced decision:` emission, update it to the new contract (respect committed verdict / preserve NMD) — the production behavior is intentionally changed, so such assertions are stale.

- [ ] **Step 2: Commit any test fixes**

```bash
git add -A tests/
git commit -m "test: update stale assertions for honest-NMD force decision"
```
(Skip if Step 1 was already green.)

---

### Task 4: Behavioral validation — targeted findings + final versionab A/B

This task needs the LLM proxy (gpt-5.5) live. It spends real tokens (~$19-scale for the full run).

- [ ] **Step 1: Preflight the LLM backend**

Run: `.venv/bin/vuln-hunter-x check` (or the benchmark dry-run below).
If the backend is unreachable / unconfigured: **STOP and report to the user** — the deterministic tests (Tasks 1-3) are the code gate; the behavioral run cannot proceed without the proxy.

- [ ] **Step 2: Preview cost ($0)**

Run: `python benchmark/src/benchmark.py --dry-run versionab`
Expected: prints the target list (dvcp, dvwa, nodegoat, insecure-coding-examples) and the previous baseline it will compare against (`1.0.0@795e4fd`).

- [ ] **Step 3: Run the full versionab benchmark**

Run: `python benchmark/src/benchmark.py versionab`
This verifies all frozen panels with the fixed engine, writes `benchmark/result/version_ab/1.0.0@<newsha>/`, and auto-generates `compare_vs_1.0.0@795e4fd.{json,md}`.

- [ ] **Step 4: Verify the "done when" criteria against the compare report**

Read `benchmark/result/version_ab/1.0.0@<newsha>/compare_vs_1.0.0@795e4fd.md` and the per-app `verdicts/*.md`. Confirm:
- The three `sqli_blind` findings (`high.php:33`, `low.php:32`, `medium.php:34`) and `nodegoat server.js:78` are **TP with reasoning that quotes the actual flagged line** (no `[Forced decision:` tag, no "flagged line not present").
- The not-real findings `cryptography/.../ecb_attack.php:92` and `upload/source/impossible.php:54` are **FP** (no longer forced-TP).
- `dvcp imgRead.c:62` remains **TP** (the #118 numbering win holds).
- No finding regressed from a correct verdict to an over-dismissal.

- [ ] **Step 5: Commit the new baseline + compare report**

```bash
git add benchmark/result/version_ab/
git commit -m "bench(versionab): baseline 1.0.0@<newsha> vs 795e4fd — slice-containment + honest-NMD fix"
```

- [ ] **Step 6: Summarize the A/B/C outcome for the user**

Report: precision/recall deltas vs B, whether the over-confirmed forced-TPs became real-evidence TPs (recall preserved legitimately) or correct FPs (precision up), and any residual NMDs. Note this is still a real-heavy panel — an FP-heavy panel remains the recommended follow-up.

---

## Self-Review

**Spec coverage:**
- Root-cause bug 1 (non-containing slice) → Task 1. ✅
- Root-cause bug 2 (keyword-forced TP) → Task 2. ✅
- Goal 1 (flagged line always in slice) → Task 1 tests. ✅
- Goal 2 (persistent NMD preserved; commit still breaks ties) → Task 2 tests. ✅
- Goal 3 (affected findings resolve on real evidence) → Task 4 Step 4. ✅
- Goal 4 (final versionab A/B) → Task 4 Step 3. ✅
- Out-of-scope items (arm_b, PHP patterns, #120, FP-heavy panel) → Global Constraints + Task 2 Step 4 + Task 4 Step 6. ✅

**Placeholder scan:** No TBD/TODO; every code and test step shows full code; every command shows expected output. `<newsha>` is a runtime-resolved git SHA, not a placeholder to fill in by hand.

**Type consistency:** `get_context(...) -> CodeContext` with `.start_line/.end_line/.function_name` used consistently across Task 1 tests and the edit. `_force_decision_turn` returns the 7-tuple with the parsed dict first in both the edit and Task 2 tests; `parsed["verdict"]`/`parsed["reasoning"]`/`parsed["parse_failed"]` keys match `_parse_response`'s output as used by the existing (kept) parse-failure test.
