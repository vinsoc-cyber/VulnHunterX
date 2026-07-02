# Fix #118 — Anchored Code Slice + Quote-and-Confirm Guard

**Issue:** [#118 — Misaligned code slice → verifier dismisses real bugs it can't "see"](https://github.com/vinsoc-cyber/VulnHunterX/issues/118)
**Date:** 2026-06-22
**Status:** Design approved; ready for implementation plan
**Approach:** A — stateless formatter (keep `CodeContext.code` raw)

## Problem / Root Cause

The verifier prompt presents an **absolute** flagged-line number (`finding.start_line`,
e.g. 62) next to an **unnumbered** code block whose file offset is never disclosed.
`get_context()` computes the slice's absolute start (`CodeContext.start_line`), but the
engine passes only `context_result.code` to the LLM (`engine.py:1221,1246`) — the anchor
is dropped. The model cannot map "line 62" onto the block, so it counts/guesses, lands on
the wrong physical line, sees the flagged construct "isn't there," and stamps real bugs
**False Positive**.

This is compounded by the system prompt's RULE-SCOPE DISCIPLINE
(`config/prompts/system_prompt.yaml` L59–60): *"first confirm the construct… is present
at the flagged line; if NOT present → False Positive."* With broken anchoring the model
can't see the construct, so this rule actively drives the wrong verdict.

The existing `_window_around_line` helper (`prompts.py:18`) tries to number lines but
(a) only fires when a rule sets `snippet_window_lines`, and (b) conflates snippet-relative
vs absolute numbering (`start = target_line - window` assumes snippet-line == file-line),
so it no-ops or mis-numbers on function slices.

**Confirmed instance:** dvcp `imgRead.c:62`, `cpp/double-free` — VHX emitted FP @0.88:
*"the flagged line imgRead.c:62 is an array read from buff3, not a free(buff1) call."* It
located the wrong line. Meta-audit confirmed line 62 **is** `free(buff1)` and the bug is
real.

## Goal / Success Criteria ("Done when")

1. The verifier always receives code with **correct absolute per-line numbers** and the
   flagged line marked.
2. When the flagged line is **not** within the provided slice, the model returns **Needs
   More Data** (requesting the correct slice), never False Positive for invisibility.
3. The 6 issue-#118 findings are **no longer dismissed on wrong-line grounds** on re-run.

## Scope

**In:** deterministic numbering renderer; thread the absolute anchor through the call
chain; quote-and-confirm guard in the system prompt (yaml + built-in default);
fold/remove the buggy `_window_around_line`.

**Out (flagged for a separate issue):** `_resolve_path` ignores `repo_name`
(`extractor.py:141`) → a *different* misalignment (wrong file, not wrong line); harmless on
the 1-repo-per-lang benchmark, so kept out to stay surgical.

## Design (Approach A — stateless formatter)

### Component 1 — `render_code_for_prompt(code, start_line, flagged_line, window=None) -> str`

New pure function in `prompts.py`:

- Numbers each line `f"{n}: {text}"` with **absolute** numbers derived from `start_line`.
- Marks the flagged line: `→ {n}: {text}`; others aligned ` {n}: {text}`.
- If `flagged_line ∉ [start_line, start_line+len-1]`: no marker; prepend
  `// NOTE: flagged line {flagged_line} is NOT within this slice (lines {start}-{end}); request the enclosing function.`
  This feeds the guard's NMD path for wrong-bounds cases.
- If `window` given (from `questions.snippet_window_lines`): trim to ±window around the
  flagged line, then number. **Subsumes `_window_around_line`, which is removed** (orphaned
  by this change).
- Total function: empty code / `start_line <= 0` → safe fallback; never raises.

### Component 2 — Thread the anchor (one new default-safe param)

Add `context_start_line: int = 1` to:
- `build_user_prompt` (`prompts.py:224`)
- `analyze` (`client.py:313`)
- `analyze_with_voting` (`client.py:729`)
- the internal sample-analyzer (`client.py:~960`)

`_build_prompt` embeds
`render_code_for_prompt(context, context_start_line, finding.start_line, questions.snippet_window_lines)`
inside `<code_under_review>`. The two engine sites (`engine.py:1219,1244`) pass
`context_start_line=context_result.start_line`. The default keeps existing positional
callers (`test_framework.py:224,251`) working.

### Component 3 — Quote-and-confirm guard

Edit `config/prompts/system_prompt.yaml` (the loaded source of truth) and mirror in
`DEFAULT_SYSTEM_PROMPT`:

- Prepend methodology **Step 0**: *"Locate the flagged line by its number in the numbered
  code block and quote its exact text. Confirm the rule's construct is present on THAT line
  before any further analysis."*
- Revise RULE-SCOPE DISCIPLINE (L59–60): keep *construct genuinely absent on a line you can
  SEE → False Positive*; add *cannot locate the flagged line / it is marked NOT-within-slice
  → **Needs More Data** + request the correct slice; do NOT return False Positive for
  invisibility.*

### Data flow

```
engine._verify_single_finding
  context_result = get_context(...)                  # .code (raw) + .start_line (absolute)
  llm_client.analyze[_with_voting](
      finding, context=context_result.code,
      context_start_line=context_result.start_line,  # NEW
      func_name=context_result.function_name, ...)
    -> build_user_prompt(..., context_start_line)    # NEW param
        -> render_code_for_prompt(code, context_start_line, finding.start_line, window)
        -> <code_under_review>{numbered + marked}</code_under_review>
  system prompt: + Step-0 locate&quote, + FP/NMD split
```

## Error Handling

- Renderer is total (never raises): out-of-range flagged line → NOTE, not crash; bad
  `start_line` → safe fallback.
- New param defaults keep every existing caller and test green.
- `CodeContext.code` stays **raw** → `snippet_provider`, `SlicedContextExtractor`,
  `_extract_sink_callees` are untouched.

## Testing

**Deterministic (no LLM)** — new `tests/test_prompt_code_numbering.py`:
- numbering correctness: slice starting at file line 40, flagged 62 → each line's absolute
  number correct; flagged line marked + exact content.
- out-of-slice: flagged line beyond slice → NOTE present, no marker.
- window composition: `window=N` → trimmed range + correct absolute numbers + header.
- guard text present in the rendered system prompt.
- regression: existing `test_framework.py`, `test_verification_engine.py`,
  `test_llm_client*.py` still pass.

**Behavioral (LLM — the "Done when"):**
- re-verify the 6 findings: dvcp `imgRead.c:62` (`repos/c/dvcp`); DVWA blind-SQLi
  `high.php:33` / `medium.php:34` / `low.php:32`; NodeGoat `server.js:78`;
  bad-python-extract `server.py:93`. Data is on disk under `repos/` + `output/`. Requires
  the LLM proxy live. Confirm none are dismissed on wrong-line grounds.

## Files touched

- `src/vuln_hunter_x/llm/prompts.py` — add `render_code_for_prompt`; remove
  `_window_around_line`; `build_user_prompt` + param + embed; mirror guard in
  `DEFAULT_SYSTEM_PROMPT`.
- `config/prompts/system_prompt.yaml` — Step-0 + FP/NMD split (the version that ships).
- `src/vuln_hunter_x/llm/client.py` — + `context_start_line` on `analyze`,
  `analyze_with_voting`, internal analyzer.
- `src/vuln_hunter_x/verification/engine.py` — 2 call sites pass `context_result.start_line`.
- `tests/test_prompt_code_numbering.py` (new); possibly `tests/test_framework.py`.

## Decisions log (user-approved)

- **Scope** = numbering + flagged-line marker **+ quote-and-confirm guard**.
- **Verification** = unit tests + targeted re-run of the 6 findings.
- **Approach** = A (stateless formatter); keep `CodeContext.code` raw.
- **Marker style** = `→ 62:` gutter; **remove** `_window_around_line` rather than patch it.
