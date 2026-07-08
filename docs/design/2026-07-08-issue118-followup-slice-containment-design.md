# Verifier slice containment + honest NMD — follow-up to #118

**Date:** 2026-07-08
**Status:** Design approved; ready for implementation plan
**Addresses:** residual #118, #119 (over-confirmed non-bugs), #121 (over-hedges NMD)
**Builds on (keeps):** `docs/design/2026-06-22-issue118-code-slice-design.md` — the absolute
line-numbering renderer is correct and stays; this fixes what it left unaddressed.

## Background

`795e4fd` ("Fix #118: anchored code slice + quote-and-confirm guard") was meant to fix
**#118** — a misaligned/truncated slice makes the verifier conclude the flagged construct
"isn't there," so it stamps real bugs **False Positive** (over-*dismissal*).

An independent, source-grounded A/B audit of `eda2fd0 → 795e4fd` (same model, gpt-5.5 temp 0 —
a prompt/logic change) found the fix **moved the bias instead of removing it**: it converted
over-*dismissal* into over-*confirmation*. Two things shipped:

1. Absolute line-numbering + a flagged-line marker (`render_code_for_prompt`). **Genuinely
   correct** — `dvcp imgRead.c:62` FP→TP is real and validated. Kept.
2. A Step-0 "quote-and-confirm guard" whose own success criterion #2 said: *flagged line not in
   slice → **Needs More Data**, never FP-for-invisibility.* That NMD intent is **silently
   overridden in production** by a pre-existing mechanism (`force_decision`), which keyword-forces
   the NMD to **True Positive**. The DVWA/NodeGoat findings were deferred (never re-run) before
   merge, so this was not caught.

Net effect: on the real-heavy benchmark it reads as +6% recall; on FP-heavy production code it
inverts to a precision loss. The flagged line is **still never seen** — the root cause is unfixed.

## Root cause (reproduced, not inferred)

Two compounding bugs feed every off-slice forced-TP the audit found.

**Bug 1 — `get_context` can return a slice that does not contain the flagged line.**
`ContextExtractor.get_context` (`src/vuln_hunter_x/context/extractor.py:105`) returns the
enclosing-"function" slice from `_find_function_bounds` **without checking the flagged line is
inside it**. The regex fallback (`extractor.py:204`) matches control-flow keywords (`if`, `while`,
`switch`) as function definitions; PHP is **absent from `_FUNCTION_PATTERNS`** (`extractor.py:23`)
so it borrows the C regexes. Reproduced against `repos/` at the pinned SHAs:

| finding | returned slice | `function_name` | contains flagged line? |
|---|---|---|---|
| `dvwa .../sqli_blind/source/high.php:33` | `[19, 26]` | `'if'` | **no** |
| `dvwa .../sqli_blind/source/low.php:32` | `[20, 26]` | `'if'` | **no** |
| `dvwa .../sqli_blind/source/medium.php:34` | `[22, 28]` | `'if'` | **no** |
| `nodegoat server.js:78` | `[31, 35]` | `'if'` | **no** |
| `nodegoat app/routes/index.js:34` (healthy) | `[11, 83]` | `'index'` | yes — unchanged by fix |

The `±context_lines` fallback (`extractor.py:116-124`) *would* contain the line, but the bad
function-bounds branch pre-empts it. The CSV-derived path already enforces containment
(`extractor.py:198`), so only the regex-derived bounds are ever wrong.

**Bug 2 — `_force_decision_turn` keyword-forces TP on the unseen line.**
`LLMClient._force_decision_turn` (`src/vuln_hunter_x/llm/client.py:1204-1250`): when the terminal
verdict is NMD, it counts taint vocabulary (`tp_signals`: `"no validation"`, `"unsafe"`, …) and
promotes to **True Positive**, tagging `[Forced decision: evidence leans toward TP]` at confidence
`Low`. `#118`'s guard correctly makes the model answer NMD-for-invisibility, but this mechanism
overrides it. No challenge arm catches a forced-TP on a taint finding — `engine.py:1294` `arm_b`
only rescues forced-*FP*; `arm_c`/`arm_d` don't cover a Low-confidence forced-TP on a
framework-taint CWE. So it ships unchallenged.

## Goal / success criteria ("done when")

1. `get_context` **always** returns a slice containing the flagged line, for every language,
   whenever the file is readable and `1 <= line <= len(file)`.
2. When the model genuinely cannot see the flagged line and returns NMD, the verdict **stays NMD** —
   never a keyword-forced TP/FP. `force_decision` still breaks genuine ties when the model *did* see
   the line and commits to a side.
3. On a targeted re-run, the audit's off-slice findings resolve on **real evidence**: real
   SQLi/CSRF (`sqli_blind` ×3, `server.js:78`) → TP with sound reasoning; not-real
   (`cryptography/.../ecb_attack.php:92`, `upload/source/impossible.php:54`) → FP. No new
   over-dismissals; `#118`'s real wins hold (`dvcp imgRead.c:62` stays TP).
4. A final full `versionab` A/B benchmark (post-fix version C vs B, and vs A) is produced with its
   compare report.

## Scope

**In:**
- Fix A — containment guard in `get_context` (`extractor.py`).
- Fix C — drop the taint-keyword promotion in `_force_decision_turn`; keep NMD when the model
  re-refuses after the explicit force prompt (`client.py`).
- Deterministic unit tests for both; prune assertions tied to the removed heuristic.

**Out (flagged, not done here):**
- C++ `if_constexpr` / CWE-tunnel-vision regressions (#120) and the demo-vs-deployed Step-0 bar.
- Adding PHP (and other missing-language) function patterns to `_FUNCTION_PATTERNS` — a quality
  follow-up; the containment guard makes *correctness* language-agnostic without it.
- `arm_b` (`engine.py:1294`) becomes practically orphaned once no `[Forced decision:` sentinel is
  emitted — **flagged for a follow-up, not deleted** (surgical-changes rule).
- An FP-heavy validation panel (the audit's recommendation) — separate effort.

## Design

### Fix A — containment guard (`extractor.py:105`)

Add a containment predicate to the function-slice branch; on failure, fall through to the existing
`±context_lines` window:

```python
if (
    func_start is not None
    and func_end is not None
    and func_start + 1 <= line <= func_end + 1   # NEW: the slice must contain the flagged line
):
    code = "\n".join(lines[func_start : func_end + 1])
    return CodeContext(...)                      # unchanged
# else: fall through to the ±context_lines window (extractor.py:116-124),
#       which contains `line` whenever 1 <= line <= len(lines).
```

- Working cases (bounds already contain the line) are **unchanged** → no regression for the
  languages/paths that already work (incl. the CSV path, which enforces containment at `:198`).
- Residual truly-unseeable case (`line > len(lines)`, or unreadable file → `_fallback_context`):
  the window/fallback does not contain the line → `render_code_for_prompt` emits its existing
  out-of-slice NOTE → model answers NMD → **Fix C keeps it NMD**.

### Fix C — honest NMD (`client.py:_force_decision_turn`)

Remove the `tp_signals` / `fp_signals` promotion block (`client.py:1204-1250`). The method still
appends `_FORCE_DECISION_PROMPT` and re-parses:
- Model commits to TP/FP → **respected** (genuine ties break as before).
- Model still returns NMD → **keep NMD** (abstain). No keyword guess in either direction.
- The existing `parse_failed → NMD` short-circuit (`client.py:1194-1203`) is kept.

No `[Forced decision:` sentinel is emitted thereafter.

## Testing

**Deterministic (no LLM) — the "done when" gates for goals 1–2:**
- Context extraction (new `tests/test_context_extractor.py`, or extend `tests/test_framework.py`):
  flagged line is inside the returned slice for — a PHP `if`-block case (`high.php:33`), a JS
  `if`-block case (`server.js:78`), a function-less file, and a line past EOF (window clamps; slice
  does not falsely claim containment). A healthy function case keeps its existing bounds (regression
  guard).
- Force decision (`tests/test_calibration_fixes.py`, `tests/test_llm_client.py`):
  `_force_decision_turn` **keeps NMD** when the forced turn re-parses NMD; **commits** when it parses
  TP or FP; still short-circuits on `parse_failed`. Rewrite
  `TestForcedDecisionAccessControlSignals::test_no_authorization_in_reasoning_promotes_tp` to the new
  contract (NMD preserved, no `[Forced decision:` tag); `test_parse_failure_not_keyword_forced_to_tp`
  is unchanged and still passes.
- Run the blast radius green: the two files above plus `test_treesitter_extractor.py`,
  `test_context_provider.py`, `test_prompt_code_numbering.py`, `test_registry_contract.py`
  (via `.venv/bin/python -m pytest --no-cov`, `--ignore tests/test_recall_1192_services.py`).

**Behavioral (LLM):**
- Targeted re-run (dev): re-verify the audit's affected findings; confirm goal 3.
- Acceptance: final full `versionab` A/B benchmark (goal 4).

## Files touched
- `src/vuln_hunter_x/context/extractor.py` — containment predicate in `get_context`.
- `src/vuln_hunter_x/llm/client.py` — remove the keyword promotion in `_force_decision_turn`.
- `tests/test_context_extractor.py` (new) — containment tests.
- `tests/test_calibration_fixes.py` — rewrite the one promotion test to the new contract.
- (possibly) `tests/test_llm_client.py` — a keep-NMD-when-commit-refused case.
