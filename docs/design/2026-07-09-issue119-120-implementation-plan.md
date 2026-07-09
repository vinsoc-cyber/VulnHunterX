# Impact-first verdict (#119 + #120) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:test-driven-development. Every production
> change gets a failing test first (RED), watched fail, then minimal code (GREEN). Steps use `- [ ]`.

**Goal:** Make the verifier decide by *concrete consequence at the flagged sink* — not by construct
presence (#119, over-confirm) nor by CWE-name match (#120, over-dismiss).

**Architecture:** Three surgical levers — retune `_FORCE_DECISION_PROMPT` (Lever 1, client.py), reframe
RULE-SCOPE DISCIPLINE in the live YAML + Python fallback (Lever 2), retire the `_check_rule_construct_presence`
CWE enforcer (Lever 3, engine.py). Design: `docs/design/2026-07-09-issue119-120-impact-first-verdict-design.md`.

**Tech Stack:** Python 3.12, pytest, litellm; `benchmark/` versionab mode for acceptance.

## Global Constraints

- Tests via `.venv/bin/python -m pytest --no-cov` (system python lacks the pkg); always
  `--ignore tests/test_recall_1192_services.py` (breaks collection).
- Surgical: touch only the four files below; match existing style; delete only what these changes orphan.
- Prompt edits must go in **both** the live YAML (`config/prompts/system_prompt.yaml`) and the Python
  fallback (`src/vuln_hunter_x/llm/prompts.py` `DEFAULT_SYSTEM_PROMPT`) — they must stay in sync.
- Benchmark: default config `openai-gpt-5.5-temp0-iter5`; same provider/model/temp/max_iter/panel_hash as
  baseline C (`8a63259`) → no confound-guard abort.

## File Structure
- `src/vuln_hunter_x/verification/engine.py` — remove enforcer + 2 helpers + call site (Lever 3).
- `src/vuln_hunter_x/llm/client.py` — retune `_FORCE_DECISION_PROMPT` guideline (Lever 1).
- `config/prompts/system_prompt.yaml` — reframe RULE-SCOPE DISCIPLINE, live (Lever 2).
- `src/vuln_hunter_x/llm/prompts.py` — same reframe in `DEFAULT_SYSTEM_PROMPT` (Lever 2 sync).
- `tests/test_calibration_fixes.py` — retirement test; drop import (line 29) + `TestRuleScopeConstructPresence`.
- `tests/test_prompt_code_numbering.py` — prompt intent-lock + sync tests.

---

### Task 1: Lever 3 — retire the CWE-class enforcer

**Files:** Modify `src/vuln_hunter_x/verification/engine.py`, `tests/test_calibration_fixes.py`.
**Interfaces:** Removes module-level `_check_rule_construct_presence`, `_CWE_CLASS_MARKERS`,
`_cwe_classes_in_text` from `engine`. No other module imports them (verified).

- [ ] **Step 1: Write the failing test** — add to `tests/test_calibration_fixes.py` (module level, where
  `TestRuleScopeConstructPresence` was):

```python
def test_rule_scope_enforcer_is_retired():
    # #120: the rule locates a sink, it is not a straitjacket. The CWE-class
    # enforcer that downgraded any cross-class TP is retired, with its helpers.
    import vuln_hunter_x.verification.engine as engine
    assert not hasattr(engine, "_check_rule_construct_presence")
    assert not hasattr(engine, "_CWE_CLASS_MARKERS")
    assert not hasattr(engine, "_cwe_classes_in_text")
```

- [ ] **Step 2: Run it, verify RED**
  Run: `.venv/bin/python -m pytest --no-cov tests/test_calibration_fixes.py::test_rule_scope_enforcer_is_retired -q`
  Expected: FAIL — the three symbols still exist (assertion error, not import error).

- [ ] **Step 3: GREEN — remove the production symbols and the obsolete tests together.**
  In `engine.py` delete: the comment + `_CWE_CLASS_MARKERS` dict (`:514-528`), `_cwe_classes_in_text`
  (`:531-532`), `_check_rule_construct_presence` (`:535-570`), and the call + its two-line comment at
  `:1359-1361`:
```python
        # Rule-scope discipline: a TP whose reasoning argues a CWE class other
        # than the one the rule reported is out of scope — downgrade it.
        verdict = _check_rule_construct_presence(verdict)
```
  In `tests/test_calibration_fixes.py` delete `    _check_rule_construct_presence,` from the import block
  (`:29`) and delete the whole `class TestRuleScopeConstructPresence:` (its 4 tests exercise removed code).

- [ ] **Step 4: Verify GREEN**
  Run: `.venv/bin/python -m pytest --no-cov tests/test_calibration_fixes.py -q`
  Expected: PASS (retirement test green; no import error; the two surviving calibrators untouched).

- [ ] **Step 5: Commit**
```bash
git add src/vuln_hunter_x/verification/engine.py tests/test_calibration_fixes.py
git commit -m "fix(verifier): retire CWE-class rule-scope enforcer (#120)

The rule locates a suspicious sink; it does not fix the verdict's class.
Drop _check_rule_construct_presence + _CWE_CLASS_MARKERS + _cwe_classes_in_text
(the downgrade that dismissed a real same-sink bug for a CWE-name mismatch)."
```

---

### Task 2: Lever 1 — impact-first force-decision prompt

**Files:** Modify `src/vuln_hunter_x/llm/client.py`, `tests/test_prompt_code_numbering.py`.

- [ ] **Step 1: Write the failing test** — add to `tests/test_prompt_code_numbering.py`:

```python
def test_force_decision_prompt_is_consequence_first():
    from vuln_hunter_x.llm.client import LLMClient
    fd = LLMClient._FORCE_DECISION_PROMPT
    assert "lean toward True Positive" not in fd            # old absence-of-defense thumb gone
    assert "decide by CONSEQUENCE at the flagged sink" in fd  # new impact-first guideline
    assert "EXCEPTION for correctness" in fd                # correctness-rule carve-out preserved
```

- [ ] **Step 2: Run it, verify RED**
  Run: `.venv/bin/python -m pytest --no-cov "tests/test_prompt_code_numbering.py::test_force_decision_prompt_is_consequence_first" -q`
  Expected: FAIL — "lean toward True Positive" still present; new phrase absent.

- [ ] **Step 3: GREEN** — in `client.py` `_FORCE_DECISION_PROMPT`, replace ONLY the `GUIDELINE:` sentence
  (`:1139-1141`), leaving the "You MUST choose … NMD is NOT acceptable" intro and the `EXCEPTION` block intact:
```python
        "GUIDELINE (decide by CONSEQUENCE at the flagged sink, not by absence of a defense): "
        "choose True Positive only when you can name a concrete, attacker-reachable consequence "
        "at the flagged sink — a real exploit path with real impact (code/command execution, "
        "data disclosure, memory corruption, auth bypass). The mere ABSENCE of a visible "
        "sanitizer, guard, or framework protection is NOT sufficient for True Positive. Choose "
        "False Positive when a specific defense makes the path safe, OR when the flagged construct "
        "carries no real security consequence even though it matches the rule — e.g. a permissive "
        "header with nothing sensitive behind it, a loose comparison with no secret operand, a "
        "value that is only logged or printed, or an operator/CLI-controlled source with no trust "
        "boundary.\n\n"
```

- [ ] **Step 4: Verify GREEN**
  Run: `.venv/bin/python -m pytest --no-cov "tests/test_prompt_code_numbering.py::test_force_decision_prompt_is_consequence_first" tests/test_calibration_fixes.py -q`
  Expected: PASS (force-decision behavior tests in `test_calibration_fixes.py` still green — they assert
  NMD/commit handling, not the guideline wording).

- [ ] **Step 5: Commit**
```bash
git add src/vuln_hunter_x/llm/client.py tests/test_prompt_code_numbering.py
git commit -m "fix(verifier): force-decision leans on consequence, not absence of defense (#119)"
```

---

### Task 3: Lever 2 — rule-as-locator system prompt (YAML + Python sync)

**Files:** Modify `config/prompts/system_prompt.yaml`, `src/vuln_hunter_x/llm/prompts.py`,
`tests/test_prompt_code_numbering.py`.

- [ ] **Step 1: Write the failing tests** — add to `tests/test_prompt_code_numbering.py`:

```python
def test_system_prompt_rule_is_locator_not_straitjacket():
    sp = PromptBuilder().get_system_prompt(tool_name="Semgrep", lang="php")  # live (YAML)
    assert "LOCATES a suspicious sink" in sp
    assert 'NEVER return "True Positive" for a vulnerability class other than' not in sp
    assert "LOCATE the flagged line" in sp and "Needs More Data" in sp  # #118 guards preserved

def test_rule_scope_reframe_synced_yaml_and_fallback():
    sp = PromptBuilder().get_system_prompt(tool_name="Semgrep", lang="php")
    for text in (sp, DEFAULT_SYSTEM_PROMPT):
        assert "LOCATES a suspicious sink" in text
        assert "do not relabel" not in text
        assert 'NEVER return "True Positive" for a vulnerability class other than' not in text
```

- [ ] **Step 2: Run them, verify RED**
  Run: `.venv/bin/python -m pytest --no-cov "tests/test_prompt_code_numbering.py::test_system_prompt_rule_is_locator_not_straitjacket" "tests/test_prompt_code_numbering.py::test_rule_scope_reframe_synced_yaml_and_fallback" -q`
  Expected: FAIL — old "NEVER return …"/"do not relabel" present; "LOCATES a suspicious sink" absent.

- [ ] **Step 3: GREEN — replace the `RULE-SCOPE DISCIPLINE:` block in BOTH files.**
  `config/prompts/system_prompt.yaml` (`:65-68`, 2-space YAML indent, `  - ` bullets) and
  `src/vuln_hunter_x/llm/prompts.py` `DEFAULT_SYSTEM_PROMPT` (`:121-124`, `- ` at column 0) — identical
  text, only the indent differs:
```text
RULE-SCOPE DISCIPLINE:
- The reported rule LOCATES a suspicious sink; it does not fix the verdict's vulnerability class. Judge whether the FLAGGED SINK (the flagged line and the dataflow reaching it) is genuinely, exploitably dangerous. First confirm, per step 0, that the construct the rule points at is present at the flagged line.
- If the flagged sink is genuinely exploitable, return "True Positive" even when its precise class differs from the rule's named CWE — e.g. a tainted filename tagged SSRF that is really a path-traversal / local-file read at that same sink, or a tainted path whose contents reach eval() (LFI -> RCE). Name the real class in your reasoning.
- Do NOT manufacture a True Positive from an UNRELATED problem elsewhere: a different bug at a different line/dataflow than the flagged sink does not confirm THIS finding — mark "False Positive" for this finding.
- Distinguish two look-alike cases with OPPOSITE verdicts: (a) you can SEE the flagged line and the sink is genuinely benign — the rule's construct is absent, or present-but-harmless (e.g. an integer-multiplication rule whose flagged line has no multiplication; a sizeof whose result is only printed) → "False Positive"; (b) you canNOT locate the flagged line in the provided code, or it is marked as outside the slice → "Needs More Data" and request the enclosing function — never "False Positive" merely because the construct is not visible.
```

- [ ] **Step 4: Verify GREEN**
  Run: `.venv/bin/python -m pytest --no-cov tests/test_prompt_code_numbering.py tests/test_framework.py -q`
  Expected: PASS (new tests green; existing `test_system_prompt_*` in both files still green — step-0
  locate + NMD guards are retained by the reframe).

- [ ] **Step 5: Commit**
```bash
git add config/prompts/system_prompt.yaml src/vuln_hunter_x/llm/prompts.py tests/test_prompt_code_numbering.py
git commit -m "fix(verifier): rule locates a sink, not its verdict class (#120)"
```

---

### Task 4: Integration — blast-radius green + versionab A/B benchmark (acceptance)

**Files:** none (produces `benchmark/result/version_ab/1.0.0@<new-sha>/` + compare report; committed after).

- [ ] **Step 1: Full blast radius green**
  Run: `.venv/bin/python -m pytest --no-cov --ignore tests/test_recall_1192_services.py tests/test_calibration_fixes.py tests/test_prompt_code_numbering.py tests/test_framework.py tests/test_llm_client.py tests/test_context_extractor.py -q`
  Expected: all PASS, output pristine.

- [ ] **Step 2: Run the versionab A/B benchmark** (version D = new HEAD sha; auto-compares to C `8a63259`)
  Run: `.venv/bin/python benchmark/src/benchmark.py versionab --force`
  Expected: completes across all panels; produces D baseline + `compare_vs` report. (~$15, long-running —
  monitor, do not busy-wait.)

- [ ] **Step 3: Verify success criteria against the compare report**
  Check: recall ↑ (the `tainted-filename` DVWA cluster `view_help :20/:22`, `view_source :63/:68`,
  `view_source_all :14/18/22/26` flip MISS→TP; `view_source` siblings consistent); precision flat-or-↑
  (permissive-CORS pair, the two md5-loose-equality no-secret cases flip FALSE-ALARM→correct-FP); #118
  wins held (`imgRead.c:62`, `sqli_blind` ×3, `server.js:78` stay TP). Any net regression → documented reason.

- [ ] **Step 4: Commit the benchmark artifacts**
```bash
git add benchmark/result/version_ab/
git commit -m "bench(versionab): version D vs C — impact-first verdict A/B (#119, #120)"
```

## Self-Review
- **Spec coverage:** Levers 1/2/3 → Tasks 2/3/1; validation → Task 4. All spec "Files touched" covered.
- **Placeholders:** none — every step has exact test code, exact replacement text, exact commands.
- **Type/name consistency:** symbol names (`_FORCE_DECISION_PROMPT`, `_check_rule_construct_presence`,
  `_CWE_CLASS_MARKERS`, `_cwe_classes_in_text`, `DEFAULT_SYSTEM_PROMPT`, `PromptBuilder.get_system_prompt`)
  match the source read at HEAD `8cd0e9c`.
