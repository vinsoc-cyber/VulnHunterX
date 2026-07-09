# Impact-first verdict — #119 (over-confirm) + #120 (CWE-tunnel over-dismiss)

**Date:** 2026-07-09
**Status:** Design approved (approach A: full relax + retire enforcer); ready for implementation plan
**Addresses:** #119 (confirms the construct without checking impact) + #120 (CWE-label tunnel vision
dismisses a real bug). Partially dissolves #122 (several self-contradictions resolve as a side effect).
**Builds on (keeps):** the #118 follow-up (`8cd0e9c` — slice containment + honest NMD). That fixed the
*input* (the flagged line is in the slice) and killed the *engine* force-promotion. This fixes the
*judgment rule* — what verdict a correctly-sliced finding warrants.

## Background

The #118 work established that VHX had two mirror-image miscalibrations. #118/its follow-up fixed the
over-*dismissal* caused by a bad slice. The independent source audit of the merged version
(`1.0.0@8a63259`, 125 findings) found the two remaining, still-open judgment errors — and they are the
**same root cause pulling in opposite directions**:

- **#119 — over-confirm (hurts precision, ~15 findings).** The verifier emits True Positive as soon as
  the flagged *construct* is present, with no check for a real consequence or an effective guard.
- **#120 — over-dismiss (hurts recall, ~11 findings).** The verifier dismisses a real bug at the flagged
  sink because its precise class does not match the rule's *named* CWE.

Both stem from letting **construct/label presence** drive the verdict instead of **the concrete
consequence at the flagged sink**. Because they pull opposite ways, fixing one alone swings the bias the
other way — exactly the "version B moved the bias" failure #118 spent effort undoing. There is hard
evidence of the swing: `dvcp imgRead.c:132` was the #121 over-hedge (NMD) in the issue; in `8a63259` it is
now a #119 over-confirm (TP). So the two are fixed **together**, with the A/B benchmark as the arbiter.

**#120 is partly deliberate design, not a pure bug.** An explicit prompt rule and an engine enforcer
forbid "relabeling." That guard exists for a real reason — stop the model confirming a finding by pointing
at an *unrelated* vuln — but it over-rotates into dismissing genuinely-dangerous flagged sinks. The fix
must keep the anti-*unrelated-relabel* guard while dropping the CWE-name straitjacket.

## Root cause (three levers, quoted from HEAD `8cd0e9c`)

**Lever 1 — #119: the forced-decision prompt biases toward TP on absence-of-defense.**
`LLMClient._FORCE_DECISION_PROMPT` (`src/vuln_hunter_x/llm/client.py:1134-1150`):

> "GUIDELINE: If the code handles untrusted input and you see NO clear sanitization, bounds checking,
> or framework protection, **lean toward True Positive** … Only choose False Positive if you can point
> to a specific defense."

The #118 follow-up stopped the *engine* keyword-promoting NMD→TP, but this prompt still tells the **model**
that "no visible defense ⇒ TP." The audit's over-confirms quote it verbatim ("under the final instruction
… the balance of evidence leans True Positive"). The block already carries an `EXCEPTION` for
correctness/type-hygiene rules that is *impact-first* (requires operands to "realistically reach values
that overflow … AND the result is used dangerously") — the fix generalises that stance.

**Lever 2 — #120: the system prompt forbids any cross-class TP.**
`config/prompts/system_prompt.yaml:65-68` (the **live** prompt; the Python `DEFAULT_SYSTEM_PROMPT`
at `src/vuln_hunter_x/llm/prompts.py:121-124` is a byte-identical fallback):

> "If you find a DIFFERENT kind of problem (e.g. a path-traversal concern under an integer-overflow
> rule), that does NOT make this finding a True Positive … mark 'False Positive' … do not relabel.
> NEVER return 'True Positive' for a vulnerability class other than the one the rule reported."

This is the tunnel. On DVWA, `tainted-filename` carries **both CWE-918 (SSRF) and CWE-22/73
(path-traversal)** (`config/rule_categories.yaml:270-276`); the model sees "SSRF," applies an SSRF-only
test, and dismisses a real LFI/path-traversal read at the exact flagged sink — *while acknowledging the
danger in its own text*.

**Lever 3 — #120: an engine enforcer damps cross-class TPs.**
`_check_rule_construct_presence` (`src/vuln_hunter_x/verification/engine.py:535-570`, called once at
`:1361`) downgrades a TP to Low confidence when the reasoning's CWE markers (`_CWE_CLASS_MARKERS`,
`:517-528`) are off-scope vs the rule's CWE. Its premise — reasoning-class must equal rule-class — *is* the
tunnel vision. With Lever 2 relaxed it would fight the prompt. Its two helpers (`_CWE_CLASS_MARKERS`,
`_cwe_classes_in_text`) are used **only** here.

**Why the fix is measurable — the oracle keys on `(rule_id, file, line)`, not CWE class**
(`benchmark/src/modes/version_ab.py:66,118`). The DVWA `ground_truth.json` already lists the #120 sinks as
**real**, so they are counted as recall today and missed:

| finding (rule@file:line) | oracle | VHX @ `8a63259` | after fix |
|---|---|---|---|
| `tainted-filename@…/view_help.php:20` / `:22` | real | **FP** (miss) | → TP |
| `tainted-filename@…/view_source.php:63` / `:68` | real | **FP** (miss) | → TP |
| `tainted-filename@…/view_source_all.php:14/18/22/26` | real | **FP** (miss) | → TP |
| `tainted-filename@…/view_source.php:67` | real | TP | TP (already right; siblings become consistent) |
| `eval-use@…/view_help.php:20` / `:22` | real | TP | TP — same sink already confirmed under `eval-use`; only its SSRF-labeled `tainted-filename` twin is dismissed (the tunnel, in one line) |

Symmetrically, #119 targets are **not** in the oracle (not-real) yet confirmed today — flipping them
TP→FP raises precision: `php-permissive-cors@…/gen_openapi.php:6` & `…/public/index.php:11`,
`md5-loose-equality@…/captcha/…/impossible.php:46` & `…/javascript/index.php:43`,
`cpp/suspicious-sizeof@…/practice/decay.cpp:5`, `cpp/path-injection@imgRead.c:132`.

## Goal / success criteria ("done when")

Measured on the frozen `versionab` panel, version D (new sha) vs C (`8a63259`):

1. **Recall ↑** — the #120 DVWA cluster (`view_help`, `view_source :63/:68`, `view_source_all`) flips
   FN→TP; the `view_source.php` sibling inconsistency (`:63/:68` vs `:67`) resolves to all-TP.
2. **Precision flat-or-↑** — the #119 not-real over-confirms (permissive-CORS pair, the two no-secret
   md5-loose-equality cases, `decay.cpp:5`, `imgRead.c:132`) flip TP→FP.
3. **No previously-sound TP lost** — the #118 wins hold: `imgRead.c:62` double-free, `sqli_blind` ×3,
   `server.js:78` stay TP (each has a locally-demonstrable consequence, so impact-first keeps them).
4. **The anti-unrelated-relabel guard survives** — a verdict that argues a bug at a *different* line/flow
   than the flagged sink still returns FP for the reported finding (deterministic unit test).
5. **Net: recall ↑ AND precision flat-or-↑** on the compare report. Any net regression is accompanied by
   a defensible, documented reason (e.g. a genuinely not-locally-decidable finding honestly moving off TP).
6. A final full `versionab` A/B benchmark (D vs C, and vs B/A) is produced with its compare report.

## Scope

**In:**
- Lever 1 — retune `_FORCE_DECISION_PROMPT` from "no defense ⇒ lean TP" to impact-first (`client.py`).
- Lever 2 — reframe RULE-SCOPE DISCIPLINE: the rule *locates a sink*; a genuinely exploitable **flagged
  sink** is TP regardless of the rule's CWE name; an **unrelated** problem **elsewhere** stays FP. Apply
  to the **live YAML and the Python fallback** (keep them in sync).
- Lever 3 — retire `_check_rule_construct_presence` and its two now-orphaned helpers (`engine.py`).
- Deterministic unit tests; prune/rewrite tests tied to the removed enforcer.

**Out (flagged, not done here):**
- #121 cross-file context fetching (a capability, not a calibration) — e.g. the NodeGoat `user-dao.js`
  NoSQL-injection sinks whose attacker-controlling caller lives in another file. The rule-as-locator
  reframe may help, but resolving them reliably needs cross-file source and is a separate effort.
- #122's general reconciliation pass — this fix dissolves several contradictions but adds no post-hoc
  grouping step.
- The ice C++ `if_constexpr` `#define constexpr` misread (a compile-time-vs-runtime reasoning gap) — the
  reframe may help, but it is not a guaranteed target of this change.
- Adding a *structured* same-sink location check to the engine (the "unrelated-elsewhere" guard now lives
  in the prompt) — future hardening if the benchmark shows a precision leak.

## Design

### Lever 1 — impact-first force decision (`client.py:1134-1150`)

Replace **only** the `GUIDELINE:` sentence (the absence-of-defense→TP thumb). Keep the "you MUST choose
TP or FP / NMD is not a final response" framing (the turn's purpose; the engine already honors a returned
NMD after the #118 follow-up) and keep the correctness-rule `EXCEPTION` verbatim (already impact-first).

New guideline (decide by consequence, symmetric):

```text
GUIDELINE (decide by CONSEQUENCE at the flagged sink, not by absence of a defense):
Choose True Positive only when you can name a concrete, attacker-reachable consequence at the
flagged sink — a real exploit path with real impact (code/command execution, data disclosure,
memory corruption, auth bypass, ...). The mere ABSENCE of a visible sanitizer, guard, or framework
protection is NOT sufficient for True Positive. Choose False Positive when a specific defense makes
the path safe, OR when the flagged construct carries no real security consequence even though it
matches the rule — e.g. a permissive header with nothing sensitive behind it, a loose comparison
with no secret operand, a value that is only logged/printed, or an operator/CLI-controlled source
with no trust boundary.
```

### Lever 2 — rule as locator, not straitjacket (`system_prompt.yaml:65-68` + `prompts.py:121-124`)

Replace the RULE-SCOPE DISCIPLINE block in **both** files with:

```text
RULE-SCOPE DISCIPLINE:
- The reported rule LOCATES a suspicious sink; it does not fix the verdict's vulnerability class.
  Judge whether the FLAGGED SINK (the flagged line and the dataflow reaching it) is genuinely,
  exploitably dangerous. First confirm, per step 0, that the construct the rule points at is present
  at the flagged line.
- If the flagged sink is genuinely exploitable, return "True Positive" even when its precise class
  differs from the rule's named CWE — e.g. a tainted filename tagged SSRF that is really a
  path-traversal / local-file read at that same sink, or a tainted path whose contents reach eval()
  (LFI -> RCE). Name the real class in your reasoning.
- Do NOT manufacture a True Positive from an UNRELATED problem elsewhere: a different bug at a
  different line/dataflow than the flagged sink does not confirm THIS finding -> "False Positive".
- Two look-alike cases with OPPOSITE verdicts: (a) you can SEE the flagged line and the sink is
  genuinely benign — the rule's construct is absent, or present-but-harmless (e.g. an
  integer-multiplication rule whose flagged line has no multiplication; a sizeof whose result is only
  printed) -> "False Positive"; (b) you canNOT locate the flagged line, or it is marked outside the
  slice -> "Needs More Data" and request the enclosing function — never "False Positive" merely
  because the construct is not visible.
```

This drops the absolute "NEVER TP for another class" / "do not relabel" while **preserving** step-0 locate,
the benign-sink→FP case, and the can't-see→NMD case (all #118 territory).

### Lever 3 — retire the CWE-class enforcer (`engine.py`)

- Delete the call `verdict = _check_rule_construct_presence(verdict)` at `engine.py:1361`.
- Delete `_check_rule_construct_presence` (`:535-570`) and its now-orphaned helpers `_CWE_CLASS_MARKERS`
  (`:517-528`) and `_cwe_classes_in_text` (`:531-532`).
- The sibling calibrators in the chain (e.g. the CLI-argv-source downgrade at `:505`) are unrelated and
  stay untouched.

## Testing

**Deterministic (no LLM):**
- **Enforcer retirement (the RED→GREEN centerpiece):** in `tests/test_calibration_fixes.py`, construct a
  `Verdict` (TP / High) whose `finding.cwe_ids=["CWE-918"]` and whose reasoning argues "path traversal",
  run it through the public calibrator entry point that contained the `:1361` call, and assert confidence
  stays **High** (pre-fix this downgraded to Low). Assert `_check_rule_construct_presence` /
  `_CWE_CLASS_MARKERS` no longer exist on the module (removal + no-orphan guard). Remove/rewrite any
  existing test that asserted the old downgrade.
- **Prompt intent locks (guard against silent revert):** assert `_FORCE_DECISION_PROMPT` no longer
  contains "lean toward True Positive" and now contains the consequence-first phrasing; assert the live
  YAML system prompt no longer contains "NEVER return \"True Positive\" for a vulnerability class other
  than" and contains "LOCATES a suspicious sink"; assert the YAML and the Python fallback RULE-SCOPE block
  match (sync guard).
- Run the blast radius green (`.venv/bin/python -m pytest --no-cov`,
  `--ignore tests/test_recall_1192_services.py`): `test_calibration_fixes.py`, `test_llm_client.py`,
  `test_prompt_*.py`, and any engine calibrator test.

**Behavioral (LLM) — the real proof:**
- Targeted dev re-run of the #119/#120 findings above; confirm the flip directions in goals 1-2 and the
  guard in goal 4.
- Acceptance: final full `versionab` A/B benchmark (goal 6).

## Files touched
- `src/vuln_hunter_x/llm/client.py` — retune `_FORCE_DECISION_PROMPT` guideline (Lever 1).
- `config/prompts/system_prompt.yaml` — reframe RULE-SCOPE DISCIPLINE (Lever 2, live).
- `src/vuln_hunter_x/llm/prompts.py` — same reframe in the `DEFAULT_SYSTEM_PROMPT` fallback (Lever 2, sync).
- `src/vuln_hunter_x/verification/engine.py` — retire `_check_rule_construct_presence` + orphaned helpers (Lever 3).
- `tests/test_calibration_fixes.py` — enforcer-retirement + prompt-intent tests; prune the old downgrade test.
