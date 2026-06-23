# Fix #118 — Behavioral Re-run Results (Task 5 acceptance)

**Date:** 2026-06-22
**Branch:** `fix/118-anchored-code-slice`
**Model:** `openai/gpt-5.5` (same model as the 2026-06-19 baseline — only the prompt/code changed)
**Scope:** Targeted flagship slice — `c/dvcp` (5 findings) + `python/bad-python-extract` (1 finding). The larger affected apps (DVWA blind-SQLi ×3 in 72 findings; NodeGoat CSRF in 17 findings) were **not** re-run here (cost); see "Not yet run".
**Baseline preserved at:** `.superpowers/sdd/task5-baseline/` (pre-fix per-finding verdicts).

## Flagship findings — before vs after

| Finding | Before (pre-fix) | After (post-fix) |
|---|---|---|
| `imgRead.c:62` · `cpp/double-free` | **False Positive** / High / 0.88 — *"the flagged line imgRead.c:62 is an array read from `buff3`, not a `free(buff1)` call … mis-anchored to a line where the reported construct is absent."* | **True Positive** / High / 0.95 — *"the relevant two frees are exactly imgRead.c:59 and imgRead.c:62, both in `ProcessImage` … this is a real CWE-415 double-free."* |
| `server.py:93` · `py/flask-debug` | **False Positive** / Medium / 0.7 — *"the reported construct is not present … no debug-mode sink is available in the provided analysis scope."* | **Needs More Data** / High / 0.99 — *"the flagged line 93 is missing from the provided slice. **Per the required methodology, when the flagged line is not present, the correct verdict is Needs More Data rather than False Positive.**"* |

Both findings **stopped being dismissed on wrong-line grounds** — satisfying the spec's "Done when" criteria #2 (flagged line not in slice → NMD, not FP) and #3 (no wrong-line dismissal). The `server.py:93` reasoning quotes the Step-0 guard verbatim, demonstrating the guard (not only the numbering) is driving the behavior change.

## dvcp full regression check (all 5 findings)

| Finding | Before | After | Note |
|---|---|---|---|
| `double-free :62` | FP / 0.88 | **TP / 0.95** | ✅ flagship #118 case fixed |
| `use-after-free :67` | TP / 0.88 | TP / 0.99 | stable (correct) |
| `invalid-pointer-deref :91` | TP / 0.95 | TP / 0.92 | stable (correct) |
| `invalid-pointer-deref :95` | TP / 0.95 | TP / 0.95 | stable (correct) |
| `path-injection :132` | NMD / 0.6 | FP / 0.78 | ✅ over-hedge resolved to the meta-audit's confirmed not-real verdict |

**No regressions.** Every change is an improvement or stable; the three already-correct True Positives held.

## Verdict

The fix works behaviorally on the flagship cases. The numbering removes the wrong-line miscount (`:62` FP→TP) and the guard correctly converts "can't see the flagged line" into Needs-More-Data instead of a false dismissal (`server.py:93` FP→NMD, citing the methodology).

## Not yet run (deferred — cost)

- DVWA blind-SQLi ×3: `vulnerabilities/sqli_blind/source/{high.php:33, medium.php:34, low.php:32}` — re-verifying requires the DVWA app (~72 findings).
- NodeGoat CSRF: `server.js:78` — ~17 findings.

To complete full Task-5 coverage of all 6 issue-#118 findings, re-run:
```
.venv/bin/vuln-hunter-x verify --local-path repos/php/dvwa --lang php --max-iterations 5 -j 4
.venv/bin/vuln-hunter-x verify --local-path repos/javascript/nodegoat --lang javascript --max-iterations 5 -j 4
```
(Back up `output/<lang>/<app>/verification_results` first; both overwrite in place.)
