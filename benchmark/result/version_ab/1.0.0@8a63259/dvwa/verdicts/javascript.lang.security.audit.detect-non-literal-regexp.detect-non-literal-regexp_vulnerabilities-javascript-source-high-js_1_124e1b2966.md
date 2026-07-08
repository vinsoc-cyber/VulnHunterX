# javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged non-literal `RegExp` construction is present, but the visible data flow shows the regex fragment is generated from a bounded numeric literal/loop counter on the same line, not from user-controlled input. No additional context provided a source that could influence the pattern, so the reported CWE-1333 ReDoS condition is not clearly exploitable.

## Data flow

line 1 literal argument `0x137` in the IIFE call → line 1 parameter `f` → line 1 loop `while(f--)` → line 1 local encoder `h(f)` → line 1 concatenation `'\x5cb'+h(f)+'\x5cb'` → line 1 sink `new RegExp(..., 'g')` → line 1 `.replace(...)` call via `d[b('0x2')](...)`; additional requested context `global:a` and `function:<unknown>` was unavailable and adds no new source

## Answers

1. Step 0 / flagged line location: The flagged line is present at `vulnerabilities/javascript/source/high.js:1`, in function context `<unknown>` / apparent top-level obfuscated JavaScript. The exact flagged construct on that line is `d=d[b('0x2')](new RegExp('\x5cb'+h(f)+'\x5cb','g'),g[f]);`. This confirms the rule-described construct is present: `new RegExp()` is called with a non-literal expression containing `h(f)`.
2. Step 1 source: The potentially dangerous regex-pattern component originates from parameter `f` of the immediately invoked function expression on line 1. In the visible invocation, `f` is supplied as the literal numeric value `0x137` in `}(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{}));`. The additional context for `global:a` and `function:<unknown>` is unavailable and does not show any user input, file, network, database, or request source.
3. Step 2 trace: On line 1, literal `0x137` is passed as parameter `f`; `f` is decremented by `while(f--)`; the local helper `h=function(j){...}` is called as `h(f)`; `h` transforms the numeric value using modulo/division, `parseInt(j/e)`, `String[b('0x0')](j+0x1d)`, and `j[b('0x1')](0x24)`; the result is concatenated into `'\x5cb'+h(f)+'\x5cb'`; the resulting string is passed to `new RegExp(...,'g')`; that regex is used in a replacement call `d[b('0x2')](..., g[f])`.
4. Step 3 validation/sanitization: No explicit regex safety library or ReDoS sanitizer is visible. However, the visible code constrains the regex fragment because `h(f)` is derived from a bounded numeric loop counter initialized from the literal `0x137` on line 1, and the transformation emits encoded identifier-like tokens rather than accepting arbitrary regex syntax from an external source. The unavailable additional context does not add contrary evidence.
5. Step 4 sink: The sink is `new RegExp('\x5cb'+h(f)+'\x5cb','g')` on line 1. The dangerous operation for this rule is dynamic regular-expression construction, which could be exploitable if the pattern string were attacker-controlled and could contain pathological regex constructs.
6. Step 5 framework/library protections: No framework or library automatic protection is visible. The relevant protection for this specific finding is not framework-based; it is the local visible fact that the regex pattern component is generated from a numeric literal / loop counter on line 1 rather than from user-controlled input.
7. Step 6 attacker privilege/authentication: Not visible in provided context. No request handler, route, authentication check, or caller context is shown. But the visible flagged path does not expose a way for any attacker privilege level to influence `h(f)` or the constructed regex pattern.
8. Step 7 impact: If an attacker controlled the `RegExp` pattern, the potential impact would be Regular Expression Denial of Service / main-thread blocking under CWE-1333. In the visible code, attacker control of the pattern is not demonstrated because the regex component is generated from bounded local numeric values.
9. Step 8 weakest link: For the reported non-literal-RegExp issue, no exploitable weak link is visible. The non-literal regex is real syntactically, but the defense is complete for this path because the dynamic portion comes from deterministic local numeric encoding, not from external input. The newly supplied context is unavailable and does not change this assessment.
