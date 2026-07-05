# javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context is unavailable and does not reveal any external source, while the visible flagged path shows the regex pattern component coming from a literal-bounded numeric loop counter on line 1. Because no attacker-controlled data reaches `new RegExp(...)`, and the generated token is not arbitrary regex syntax, the reported CWE-1333 ReDoS issue is not exploitable in the provided code.

## Data flow

vulnerabilities/javascript/source/high.js:1 literal `0x137` → parameter `f` of `function(d,e,f,g,h,i)` → `while(f--)` numeric decrement loop → `h(f)` base/token conversion helper → concatenation into `'\\b' + h(f) + '\\b'` represented as `'\x5cb'+h(f)+'\x5cb'` → sink `new RegExp(..., 'g')` in exact flagged expression `d=d[b('0x2')](new RegExp('\x5cb'+h(f)+'\x5cb','g'),g[f]);` → used by replacement call `d.replace(...)` via `b('0x2')` resolving to `replace`.

## Answers

1. Q1 / Step 1: The new context does not change the source analysis because `global:a`, `global:b`, and `all_callers:<unknown>` are unavailable. In the visible code, the RegExp pattern component originates from parameter `f` of the unpacking function on `vulnerabilities/javascript/source/high.js:1`, and that parameter is supplied by the literal `0x137` in the same top-level call.
2. Q2 / Step 2: The data flow remains: literal `0x137` is passed as `f` to `function(d,e,f,g,h,i)` on line 1 → `while(f--)` iterates over bounded numeric values on line 1 → `h(f)` converts the number to a base-`e` token on line 1 → `h(f)` is concatenated into the regex string `('\x5cb'+h(f)+'\x5cb')` on line 1 → that value is passed to `new RegExp(..., 'g')` on line 1.
3. Q3 / Step 3: No explicit ReDoS validation or regex-sanitization library is visible. However, the dynamic regex component is not arbitrary input: it is derived from a numeric loop counter initialized by the literal `0x137` on line 1. The helper `h` produces token strings using `toString(0x24)` and `String.fromCharCode(...)` on line 1, which limits generated characters to base-conversion style word tokens rather than attacker-supplied regex syntax.
4. Q4 / Step 4: The sink is the exact flagged expression on line 1: `d=d[b('0x2')](new RegExp('\x5cb'+h(f)+'\x5cb','g'),g[f]);`. The dangerous operation for CWE-1333 is dynamic RegExp construction; it would be unsafe if an attacker controlled the pattern or could inject catastrophic-backtracking regex constructs.
5. Q5 / Step 5: No framework or library automatic protection is visible. This is plain top-level JavaScript in `vulnerabilities/javascript/source/high.js:1`. The relevant visible defense is data-origin and construction: the regex pattern is generated from a bounded numeric loop counter, not from request, file, network, database, or other visible user input.
6. Q6 / Step 6: The privilege or authentication level needed to execute this code path is not visible in the provided context. The code appears to execute at top level, but no HTTP route, UI flow, authentication check, or deployment context is shown.
7. Q7 / Step 7: If an attacker controlled the RegExp pattern, the impact would be Denial of Service through catastrophic regex evaluation blocking the JavaScript thread. In this visible code path, attacker control of the RegExp pattern is not established, and the pattern is constructed from bounded generated tokens.
8. Q8 / Step 8: The weakest-looking point is the non-literal `new RegExp(...)` on line 1. For this specific finding, the visible defense is complete: the dynamic pattern portion `h(f)` is generated from a literal-bounded numeric loop counter and not from an attacker-controlled source, so the ReDoS condition described by the rule is not present on the shown path.
