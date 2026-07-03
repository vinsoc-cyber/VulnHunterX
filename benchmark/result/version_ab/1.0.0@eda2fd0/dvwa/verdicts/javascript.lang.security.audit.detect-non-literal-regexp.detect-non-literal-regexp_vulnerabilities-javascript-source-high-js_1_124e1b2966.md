# javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional requested context is unavailable and does not reveal any attacker-controlled source, while the visible code itself shows the dynamic RegExp component is derived from a static bounded numeric counter. The sink is present, but the constructed pattern is constrained to simple token replacement rather than attacker-supplied or catastrophic regex syntax.

## Data flow

vulnerabilities/javascript/source/high.js:1: top-level `eval(function(d,e,f,g,h,i){...}(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{}))` → parameter `f` receives static numeric literal `0x137` → `while(f--)` iterates over bounded numeric values → `h(f)` converts the counter to an alphanumeric token → concatenation into `new RegExp('\x5cb'+h(f)+'\x5cb','g')` → used as the search pattern in `d.replace(..., g[f])`

## Answers

1. Step 1: The new context for `global:a`, `global:b`, and `all_callers:<unknown>` is unavailable and does not change the visible source analysis. In the provided code, the potentially dangerous RegExp pattern component originates from `h(f)` at `vulnerabilities/javascript/source/high.js:1`; `f` is supplied by the same top-level call as the static literal `0x137`, not from visible user input, file, network, database, or request data.
2. Step 2: Exact flagged line/function: `vulnerabilities/javascript/source/high.js:1`, function `<unknown>` / top-level packed JavaScript. The relevant flagged expression is `d=d[b('0x2')](new RegExp('\x5cb'+h(f)+'\x5cb','g'),g[f]);`. Data flow: static argument `0x137` is passed as `f` to the unpacker function at line 1 → `h` is defined at line 1 as a base-conversion/token-generation function → `while(f--)` at line 1 decrements the numeric loop counter → `h(f)` at line 1 converts the numeric counter into an alphanumeric token → the token is concatenated into `'\x5cb' + h(f) + '\x5cb'` at line 1 → the result is compiled by `new RegExp(..., 'g')` at line 1.
3. Step 3: No regex-specific validation library is used at line 1. However, the visible code applies a strong data constraint: the only dynamic regex component is generated from a bounded numeric loop counter, not attacker-controlled text. The `h(j)` function on line 1 emits base-style alphanumeric tokens using `toString(0x24)` and `String.fromCharCode(...)`; it does not pass arbitrary regex metacharacters from an external source into the pattern.
4. Step 4: The sink is `new RegExp('\x5cb'+h(f)+'\x5cb','g')` inside a replacement operation at `vulnerabilities/javascript/source/high.js:1`. The dangerous operation would be dynamic regular-expression construction, which could cause ReDoS if the pattern were attacker-controlled or contained catastrophic regex constructs. Here the pattern is word-boundary markers around a generated alphanumeric token.
5. Step 5: No framework or library automatic protection is visible. This is standalone packed JavaScript at line 1. The relevant protection is the visible local type/value constraint: the regex component comes from a static bounded numeric loop counter transformed into simple tokens.
6. Step 6: Authentication or privilege level is not visible in provided context. The code appears to execute at script load from top-level `eval(...)` on line 1, but there is no visible request handler, route, user role, or authorization boundary.
7. Step 7: If an attacker controlled the RegExp pattern, the concrete impact would be denial of service / main-thread blocking consistent with CWE-1333. In the provided code, attacker control of the pattern is not shown; the visible pattern shape is simple and non-catastrophic.
8. Step 8: No weak link exists for the reported non-literal-RegExp/ReDoS path in the visible code. The defense is the complete local data-flow constraint: `f` is a static numeric literal (`0x137`) at line 1, `while(f--)` bounds its values at line 1, and `h(f)` generates only simple token strings before `new RegExp` at line 1.
