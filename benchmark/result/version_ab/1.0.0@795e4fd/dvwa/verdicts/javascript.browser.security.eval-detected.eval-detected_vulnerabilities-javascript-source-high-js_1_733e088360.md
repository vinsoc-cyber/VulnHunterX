# javascript.browser.security.eval-detected.eval-detected @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** High (0.88) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The reported `eval()` construct is present, but the evaluated code is constructed only from hardcoded literals and deterministic transformations visible on line 1. The additional requested context was unavailable and reveals no external source; based on the provided code, no attacker-controlled data reaches the `eval()` sink, so the specific CWE-95 injection path is not demonstrated.

## Data flow

vulnerabilities/javascript/source/high.js:1 hardcoded `var a=[...]` → line 1 constant table rotation `(function(c,d){...}(a,0x1f4))` → line 1 lookup helper `b=function(c,d){...return e;}` → line 1 unpacker arguments `b('0x7')`, `0x3e`, `0x137`, `b('0x8')[b('0x9')]('|')` → line 1 deterministic replacement loop `d=d[b('0x2')](new RegExp(...),g[f])` → line 1 sink `eval(function(...){...}(...))`

## Answers

1. Step 0: The flagged line is present at vulnerabilities/javascript/source/high.js:1, in function `<unknown>` / apparent top-level script scope. The exact rule-relevant construct on the flagged line is `eval(function(d,e,f,g,h,i){...}(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{}));`. This confirms the construct described by the rule, use of `eval()`, is present on the flagged line.
2. Q1: The additional context for `global:a`, `global:b`, and `function:<unknown>` is unavailable and does not change the prior answer. In the visible code, the data passed to `eval()` originates from hardcoded literals on line 1: the array literal `var a=[...]`, constants such as `0x1f4`, `0x3e`, `0x137`, and string lookups through `b('0x7')`, `b('0x8')`, and `b('0x9')`. No user input, request parameter, file, network, database, DOM input value, or other external source is visible.
3. Q2: Data flow with the additional context included: the requested additional context is unavailable, so the visible flow remains line 1 only. `var a=[...]` initializes a hardcoded packed string table at line 1 → `(function(c,d){...}(a,0x1f4))` rotates/mutates that table using constant `0x1f4` at line 1 → `var b=function(c,d){c=c-0x0;var e=a[c];return e;};` reads values from the hardcoded table at line 1 → the unpacker receives `b('0x7')`, `0x3e`, `0x137`, and `b('0x8')[b('0x9')]('|')` at line 1 → the unpacker performs deterministic string replacement using `d=d[b('0x2')](new RegExp(...),g[f])` at line 1 → the returned string is executed by `eval(...)` at line 1.
4. Q3: No validation, sanitization, or encoding is applied before the `eval()` sink on line 1. The visible transformations are obfuscation/unpacking steps, not security sanitization. However, the visible input to those transformations is hardcoded and deterministic, so there is no visible attacker-controlled data requiring sanitization on this path.
5. Q4: The sink is `eval(...)` on line 1. The dangerous operation is execution of a dynamically constructed JavaScript string as code. It would become code injection if an attacker could influence the evaluated string.
6. Q5: No framework or library automatic protection is visible. There is no visible CSP enforcement, sandboxing, template auto-escaping, ORM parameterization, or other framework-level guard around `eval()` on line 1.
7. Q6: The privilege level or authentication state required to trigger this code path is not visible. The snippet appears to be top-level script code on line 1, so it would execute when the script is loaded, but who can cause that load is not shown.
8. Q7: If an attacker controlled the evaluated string, impact would be arbitrary JavaScript execution in the browser/runtime context, enabling DOM manipulation, data theft, credential/session theft, or actions as the victim. In the visible code, attacker control of the evaluated string is not shown.
9. Q8: The weakest visible link is the use of `eval()` itself on line 1 without sanitization. For this specific finding, the defense against CWE-95 exploitation is that the eval argument is visibly derived from hardcoded literals and deterministic local transformations on the same line, with no visible external input source reaching the sink.
