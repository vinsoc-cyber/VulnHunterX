# javascript.browser.security.eval-detected.eval-detected @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** Medium (0.78) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged eval sink is real and located at line 1, but the evaluated string is visibly derived from hardcoded literals assigned on the same line and deterministic unpacking logic. The additional context was unavailable and does not reveal any external input source reaching the sink, so this specific CWE-95/code-injection finding is not clearly exploitable.

## Data flow

vulnerabilities/javascript/source/high.js:1 hardcoded `var a=[...]` → line 1 IIFE mutates `a` with `push`/`shift` → line 1 `var b=function(c,d){... return a[c];}` retrieves packed strings → line 1 unpacker receives `b('0x7')` and `b('0x8').split('|')` → line 1 unpacker performs `replace(new RegExp(...), g[f])` → line 1 `eval(...)` executes the resulting string; additional context for `global:a`, `global:b`, and callers was unavailable and adds no visible external source

## Answers

1. Q1: The new context does not change the source analysis: `global:a`, `global:b`, and `all_callers:<unknown>` are unavailable. In the visible code, the data passed to `eval` originates from hardcoded literals assigned in `var a=[...]` at vulnerabilities/javascript/source/high.js:1, not from visible user input, file, network, database, URL, DOM input, or storage.
2. Q2: The flagged line is vulnerabilities/javascript/source/high.js:1, in Function: `<unknown>` / apparent top-level script code. The relevant exact sink text on that line is: `eval(function(d,e,f,g,h,i){h=function(j){return(j<e?'':h(parseInt(j/e)))+((j=j%e)>0x23?String[b('0x0')](j+0x1d):j[b('0x1')](0x24));};...}(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{}));`. Data flow: hardcoded `var a=[...]` at line 1 → array-rotation IIFE `(function(c,d){...}(a,0x1f4))` at line 1 → lookup helper `var b=function(c,d){c=c-0x0;var e=a[c];return e;};` at line 1 → unpacker inputs `b('0x7')` and `b('0x8')[b('0x9')]('|')` at line 1 → token replacement via `replace(new RegExp(...), g[f])` at line 1 → generated string passed to `eval(...)` at line 1.
3. Q3: No validation, sanitization, or encoding is visible at line 1. The operations are obfuscation/unpacking operations: array rotation, table lookup through `b`, `split('|')`, `RegExp`, and `replace(...)`. These are not sufficient sanitization for externally controlled code, but no externally controlled source is visible on this path.
4. Q4: The sink is `eval(...)` at vulnerabilities/javascript/source/high.js:1. The unsafe operation is executing a string as JavaScript code.
5. Q5: No framework or library automatic protection is visible. The additional requested context was unavailable, and the provided code shows raw JavaScript `eval` without CSP, sandboxing, framework escaping, or another protective mechanism.
6. Q6: The authentication or privilege level required to trigger this code is not visible in the provided context. Because the code appears top-level on line 1, it would execute when the script is loaded, but routing, access control, and script inclusion context are not shown.
7. Q7: If an attacker controlled the evaluated string, the impact would be arbitrary JavaScript execution in the browser context, potentially enabling DOM manipulation, credential/session theft, or actions as the victim. In the visible code, attacker control over the evaluated string is not demonstrated.
8. Q8: The weakest link is the use of `eval` itself on line 1. However, the visible data feeding the sink is a hardcoded packed payload with deterministic unpacking, and the added context did not reveal any external source that can modify `a`, `b`, or the eval argument before execution.
