# javascript.browser.security.eval-detected.eval-detected @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** High (0.88) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged `eval` call is present, but the evaluated string is visibly constructed from hardcoded constants through deterministic local transformations on the same line. The additional requested context was unavailable and does not reveal any external source, while the provided code shows no user/file/network/database input reaching the eval sink.

## Data flow

hardcoded array literal `a` (`vulnerabilities/javascript/source/high.js:1`) → deterministic array rotation IIFE `(function(c,d){...}(a,0x1f4))` (`vulnerabilities/javascript/source/high.js:1`) → local lookup helper `b(c,d)` returns `a[c]` (`vulnerabilities/javascript/source/high.js:1`) → unpacker arguments `b('0x7')`, constants, and `b('0x8')[b('0x9')]('|')` (`vulnerabilities/javascript/source/high.js:1`) → deterministic token replacement inside unpacker (`vulnerabilities/javascript/source/high.js:1`) → returned string passed to `eval(...)` sink (`vulnerabilities/javascript/source/high.js:1`)

## Answers

1. Q1: The new context does not change the source analysis. The data passed to `eval` originates from hardcoded literals in the same physical line: array `a` is initialized with string constants, and the unpacker is invoked with constant arguments on `vulnerabilities/javascript/source/high.js:1`. The requested `global:a` context is unavailable, but the provided code visibly declares `var a=[...]` before the `eval` on the same line.
2. Q2: Data flow remains: `var a=[...]` on `vulnerabilities/javascript/source/high.js:1` → IIFE `(function(c,d){...}(a,0x1f4))` rotates/mutates `a` deterministically on line 1 → `var b=function(c,d){... return e;};` reads entries from `a` on line 1 → the unpacker receives `b('0x7')`, `0x3e`, `0x137`, `b('0x8')[b('0x9')]('|')`, `0x0`, and `{}` on line 1 → the unpacker performs deterministic replacement and returns `d` on line 1 → `eval(...)` executes that returned string on line 1.
3. Q3: No validation, sanitization, or encoding is visible before `eval` on `vulnerabilities/javascript/source/high.js:1`. However, for this CWE-95 finding, the relevant visible defense is that the evaluated code is produced from hardcoded constants and deterministic transformations, with no visible external input source.
4. Q4: The sink is `eval(function(d,e,f,g,h,i){...}(...))` on `vulnerabilities/javascript/source/high.js:1`. The dangerous operation is executing a generated string as JavaScript code.
5. Q5: No framework or library automatic protection is visible or applicable. This is a direct JavaScript `eval` call on `vulnerabilities/javascript/source/high.js:1`.
6. Q6: The required privilege/authentication state is not visible in the provided context. The code appears to be top-level script code on `vulnerabilities/javascript/source/high.js:1`, but how the script is loaded or served is not shown.
7. Q7: If an attacker could control the evaluated string, the impact would be arbitrary JavaScript execution in the browser context, which could enable data/session theft, DOM manipulation, or unauthorized actions as the victim. In the visible code, attacker control of the evaluated string is not shown.
8. Q8: The weakest link is the use of raw `eval` itself on `vulnerabilities/javascript/source/high.js:1`. The defense against the specific code-injection issue is that the eval input is visibly derived from local hardcoded literals and deterministic decoding on the same line, rather than from an external source.
