# javascript.browser.security.eval-detected.eval-detected @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** High (0.88) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional requested context is unavailable and does not change the visible trace: the flagged line contains an `eval` sink, but the evaluated string is constructed from hardcoded line-1 literals through deterministic deobfuscation. No external source is visible reaching `eval`, so the reported CWE-95/code-injection path is not established.

## Data flow

vulnerabilities/javascript/source/high.js:1 hardcoded array literal `var a=[...]` and constants → vulnerabilities/javascript/source/high.js:1 deterministic array-rotation IIFE `(function(c,d){...}(a,0x1f4))` → vulnerabilities/javascript/source/high.js:1 lookup helper `b=function(c,d){...return e;}` → vulnerabilities/javascript/source/high.js:1 unpacking IIFE `function(d,e,f,g,h,i){...d=d.replace(...); return d;}(...)` → vulnerabilities/javascript/source/high.js:1 sink `eval(...)`

## Answers

1. Flagged line location: The flagged line is line 1 in `vulnerabilities/javascript/source/high.js`, in function `<unknown>` / apparent top-level script context. The line contains the rule-described construct, specifically the JavaScript sink substring `eval(function(d,e,f,g,h,i){...}(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{}));`. Because the entire file slice is a single minified line, the dangerous construct is present on that same flagged line.
2. Q1 / source: The new context for `global:a`, `global:b`, and `function:<top-level>` is unavailable and does not reveal any external source. In the provided code, the data evaluated by `eval` originates from hardcoded literals on line 1: `var a=[...]`, numeric constants such as `0x3e` and `0x137`, and the object literal `{}`. No user input, file input, network input, database value, URL parameter, DOM input, or other attacker-controlled source is visible.
3. Q2 / trace: On line 1, `var a=[...]` defines the hardcoded obfuscated string table. Still on line 1, `(function(c,d){...}(a,0x1f4))` mutates that array deterministically via `c['push'](c['shift']())`. Then line 1 defines `var b=function(c,d){c=c-0x0;var e=a[c];return e;};`, which reads values from `a`. The `eval` argument is produced by the unpacking IIFE `function(d,e,f,g,h,i){... return d; }(...)`, called on line 1 with `b('0x7')`, `0x3e`, `0x137`, `b('0x8')[b('0x9')]('|')`, `0x0`, and `{}`. Inside that IIFE on line 1, `d` is repeatedly transformed using `d=d[b('0x2')](new RegExp('\x5cb'+h(f)+'\x5cb','g'),g[f]);`, then the returned `d` is passed directly to `eval(...)`.
4. Q3 / validation or sanitization: No sanitizer, validator, allowlist, escaping operation, sandbox, or safe parser is visible before `eval` on line 1. The transformations are deobfuscation/string reconstruction operations. For CWE-95, however, the relevant question is attacker control of evaluated code; in the visible code, the eval input is built from hardcoded constants rather than an external source.
5. Q4 / sink: The sink is the `eval(...)` call on line 1. The dangerous operation is runtime JavaScript evaluation of a reconstructed string returned from the immediately invoked unpacking function.
6. Q5 / framework or library protections: No framework or library protection is visible. There is no ORM, template engine, browser framework sanitizer, CSP configuration, or auto-escaping mechanism shown. The code is plain JavaScript-style code despite the finding metadata listing `Language: php`.
7. Q6 / privilege or authentication needed: Not visible in provided context. The snippet appears to be top-level script code, but no route, inclusion point, web page, authentication check, or authorization gate is shown.
8. Q7 / concrete impact if attacker controls the data: If an attacker could control the string passed to `eval` on line 1, the impact would be arbitrary JavaScript execution in this script’s execution context, potentially enabling DOM manipulation, credential/session-token theft, data exfiltration, or actions as the victim user. The provided code does not show attacker control over the evaluated string.
9. Q8 / weakest link: The weakest link is the direct use of `eval` on line 1 with no visible validation or sandboxing. The reason this specific CWE-95 finding is not demonstrated as exploitable is that the eval argument is visibly derived from line-1 hardcoded literals and deterministic transformations, not from external input.
