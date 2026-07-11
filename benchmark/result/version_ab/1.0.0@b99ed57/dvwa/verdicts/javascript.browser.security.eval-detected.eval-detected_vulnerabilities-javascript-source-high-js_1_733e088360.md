# javascript.browser.security.eval-detected.eval-detected @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** Medium (0.8) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged `eval(...)` sink is definitely present on line 1, but the provided code shows the evaluated string is generated from hard-coded literals and deterministic local transformations, with no visible attacker-controlled source reaching the sink. The additional requested context is unavailable and does not change the trace or introduce evidence of external input.

## Data flow

line 1 hard-coded `var a=[...]` string table → line 1 deterministic array rotation `(function(c,d){...}(a,0x1f4))` → line 1 lookup helper `b=function(c,d){ c=c-0x0; var e=a[c]; return e; }` → line 1 unpacker arguments `b('0x7')`, `0x3e`, `0x137`, `b('0x8')[b('0x9')]('|')`, `0x0`, `{}` → line 1 unpacker transformations using `parseInt`, `String.fromCharCode`, `toString`, `replace`, and `RegExp` → line 1 sink `eval(...)`

## Answers

1. Step 0 / Locate flagged line: The flagged line is line 1, and it contains the reported construct. Exact relevant text from line 1: `... var b=function(c,d){c=c-0x0;var e=a[c];return e;};eval(function(d,e,f,g,h,i){...}(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{}));`. The `eval(...)` sink described by the rule is present on the flagged line. The function is reported as `<unknown>` and appears to be top-level code in the provided context.
2. Q1 / Source: The data passed to `eval` originates from hard-coded literals on line 1: the array `a=[...]`, numeric constants such as `0x3e`, `0x137`, `0x1f4`, and literal lookup keys such as `b('0x7')`, `b('0x8')`, and `b('0x9')`. The additional requested context for `global:a`, `global:b`, and `function:<unknown>` is unavailable and does not show any external source. No user input, file input, network input, database input, URL parameter, cookie, localStorage/sessionStorage, DOM input, or server-side template substitution is visible.
3. Q2 / Trace: On line 1, `var a=[...]` initializes a hard-coded obfuscated string table. Still on line 1, `(function(c,d){...}(a,0x1f4));` rotates the array using deterministic `push` and `shift` operations. Then `var b=function(c,d){c=c-0x0;var e=a[c];return e;};` returns entries from `a`. The `eval` argument is produced by invoking an unpacker function with `b('0x7')`, `0x3e`, `0x137`, `b('0x8')[b('0x9')]('|')`, `0x0`, and `{}`. Inside that same line-1 unpacker, values are transformed with `parseInt`, `String[b('0x0')]`, `toString`, `replace`, `RegExp`, and array lookups before the final generated string is returned to `eval(...)`.
4. Q3 / Validation/sanitization: No validation, sanitization, or encoding for code-injection prevention is visible before `eval` on line 1. The visible operations are deterministic deobfuscation/unpacking steps, not security controls. However, the visible input to those operations is constant hard-coded data, not attacker-controlled data.
5. Q4 / Sink: The sink is the `eval(...)` call on line 1: `eval(function(d,e,f,g,h,i){...}(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{}));`. The dangerous operation is dynamic JavaScript code execution in the browser context.
6. Q5 / Framework or library protections: No framework or library protection is visible or applicable. This is a raw JavaScript `eval` call on line 1, not a framework-mediated API with automatic escaping, parameterization, or sandboxing.
7. Q6 / Privilege/authentication required: Not visible in provided context. The code appears to be top-level JavaScript that would run when the script is loaded, but the page inclusion path, route, and authentication requirements are not shown.
8. Q7 / Security impact if attacker controlled data: If an attacker could control the string evaluated on line 1, the impact would be arbitrary JavaScript execution in the page origin, enabling DOM manipulation, credential/session/token theft, data exfiltration, or actions as the victim user. In the provided code and additional context, attacker control over the eval string is not shown.
9. Q8 / Weakest link: The weakest link is the use of `eval` itself on line 1, because it executes generated code. For this specific flagged path, the visible limiting factor is that the eval string is derived only from constants and local deterministic transformations on line 1. The additional context supplied is unavailable and does not add evidence of an external source.
