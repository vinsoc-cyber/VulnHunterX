# javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** High (0.88) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The reported construct is genuinely present on line 1, but the dynamic regex fragment is not user-controlled in the visible code: it is produced from a constant-bounded numeric loop counter through local token-generation logic. The unavailable additional context does not introduce any attacker-controlled source, and the visible code provides a concrete restriction preventing regex-pattern injection for this finding.

## Data flow

vulnerabilities/javascript/source/high.js:1 local constant invocation `eval(function(...)(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{}))` → `f = 0x137` enters `while(f--)` on line 1 → local helper `h(f)` converts the numeric counter to a token on line 1 → token is concatenated into `new RegExp('\x5cb'+h(f)+'\x5cb','g')` on line 1 → resulting regex is used in `d[b('0x2')](..., g[f])` on line 1. Requested additional context for `global:a`, `global:b`, `function:h`, `function:<anonymous eval function>`, and `all_callers:<unknown>` was unavailable and does not add any new source or sink evidence.

## Answers

1. Flagged line location: vulnerabilities/javascript/source/high.js:1. The flagged line is present and begins `var a=['fromCharCode','toString','replace','BeJ', ...` and contains the exact reported construct `new RegExp('\x5cb'+h(f)+'\x5cb','g')`. This is inside an anonymous function passed to `eval(...)` in top-level code; the provided function name is `<unknown>`.
2. Q1/Step 1: The new context does not change the source analysis. The RegExp pattern component originates from local constants and local variables on line 1: the anonymous eval-wrapper is invoked with `e = 0x3e`, `f = 0x137`, and `g = b('0x8')[b('0x9')]('|')`. No user input, network input, file input, database input, or DOM-derived input is visible as a source for the RegExp pattern.
3. Q2/Step 2: Data flow remains: line 1 defines array `a`; line 1 rotates `a` using `(function(c,d){...}(a,0x1f4))`; line 1 defines decoder `b=function(c,d){c=c-0x0;var e=a[c];return e;}`; line 1 invokes `eval(function(d,e,f,g,h,i){...}(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{}))`; inside that anonymous function on line 1, `h=function(j){...}` converts numeric `j` to a token; line 1 loops with `while(f--)`; line 1 constructs `new RegExp('\x5cb'+h(f)+'\x5cb','g')`; line 1 uses it in `d[b('0x2')](..., g[f])`, i.e. a replace operation.
4. Q3/Step 3: There is no explicit regex escaping or ReDoS sanitizer before the `RegExp` constructor on line 1. However, the dynamic portion `h(f)` is visibly generated from the numeric loop counter `f`, initialized to constant `0x137` on line 1, and converted through arithmetic/base-conversion logic. This is a visible type/range/character restriction: it produces simple identifier-like tokens rather than attacker-supplied regex syntax.
5. Q4/Step 4: The sink is `new RegExp('\x5cb'+h(f)+'\x5cb','g')` on line 1, followed by use in string replacement via `d[b('0x2')](..., g[f])`. The operation would be dangerous if the regex pattern were attacker-controlled or capable of becoming a pathological expression, but the visible dynamic part is locally generated from a bounded numeric counter.
6. Q5/Step 5: No framework or library automatic protections are visible or relevant. This is raw JavaScript. The relevant defense visible in the code is not a framework feature but the local generation of the RegExp token from constants and bounded numeric loop values on line 1.
7. Q6/Step 6: Authentication or privilege level is not visible in the provided context. The code appears to be top-level JavaScript that executes when loaded, but no route, request handler, authentication check, or caller context is shown.
8. Q7/Step 7: For CWE-1333, the theoretical impact would be Regular Expression Denial of Service if an attacker could control the pattern. In this snippet, attacker control of the pattern is not visible; the pattern is generated from constants on line 1.
9. Q8/Step 8: No exploitable weak link is visible for the reported non-literal RegExp/ReDoS issue. The decisive defense is that the non-literal component `h(f)` is derived from a bounded numeric loop counter initialized from a constant and not from attacker-controlled input.
