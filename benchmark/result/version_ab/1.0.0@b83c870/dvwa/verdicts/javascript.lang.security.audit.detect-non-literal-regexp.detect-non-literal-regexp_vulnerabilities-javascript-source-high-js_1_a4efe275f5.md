# javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The non-literal `RegExp()` sink is real syntactically, but the dynamic regex component is visibly derived from hardcoded, bounded numeric values in the same line rather than from attacker-controlled input. The unavailable extra context adds no contrary evidence, and the provided top-level IIFE invocation shows no exploitable ReDoS data path.

## Data flow

vulnerabilities/javascript/source/high.js:1 hardcoded table `var a=[...]` → line 1 local decoder `var b=function(c,d){...}` → line 1 hardcoded IIFE call `function(d,e,f,g,h,i){...}(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{})` → parameter `f=0x137` → line 1 helper `h(f)` converts numeric counter values to strings → line 1 sink `new RegExp('\x5cb'+h(f)+'\x5cb','g')` → line 1 `replace(...)` use

## Answers

1. Step 0 / flagged line location: The flagged line is present at `vulnerabilities/javascript/source/high.js:1`, in Function `<unknown>` / top-level minified script context. The line begins `var a=['fromCharCode','toString','replace',...` and the exact flagged sink construct on that same line is `d=d[b('0x2')](new RegExp('\x5cb'+h(f)+'\x5cb','g'),g[f]);`. The rule-described construct is present: `RegExp()` is called with a non-literal expression, ` '\x5cb'+h(f)+'\x5cb' `.
2. New context impact: The additional requested context for `global:a`, `global:b`, and `all_callers:<unknown>` is unavailable and does not add new evidence. It also does not change the visible local flow: `a` and `b` are declared in the same top-level line 1, and the dynamic regex is inside an immediately invoked unpacking function on line 1.
3. Step 1: The potentially dangerous data for the regex pattern originates from visible hardcoded values on line 1, not from user input, file, network, database, or request parameters. Specifically, the unpacking function is invoked as `...(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{})`, where `f` receives hardcoded `0x137` and `g` receives a split of a hardcoded string from `b('0x8')`.
4. Step 2: Data flow, all on line 1: `var a=[...]` defines a hardcoded string table → `var b=function(c,d){... return e;};` indexes that hardcoded table → the IIFE `function(d,e,f,g,h,i){...}` is called with hardcoded arguments → parameter `f` is initialized to `0x137` → helper `h=function(j){...}` converts numeric `j` to a token string using arithmetic, `String.fromCharCode`, and `toString(0x24)` → loop `while(f--)` passes the current numeric counter to `h(f)` → `h(f)` is concatenated into `new RegExp('\x5cb'+h(f)+'\x5cb','g')` → the regex is used in `replace` on `d`.
5. Step 3: There is no explicit regex validation/sanitization library call visible on line 1. However, the dynamic part `h(f)` is not attacker-controlled in the visible code: it is derived from a bounded hardcoded numeric loop counter and converted into simple base-style alphanumeric tokens. That visible type/source guarantee prevents attacker-supplied regex patterns on this path.
6. Step 4: The sink is `new RegExp('\x5cb'+h(f)+'\x5cb','g')` on line 1, used immediately as the first argument to `replace` in `d=d[b('0x2')](new RegExp(...),g[f]);`. The operation would be dangerous if an attacker could control the regex pattern, because dynamically compiled regexes can cause ReDoS.
7. Step 5: No framework or library automatic protection is visible. This is plain JavaScript code; there is no ORM, template engine, request framework, or regex-safety library shown. The relevant protection is not framework-provided but rather the visible hardcoded/bounded origin of the regex component.
8. Step 6: The privilege or authentication state needed to execute the file is not visible. However, exploitability of this specific finding depends on controlling the regex pattern, and the provided code shows no attacker-controlled input path into `h(f)` or the `RegExp` argument.
9. Step 7: If attacker-controlled regex data reached this sink, the impact could be Regular Expression Denial of Service by blocking the JavaScript main thread/event loop. In the provided code, the concrete impact is not demonstrated because the regex pattern is generated from hardcoded numeric values.
10. Step 8: The weakest-looking link is the dynamic `RegExp()` inside obfuscated `eval(...)` code on line 1. But for this finding, the defense is complete in the visible path: the dynamic regex component comes from a hardcoded bounded counter, not from external input, and produces simple word-boundary token regexes rather than attacker-chosen patterns.
