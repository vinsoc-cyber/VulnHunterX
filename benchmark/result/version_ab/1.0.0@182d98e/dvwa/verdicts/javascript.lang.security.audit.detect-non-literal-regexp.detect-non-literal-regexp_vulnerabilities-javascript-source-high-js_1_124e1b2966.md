# javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged non-literal RegExp sink is real syntactically, but the dynamic pattern component is visibly generated from a hardcoded bounded numeric loop counter, not from user-controlled input. The unavailable additional context does not introduce any new source, and the visible sequential top-level code initializes and uses the values locally on the same line.

## Data flow

hardcoded literal `0x137` as parameter `f` in `vulnerabilities/javascript/source/high.js:1` → bounded local loop `while(f--)` on line 1 → local encoder `h(f)` on line 1 → concatenation into `new RegExp('\x5cb'+h(f)+'\x5cb','g')` on line 1 → regex used by `d[b('0x2')](..., g[f])`, i.e. `replace`, on line 1

## Answers

1. Step 0 / Location: The flagged line is present at `vulnerabilities/javascript/source/high.js:1`, in function/context `<unknown>` / top-level minified script. The relevant exact flagged sink text on that line is `new RegExp('\x5cb'+h(f)+'\x5cb','g')`, appearing inside `d=d[b('0x2')](new RegExp('\x5cb'+h(f)+'\x5cb','g'),g[f]);`. This confirms the rule-described construct, a non-literal `RegExp()` call, is present on the flagged line.
2. Q1: The potentially dangerous regex pattern component originates from local hardcoded values visible on line 1, not from a visible user-input, file, network, or database source. The variable `f` is passed as the literal `0x137` in the IIFE call on line 1, and the regex component is generated as `h(f)` from that local numeric loop variable.
3. Q2: Data flow with the additional context included: additional requested contexts for `global:a`, top-level callers, and `function:b` are unavailable and do not add any new source. In the visible code at line 1, `f` is initialized by the literal argument `0x137`; `h` is assigned a local function `function(j){...}`; the loop `while(f--)` iterates over bounded numeric values; `h(f)` converts each numeric value into a token string; that token string is concatenated into `new RegExp('\x5cb'+h(f)+'\x5cb','g')`; the resulting regex is passed to `replace` via `d[b('0x2')](...)`.
4. Q3: There is no regex-specific sanitizer such as a ReDoS checker. However, the visible code has a stronger defense for this finding: the pattern is not attacker-controlled. The value reaching `h(f)` is a bounded local numeric loop counter initialized from hardcoded literal `0x137` on line 1, and `h()` generates simple encoded token strings from that number.
5. Q4: The sink is `new RegExp('\x5cb'+h(f)+'\x5cb','g')` on line 1. The operation would be dangerous if untrusted input controlled the regex pattern, because dynamic regex construction can enable ReDoS. Here, the dynamic part is locally generated from a hardcoded numeric counter.
6. Q5: No framework or library automatic protection is visible or relevant. This is plain JavaScript on line 1. The safety conclusion does not rely on framework protection; it relies on the visible local constant/bounded source for the regex pattern.
7. Q6: No attacker privilege or authentication state is shown that would allow influencing this specific regex pattern. The script appears to execute as top-level code, but the regex pattern source is local and hardcoded in the provided line.
8. Q7: If an attacker controlled the regex pattern, the impact could be denial of service through catastrophic backtracking. In the shown code, that impact is not reachable for this finding because attacker control over the regex pattern is not visible and the pattern component is derived from bounded local numeric values.
9. Q8: No exploitable weak link is visible for the flagged ReDoS chain. The defense is complete for the shown path because the regex pattern component `h(f)` is derived from the literal `0x137` and local loop state on line 1, not from external input. The additional context provided is unavailable and does not change this analysis.
