# cpp/path-injection @ imgRead.c:132

**Verdict:** TP · **Confidence:** Medium (0.78) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

The additional context confirms the reported path-injection flow: `argv[1]` is passed directly into `ProcessImage` and then into `fopen` with no visible path validation, canonicalization, or restriction. The exploitability depends somewhat on deployment privileges, but the specific CodeQL-reported unsafe file access pattern is clearly present.

## Data flow

command-line argument `argv` enters `main` (line 126) → presence-only check `argc < 2` (lines 128-131) → user-controlled `argv[1]` passed to `ProcessImage` (line 132) → `ProcessImage` parameter `filename` receives the value → `filename` passed directly to `fopen(filename, "r")` in `ProcessImage` Statement 1

## Answers

1. Step 0 / Flagged line: The flagged line is present at line 132: `ProcessImage(argv[1]);`. The construct described by the rule is present: user-controlled command-line argument data, specifically `argv[1]`, is passed to `ProcessImage`.
2. Step 1 / Source: The dangerous data originates from command-line input to `main(int argc, char **argv)` at line 126. The user controls `argv[1]`, which is the filename argument.
3. Step 2 / Trace: `argv` enters `main` at line 126. Lines 128-131 check only that at least one argument exists. At line 132, `argv[1]` is passed directly to `ProcessImage`. In `ProcessImage`, the parameter `filename` receives that value. `filename` is then passed directly to `fopen(filename, "r")` in `ProcessImage` Statement 1.
4. Step 3 / Validation/Sanitization/Encoding: The only visible check is `argc < 2` at lines 128-131, which validates argument presence only. It does not sanitize or restrict the path. In `ProcessImage`, there is no visible canonicalization, allowlist, basename restriction, directory confinement, traversal rejection, or other path validation before `fopen(filename, "r")`.
5. Step 4 / Sink: The sink is `fopen(filename, "r")` in `ProcessImage` Statement 1. The unsafe operation is opening a filesystem path directly derived from user-controlled `argv[1]` without validation or restriction.
6. Step 5 / Framework/Library Protections: No framework-level or library-level automatic protection is visible. The C standard library `fopen` does not prevent path traversal, absolute paths, symlinks, or access to arbitrary readable files by itself.
7. Step 6 / Required Privilege/Auth State: Based on the visible `main` function at lines 126-134, any local user or process that can execute the program and supply command-line arguments can reach the sink. No authentication, authorization, or privilege check is visible.
8. Step 7 / Security Impact: If the program runs with privileges beyond the invoking user, an attacker could cause it to open and process arbitrary files readable by the process, leading to unauthorized file access or information disclosure. Even without elevated privileges, the path is fully attacker-controlled and can target unexpected files, devices, or special paths, potentially causing denial of service depending on environment.
9. Step 8 / Weakest Link: The weakest link is the complete lack of path validation between `argv[1]` at line 132 and `fopen(filename, "r")` in `ProcessImage`. The `argc` check only ensures the argument exists and does not mitigate path injection.
