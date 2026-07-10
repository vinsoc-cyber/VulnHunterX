# cpp/path-injection @ imgRead.c:132

**Verdict:** TP · **Confidence:** Low (0.3) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

The added `ProcessImage` body confirms that the command-line supplied `argv[1]` reaches `fopen(filename,"r")` with no visible path validation, canonicalization, whitelist, or directory confinement. This makes the reported path-injection/external filename control finding real for the flagged data flow. [calibration: CLI argv path source with no trust boundary — operator-controlled path in a standalone tool, likely False Positive]

## Data flow

command-line argument `argv` received by `main` (line 126) → `argc < 2` existence check only (lines 128-131) → `argv[1]` passed to `ProcessImage` (line 132) → `filename` parameter in `ProcessImage` → `fopen(filename,"r")` in `ProcessImage` Statement 1

## Answers

1. Step 0: The flagged line is present in the original code at line 132 and its exact text is `ProcessImage(argv[1]);`. The construct described by the rule is present: user-controlled command-line argument `argv[1]` is passed into `ProcessImage`, which the added context confirms calls `fopen(filename,"r")`.
2. Step 1: The dangerous data originates from command-line user input: `argv` is received by `main` at line 126, and `argv[1]` is the attacker-controlled filename used at line 132.
3. Step 2: The data flow is: `argv` parameter to `main` at line 126 → argument-count check `if (argc < 2)` at lines 128-131 → `argv[1]` passed to `ProcessImage` at line 132 → `filename` parameter of `ProcessImage` → `fopen(filename,"r")` in `ProcessImage` Statement 1.
4. Step 3: The only visible validation is the argument-count check at line 128, which ensures an argument exists. It does not validate the path, reject absolute paths, reject `..`, canonicalize the path, enforce a safe base directory, or whitelist filenames. No sufficient sanitization for path injection/path traversal is visible before `fopen(filename,"r")`.
5. Step 4: The sink is `fopen(filename,"r")` in `ProcessImage` Statement 1. The dangerous operation is opening a filesystem path that is directly controlled by the command-line argument from line 132.
6. Step 5: No framework or library protection is visible. C standard library `fopen` does not provide automatic path traversal protection, base-directory confinement, or filename sanitization.
7. Step 6: Based on the visible code, an attacker needs the ability to invoke the program and supply command-line arguments. No authentication or admin-only guard is visible in the provided context.
8. Step 7: If an attacker controls `argv[1]`, they can cause the program to open and process an arbitrary path readable by the process. Concrete impact can include unauthorized local file read/exposure through subsequent printing in `ProcessImage`, and processing attacker-selected file contents through unsafe image parsing code. The exact impact depends on the program’s runtime privileges, but arbitrary path selection is clearly present.
9. Step 8: The weakest link is the absence of any path validation or confinement between `argv[1]` at line 132 and `fopen(filename,"r")` in `ProcessImage` Statement 1. The defense chain is incomplete because the only guard, `argc < 2` at line 128, checks presence but not safety of the filename.
