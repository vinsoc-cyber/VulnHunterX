# cpp/path-injection @ imgRead.c:132

**Verdict:** TP · **Confidence:** Medium (0.78) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

The additional context confirms that the user-controlled command-line path passed at line 132 reaches `fopen(filename, "r")` with no visible sanitization, canonicalization, allowlist, or directory restriction. The exploitability impact depends on the process privileges and deployment context, but the flagged path-injection sink itself is real and undefended in the provided code.

## Data flow

command-line argument source `argv` in `main` parameter (line 126) → existence-only check `argc < 2` (line 128) → direct call `ProcessImage(argv[1])` (line 132) → `ProcessImage` parameter `filename` → direct filesystem access `fopen(filename, "r")` (`ProcessImage` Statement 1)

## Answers

1. Step 0 / flagged line: The flagged line is present at line 132 and its exact text is `ProcessImage(argv[1]);`. The construct described by the rule is present: user-controlled command-line argument `argv[1]` is passed to `ProcessImage`.
2. Step 1: The potentially dangerous data originates from command-line input: `char **argv` in `main` at line 126, specifically `argv[1]` used at line 132.
3. Step 2: The data flow is: `argv` enters `main` as a command-line argument array at line 126 → `argc < 2` checks only whether an argument exists at line 128 → `argv[1]` is passed directly to `ProcessImage` at line 132 → inside `ProcessImage`, parameter `filename` receives that value → `filename` is passed directly to `fopen(filename, "r")` at `ProcessImage` Statement 1.
4. Step 3: The only visible validation is the presence check `if (argc < 2)` at line 128. This prevents a missing argument but does not validate, sanitize, canonicalize, restrict to a safe directory, reject traversal sequences, or enforce an allowed filename pattern. No sufficient path-injection/path-traversal defense is visible before `fopen`.
5. Step 4: The sink is `fp = fopen(filename, "r");` in `ProcessImage` Statement 1. The dangerous operation is opening a filesystem path directly controlled by the command-line argument. This can allow an attacker to cause the program to read and process an arbitrary path accessible to the process.
6. Step 5: No framework or library automatic protection is visible. Standard C `fopen` does not sanitize or restrict paths. No wrapper, allowlist, chroot/jail, canonicalization, or safe base-directory enforcement is shown.
7. Step 6: Based on the provided code, an attacker needs the ability to run or influence invocation of this program and control command-line argument `argv[1]`. Authentication state and whether the program runs with elevated privileges are not visible in the provided context.
8. Step 7: If an attacker controls `argv[1]`, the concrete impact is arbitrary local file selection for reading and processing by this program, limited to files accessible to the process. Depending on the program’s execution privileges, this could result in unauthorized file read or data exposure. Additionally, because the opened file contents are parsed into `struct Image` and used in unsafe memory operations in `ProcessImage`, attacker-controlled file selection may also lead to denial of service or memory corruption, but those are downstream issues beyond the flagged path sink.
9. Step 8: The weakest link is the complete absence of path validation between `argv[1]` at line 132 and `fopen(filename, "r")` in `ProcessImage` Statement 1. The `argc` check at line 128 is only an existence check and does not defend against path injection.
