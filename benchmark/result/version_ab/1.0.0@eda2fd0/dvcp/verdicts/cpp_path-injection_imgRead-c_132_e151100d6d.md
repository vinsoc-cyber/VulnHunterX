# cpp/path-injection @ imgRead.c:132

**Verdict:** TP · **Confidence:** High (0.92) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

The attacker-controlled command-line argument `argv[1]` flows directly into `fopen(filename, "r")` with no visible path validation, canonicalization, allowlist, or directory restriction. The code therefore allows externally controlled file-path access within the privileges of the running process.

## Data flow

command-line argument argv (line 126) → argv[1] element access (line 132) → ProcessImage(argv[1]) call (line 132) → ProcessImage parameter filename → fopen(filename, "r") in ProcessImage (Statement 1)

## Answers

1. Step 1: The vulnerability class is path injection / externally controlled file path (CWE-22/CWE-23/CWE-36/CWE-73). The dangerous data originates from command-line user input: `argv` in `main` (source identified at line 126), specifically `argv[1]` passed at line 132.
2. Step 2: Updated data trace: command-line argument array `argv` in `main` (line 126) → element `argv[1]` is accessed and passed to `ProcessImage` (line 132) → parameter `filename` in `ProcessImage(char* filename)` → `filename` is passed directly to `fopen(filename, "r")` in `ProcessImage` at Statement 1.
3. Step 3: The only visible check in `main` is `if (argc < 2)` before using `argv[1]`, which ensures an argument exists but does not validate or sanitize the path (lines 126-132). In `ProcessImage`, `filename` is used directly in `fopen(filename, "r")` at Statement 1. There is no visible path allowlist, canonicalization, base-directory restriction, traversal rejection, filename validation, or permission check before the file access.
4. Step 4: The sink is `fopen(filename, "r")` in `ProcessImage` at Statement 1. The dangerous operation is opening a file using an attacker-controlled path. Because the path is supplied directly from `argv[1]`, an attacker can choose absolute paths, relative paths, or traversal-style paths depending on the operating environment.
5. Step 5: No framework or library-level automatic protection is visible. Standard C `fopen` does not protect against path injection or path traversal; it opens the path it is given subject only to OS filesystem permissions. No protective wrapper or safe file-opening policy is shown.
6. Step 6: An attacker needs the ability to execute the program or otherwise control its command-line argument `argv[1]`. Authentication is not visible or applicable in the provided C command-line context. If the program is invoked by another service with attacker-controlled arguments, that service context is not visible, but the direct code path is reachable by supplying a command-line argument.
7. Step 7: If an attacker controls `argv[1]`, they can cause the program to open and process arbitrary files readable by the process. Concrete impacts include unauthorized file access/processing, potential information disclosure through printed parsed contents, and denial of service or memory corruption during image parsing of attacker-chosen files. For this specific CodeQL rule, the path-injection impact is arbitrary readable file selection within the process privileges.
8. Step 8: The weakest link is the complete lack of validation between `argv[1]` at line 132 and `fopen(filename, "r")` in `ProcessImage` at Statement 1. The defense chain is incomplete because the existence check `argc < 2` only checks argument count and does not constrain the file path.
