# js/indirect-command-line-injection @ Gruntfile.js:166

**Verdict:** TP · **Confidence:** Low (0.55) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 6

## Reasoning

The balance of evidence leans True Positive because an environment variable flows unsanitized into a command string passed to `exec`, and no visible validation, escaping, allow-listing, safer API, or framework protection prevents command injection. Confidence is low because the exact binding/import of `exec` and the task invocation context were not shown, but no specific defense is available to support a False Positive verdict.

## Answers

1. Step 0: The flagged line is present at line 166: `cmd + "node artifacts/db-reset.js",`. It lives in `module.exports = function(grunt) { ... }` starting at line 14, inside the `grunt.registerTask("db-reset", "(Re)init the database.", function(arg) { ... })` callback registered at line 158. The rule-relevant construct is present: a command-like string is built by concatenating `cmd` into the first argument of `exec(` opened at line 165.
2. Step 1: The dangerous data originates from `process.env.NODE_ENV` on line 159: `var finalEnv = process.env.NODE_ENV || arg || "development";`. This is an environment variable source. The fallback `arg` on the same line may also be externally influenced through Grunt task invocation, but the reported CodeQL source is `process.env`.
3. Step 2: The data flow is: `process.env.NODE_ENV` at line 159 → assigned to `finalEnv` at line 159 → concatenated into `cmd` at line 163 using `"NODE_ENV=" + finalEnv + " & "` on Windows or `"NODE_ENV=" + finalEnv + " "` otherwise → concatenated into `cmd + "node artifacts/db-reset.js"` on line 166 → passed to `exec(` at line 165.
4. Step 3: No validation, sanitization, shell escaping, quoting, allow-listing, or encoding is visible. `finalEnv` is inserted directly into the shell-command prefix at line 163. The expanded `function:exports` context confirmed no sanitizer exists within the shown exported Grunt configuration function.
5. Step 4: The sink is the apparent `exec(` call at line 165, with the command string argument on line 166. The dangerous operation is execution of a string command containing unsanitized environment-derived data. If `exec` is Node.js `child_process.exec`, shell metacharacters in `NODE_ENV` can inject additional commands.
6. Step 5: No framework or library automatic protection is visible. The code does not use `execFile`, `spawn` with an argument array, an explicit `env` option, parameterization, or any shell-escaping helper. The requested context did not reveal a protective wrapper around `exec`.
7. Step 6: The exact privilege/authentication state is not visible. This is a Grunt task named `db-reset` registered at line 158, so exploitation requires the ability to run or influence the environment of the Grunt task. That may correspond to developer/CI/build-system access rather than an unauthenticated remote user, but no caller context proves a narrower safe trust boundary.
8. Step 7: If an attacker controls `NODE_ENV` for this task, the impact is command injection / arbitrary command execution with the privileges of the Grunt process. On Unix-like platforms, shell separators such as `;`, `&&`, `|`, backticks, or `$()` could alter execution; on Windows, the command construction already uses `&` at line 163.
9. Step 8: The weakest link is direct concatenation of `finalEnv` into a command string at line 163, followed by execution through `exec` at lines 165-166, with no visible defense. No complete defense is visible in the provided code or additional context.
