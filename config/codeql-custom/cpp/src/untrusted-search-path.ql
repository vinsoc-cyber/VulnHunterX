/**
 * @name Process execution with non-absolute or PATH-controlled program name
 * @description `system`, `execvp`, `execlp`, `execvpe`, or `posix_spawnp`
 *              executed with a relative-path or bare-name program is
 *              resolved against `$PATH`. If `$PATH` is attacker-influenced
 *              (suid binaries, plugin loaders, sandboxes that forward env),
 *              an attacker can override the resolved binary.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id cpp/untrusted-search-path
 * @tags external/cwe/cwe-426
 *       external/cwe/cwe-829
 *       security
 */

import cpp

/** A call to a process-spawning function whose program name is resolved via PATH. */
class PathSearchingExecCall extends FunctionCall {
  int progIndex;

  PathSearchingExecCall() {
    (
      this.getTarget().hasGlobalOrStdName(["execvp", "execlp", "execvpe", "posix_spawnp"]) and
      progIndex = 0
      or
      this.getTarget().hasGlobalOrStdName(["system", "popen"]) and progIndex = 0
    )
  }

  Expr getProgramArg() { result = this.getArgument(progIndex) }
}

predicate isAbsolutePathLiteral(Expr e) {
  exists(StringLiteral s | s = e and s.getValue().regexpMatch("^/.*"))
}

predicate isFullyShellEscaped(Expr e) {
  // system("...") whose literal starts with a slash AND has no shell-metachars
  exists(StringLiteral s |
    s = e and
    s.getValue().regexpMatch("^/[A-Za-z0-9_./-]+( [A-Za-z0-9_./-]+)*$")
  )
}

from PathSearchingExecCall call, Expr prog
where
  prog = call.getProgramArg() and
  not isAbsolutePathLiteral(prog) and
  not isFullyShellEscaped(prog)
select call,
  "'" + call.getTarget().getName() +
  "' called with a non-absolute program reference — resolved via $PATH. " +
  "If the process inherits an attacker-controlled PATH, the binary lookup " +
  "can be hijacked. Use absolute paths or sanitised environment."
