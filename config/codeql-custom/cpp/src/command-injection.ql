/**
 * @name Command injection via tainted argument to shell/exec
 * @description User-controlled data reaching `system`, `popen`, `execl`,
 *              `execv`, `execlp`, or `execvp` without sanitisation lets
 *              an attacker inject shell metacharacters or override the
 *              executed program (CWE-78). Conservative: precision medium,
 *              comparison/sanitiser nodes treated as barriers.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @id cpp/command-injection
 * @tags external/cwe/cwe-78
 *       external/cwe/cwe-77
 *       security
 */

import cpp
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.dataflow.new.TaintTracking
import CommandInjectionFlow::PathGraph

/** An argument expression to a shell/exec sink. */
class CommandSink extends Expr {
  CommandSink() {
    exists(FunctionCall fc |
      fc.getTarget().hasGlobalOrStdName(["system", "popen"]) and
      fc.getArgument(0) = this
    )
    or
    exists(FunctionCall fc |
      fc.getTarget().hasGlobalOrStdName(["execl", "execlp", "execle",
                                          "execv", "execvp", "execve", "execvpe"]) and
      (
        fc.getArgument(0) = this
        or
        // argv strings (variadic for execl-family; array element for execv-family)
        exists(int i | i >= 1 and fc.getArgument(i) = this)
      )
    )
  }
}

module CommandInjectionCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof FlowSource }

  predicate isSink(DataFlow::Node n) { n.asExpr() instanceof CommandSink }

  // Equality comparisons and allowlist string-compare operations act as
  // sanitiser barriers (conservative: any comparison stops the flow).
  predicate isBarrier(DataFlow::Node n) {
    exists(ComparisonOperation cmp | cmp.getAnOperand() = n.asExpr())
    or
    exists(FunctionCall fc |
      fc.getTarget().hasGlobalOrStdName(["strcmp", "strncmp", "strcasecmp",
                                          "strncasecmp", "memcmp"]) and
      (fc.getArgument(0) = n.asExpr() or fc.getArgument(1) = n.asExpr())
    )
  }
}

module CommandInjectionFlow = TaintTracking::Global<CommandInjectionCfg>;

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Argument to shell/exec function is derived from $@ without validation — CWE-78.",
  source.getNode(), "an external source"
