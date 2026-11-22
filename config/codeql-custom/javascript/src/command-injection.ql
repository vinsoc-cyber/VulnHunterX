/**
 * @name OS command built from tainted input
 * @description User-controlled data passed to `child_process.exec` /
 *              `execSync`, or to `spawn` / `spawnSync` / `execFile` /
 *              `execFileSync` with `shell: true`, lets an attacker
 *              inject shell metacharacters and execute arbitrary OS
 *              commands.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id js/command-injection
 * @tags external/cwe/cwe-78
 *       security
 */

import javascript
import DataFlow::PathGraph

/** A child_process sink that runs a shell-interpreted command. */
class ShellSink extends DataFlow::Node {
  ShellSink() {
    // exec / execSync — always run via shell
    exists(DataFlow::MethodCallNode m |
      m.getMethodName() in ["exec", "execSync"] and
      m.getReceiver().asExpr().toString().regexpMatch("(?i).*child_process.*") and
      this = m.getArgument(0)
    )
    or
    exists(DataFlow::CallNode c |
      c.getCalleeName() in ["exec", "execSync"] and
      this = c.getArgument(0)
    )
    or
    // spawn / spawnSync / execFile / execFileSync with shell: true option
    exists(DataFlow::MethodCallNode m, DataFlow::Node opts |
      m.getMethodName() in ["spawn", "spawnSync", "execFile", "execFileSync"] and
      this = m.getArgument(0) and
      opts = m.getLastArgument() and
      opts.asExpr().toString().regexpMatch("(?s).*shell\\s*:\\s*true.*")
    )
  }
}

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "js/command-injection" }

  override predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  override predicate isSink(DataFlow::Node n) { n instanceof ShellSink }
}

from CommandInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Value from $@ flows into shell-interpreted command — OS command injection.",
  source.getNode(), "remote source"
