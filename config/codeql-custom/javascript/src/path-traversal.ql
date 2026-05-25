/**
 * @name Filesystem path built from tainted input
 * @description A user-controlled string flows into an `fs` path argument
 *              (readFile, writeFile, createReadStream, createWriteStream,
 *              unlink, …) without being resolved against — and confined
 *              within — a fixed base directory. An attacker can supply
 *              `../` sequences or absolute paths to read or overwrite
 *              files outside the intended directory.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id js/path-traversal
 * @tags external/cwe/cwe-22
 *       security
 */

import javascript
import DataFlow::PathGraph

/** Names of fs methods whose first argument is a path. */
private predicate fsPathMethod(string name) {
  name in [
    "readFile", "readFileSync", "writeFile", "writeFileSync",
    "appendFile", "appendFileSync", "createReadStream", "createWriteStream",
    "open", "openSync", "stat", "statSync", "lstat", "lstatSync",
    "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync",
    "readdir", "readdirSync", "access", "accessSync", "realpath",
    "realpathSync", "copyFile", "copyFileSync", "rename", "renameSync"
  ]
}

/** A sink: the path argument of an fs call. */
class FsPathSink extends DataFlow::Node {
  FsPathSink() {
    exists(DataFlow::MethodCallNode m |
      fsPathMethod(m.getMethodName()) and
      m.getReceiver().asExpr().toString() in ["fs", "fsPromises", "fs.promises"] and
      this = m.getArgument(0)
    )
  }
}

class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() { this = "js/path-traversal" }

  override predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  override predicate isSink(DataFlow::Node n) { n instanceof FsPathSink }
}

from PathTraversalConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Filesystem path from $@ is not confined to a base directory — path traversal.",
  source.getNode(), "remote source"
