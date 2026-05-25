/**
 * @name Unrestricted file upload written to disk
 * @description An uploaded file's name or path (from multer/formidable/busboy:
 *              req.file.filename, req.file.path, req.files[i].originalname)
 *              is written to disk via fs.writeFile / fs.createWriteStream
 *              without validating the extension against an allow-list.
 *              An attacker can upload executable content (.php, .jsp, .js,
 *              .html) and trigger remote code execution or stored XSS.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id js/unrestricted-file-upload
 * @tags external/cwe/cwe-434
 *       security
 */

import javascript
import DataFlow::PathGraph

/** A source: a property of an Express upload object (req.file / req.files). */
class UploadSource extends DataFlow::Node {
  UploadSource() {
    exists(DataFlow::PropRead pr, string p |
      p in ["filename", "originalname", "path", "name", "destination"] and
      pr.getPropertyName() = p and
      this = pr and
      // Receiver chain mentions req.file / req.files / file
      pr.getBase().asExpr().toString().regexpMatch("(?i).*(req\\.file|req\\.files|file).*")
    )
  }
}

/** A sink: the path argument of an fs write call. */
class FsWriteSink extends DataFlow::Node {
  FsWriteSink() {
    exists(DataFlow::MethodCallNode m |
      m.getReceiver().asExpr().toString() in ["fs", "fsPromises"] and
      m.getMethodName() in [
        "writeFile", "writeFileSync", "createWriteStream",
        "appendFile", "appendFileSync", "rename", "renameSync",
        "copyFile", "copyFileSync"
      ] and
      this = m.getArgument(0)
    )
  }
}

class UnrestrictedUploadConfig extends TaintTracking::Configuration {
  UnrestrictedUploadConfig() { this = "js/unrestricted-file-upload" }

  override predicate isSource(DataFlow::Node n) {
    n instanceof UploadSource or n instanceof RemoteFlowSource
  }
  override predicate isSink(DataFlow::Node n) { n instanceof FsWriteSink }
}

from UnrestrictedUploadConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Upload metadata from $@ used as file path without extension allow-list.",
  source.getNode(), "upload source"
