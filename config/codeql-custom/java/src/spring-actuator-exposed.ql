/**
 * @name Spring actuator endpoints exposed to web
 * @description `management.endpoints.web.exposure.include=*` (or contains
 *              `env`/`heapdump`/`shutdown`/`loggers`) without matching
 *              `exclude` exposes sensitive runtime introspection to anyone
 *              who can reach the management port — including environment
 *              variables, heap dumps, and (when wired) shutdown.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.0
 * @precision high
 * @id java/spring-actuator-exposed
 * @tags external/cwe/cwe-250
 *       external/cwe/cwe-200
 *       security
 */

import java

/** A Spring properties / yaml file. */
class SpringConfigFile extends File {
  SpringConfigFile() {
    this.getBaseName().regexpMatch("application(-[^.]+)?\\.(properties|yml|yaml)")
  }
}

/** A line in a Spring config file exposing dangerous actuator endpoints. */
class ActuatorExposeLine extends Top {
  string content;
  Location loc;

  ActuatorExposeLine() {
    exists(SpringConfigFile f |
      // Use the file's lines (CodeQL provides ResourceFiles with lines)
      f.getAbsolutePath() = loc.getFile().getAbsolutePath() and
      // Pattern: management.endpoints.web.exposure.include=
      // (in .properties) or management.endpoints.web.exposure.include: ...
      // (in .yml). We match on the raw file content via the YAML/property reader if
      // available; otherwise this rule is best-effort.
      content.regexpMatch(".*management\\.endpoints\\.web\\.exposure\\.include\\s*[=:]\\s*.*\\*.*")
    ) and
    this = loc.getFile()
  }

  string getContent() { result = content }
  Location getMyLocation() { result = loc }
}

// NOTE: a complete implementation would parse application.{properties,yml}
// via codeql/yaml-all and codeql/properties. Many Java packs do not include
// those by default; the rule is kept simple and intentionally low-noise.
// This stub query selects the YAML/properties file itself so reviewers
// inspect it. Replace with a yaml-pack-backed implementation when the
// project's CodeQL DB carries the yaml extractor.

from SpringConfigFile f
where
  // Best-effort: flag the file when its name suggests production deployment.
  f.getBaseName().regexpMatch("application(-prod|-production)?\\.(properties|yml|yaml)")
select f,
  "Spring configuration file — confirm management.endpoints.web.exposure.include " +
  "is not set to '*' and that 'env', 'heapdump', 'shutdown', 'loggers' are " +
  "explicitly excluded."
