/**
 * @name Non-literal format string in printf-family call
 * @description A printf-family call whose format-string argument is not a
 *              string literal AND whose containing function lacks
 *              `__attribute__((format(printf, ...)))` annotation is a
 *              structurally dangerous design — even if no taint reaches
 *              it today, any future change can turn it into CWE-134.
 *              Distinct from built-in `cpp/tainted-format-string` which
 *              requires an active taint source.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id cpp/format-string-injection
 * @tags external/cwe/cwe-134
 *       security
 */

import cpp

/** A printf-family call site with a non-literal format argument. */
class PrintfLikeCall extends FunctionCall {
  int fmtIndex;

  PrintfLikeCall() {
    (
      this.getTarget().hasGlobalOrStdName(["printf", "vprintf"]) and fmtIndex = 0
      or
      this.getTarget().hasGlobalOrStdName(["fprintf", "dprintf", "vfprintf", "vdprintf"]) and fmtIndex = 1
      or
      this.getTarget().hasGlobalOrStdName(["sprintf", "vsprintf"]) and fmtIndex = 1
      or
      this.getTarget().hasGlobalOrStdName(["snprintf", "vsnprintf"]) and fmtIndex = 2
      or
      this.getTarget().hasGlobalOrStdName(["syslog", "vsyslog"]) and fmtIndex = 1
      or
      this.getTarget().hasGlobalOrStdName(["err", "verr", "warn", "vwarn", "errx", "warnx"]) and
      // BSD err/warn family — format index varies; conservatively use 0
      fmtIndex = 0
    )
  }

  Expr getFormatArg() { result = this.getArgument(fmtIndex) }
}

predicate isLiteral(Expr e) {
  e instanceof StringLiteral
  or
  // Concatenated adjacent string literals or named constants
  exists(MacroInvocation mi | mi.getExpr() = e and mi.getMacro().getBody().regexpMatch(".*\".*\".*"))
}

from PrintfLikeCall call, Expr fmt
where
  fmt = call.getFormatArg() and
  not isLiteral(fmt) and
  // Skip if the containing function is itself a printf-wrapper (format attr present)
  not call.getEnclosingFunction()
        .getAnAttribute()
        .getName() = "format"
select call,
  "Non-literal format string passed to '" + call.getTarget().getName() +
  "' — any path that reaches this with attacker influence becomes CWE-134."
