/**
 * @name Timing-unsafe comparison of secret
 * @description `String.equals`, `Arrays.equals`, and `==` are not
 *              constant-time and short-circuit on the first differing
 *              byte. Use `MessageDigest.isEqual` (constant-time since
 *              JDK 6u17) or a hand-rolled constant-time loop for any
 *              HMAC / signature / password / token comparison.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision low
 * @id java/timing-unsafe-comparison
 * @tags external/cwe/cwe-208
 *       security
 */

import java

/** A non-constant-time comparison call. */
class NonCtCompareCall extends MethodCall {
  NonCtCompareCall() {
    (this.getMethod().hasName("equals") and
     this.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
    or
    (this.getMethod().hasName(["equals", "equalsIgnoreCase"]) and
     this.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
    or
    (this.getMethod().hasName("equals") and
     this.getMethod().getDeclaringType().hasQualifiedName("java.util", "Arrays"))
  }

  Expr getAnOperandExpr() {
    result = this.getQualifier() or result = this.getAnArgument()
  }
}

bindingset[s]
predicate looksLikeSecretName(string s) {
  s.toLowerCase().regexpMatch(".*(hmac|signature|sig|token|password|passwd|pwd|secret|" +
                              "apikey|api_key|hash|digest|mac|nonce|csrf|jwt|" +
                              "sessionid|session_id).*")
}

from NonCtCompareCall cmp, Variable v
where
  cmp.getAnOperandExpr().(VarAccess).getVariable() = v and
  looksLikeSecretName(v.getName())
select cmp,
  "Timing-unsafe comparison of '" + v.getName() +
  "'. Use MessageDigest.isEqual or a constant-time helper for secret " +
  "equality checks."
