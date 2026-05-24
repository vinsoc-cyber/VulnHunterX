/**
 * @name Timing-unsafe comparison of secret
 * @description `memcmp` / `strcmp` / `strncmp` / `==` short-circuit on the
 *              first differing byte, leaking secret content via response
 *              time. Use OpenSSL `CRYPTO_memcmp` or libsodium
 *              `sodium_memcmp` for any HMAC / token / password digest.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision low
 * @id cpp/timing-unsafe-comparison
 * @tags external/cwe/cwe-208
 *       security
 */

import cpp

/** A short-circuit byte-comparison function call. */
class ShortCircuitByteCompare extends FunctionCall {
  ShortCircuitByteCompare() {
    this.getTarget().hasGlobalOrStdName(["memcmp", "strcmp", "strncmp",
                                          "strcasecmp", "strncasecmp", "bcmp"])
  }

  Expr getAnOperandExpr() { result = this.getArgument([0, 1]) }
}

/** A token name that suggests one operand is a secret. */
bindingset[s]
predicate looksLikeSecretName(string s) {
  s.toLowerCase().regexpMatch(".*(hmac|signature|sig|token|password|passwd|pwd|secret|" +
                              "apikey|api_key|hash|digest|mac|nonce|session).*")
}

from ShortCircuitByteCompare cmp, Expr operand, Variable v
where
  operand = cmp.getAnOperandExpr() and
  operand.(VariableAccess).getTarget() = v and
  looksLikeSecretName(v.getName())
select cmp,
  "Timing-unsafe comparison of '" + v.getName() + "' via '" +
  cmp.getTarget().getName() + "'. Use CRYPTO_memcmp or sodium_memcmp " +
  "for any secret-equality check."
