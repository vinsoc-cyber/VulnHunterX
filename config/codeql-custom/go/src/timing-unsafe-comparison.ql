/**
 * @name Timing-unsafe comparison of secret
 * @description `bytes.Equal`, `==`, and `strings.EqualFold` short-circuit
 *              on first differing byte. Use
 *              `crypto/subtle.ConstantTimeCompare` for any HMAC /
 *              signature / token / API key comparison.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision low
 * @id go/timing-unsafe-comparison
 * @tags external/cwe/cwe-208
 *       security
 */

import go

bindingset[name]
predicate looksLikeSecretName(string name) {
  name.toLowerCase().regexpMatch(
    ".*(hmac|signature|sig|token|password|passwd|pwd|secret|apikey|" +
    "api_key|hash|digest|mac|nonce|csrf|jwt|sessionid|session_id).*"
  )
}

class SecretLikeIdent extends Ident {
  SecretLikeIdent() { looksLikeSecretName(this.getName()) }
}

from EqualityTestExpr cmp, Expr operand
where
  operand = cmp.getAnOperand() and
  (
    operand instanceof SecretLikeIdent
    or
    operand.(SelectorExpr).getSelector() instanceof SecretLikeIdent
  )
select cmp,
  "Timing-unsafe == on secret-named value. Use " +
  "crypto/subtle.ConstantTimeCompare."
