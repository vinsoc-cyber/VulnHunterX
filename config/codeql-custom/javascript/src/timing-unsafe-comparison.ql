/**
 * @name Timing-unsafe comparison of secret
 * @description `==` / `===` / `!==` short-circuit on the first differing
 *              character. Use `crypto.timingSafeEqual(Buffer.from(a),
 *              Buffer.from(b))` for any HMAC / signature / token / API key
 *              comparison.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision low
 * @id js/timing-unsafe-comparison
 * @tags external/cwe/cwe-208
 *       security
 */

import javascript

bindingset[name]
predicate looksLikeSecretName(string name) {
  name.toLowerCase().regexpMatch(
    ".*(hmac|signature|sig|token|password|passwd|pwd|secret|apikey|" +
    "api_key|hash|digest|mac|nonce|csrf|jwt|sessionid|session_id|cookie).*"
  )
}

from EqualityTest cmp, Expr operand, string name
where
  operand = cmp.getAnOperand() and
  (
    name = operand.(VarRef).getName()
    or
    name = operand.(PropAccess).getPropertyName()
  ) and
  looksLikeSecretName(name)
select cmp,
  "Timing-unsafe comparison involving '" + name + "'. " +
  "Use crypto.timingSafeEqual for secret equality."
