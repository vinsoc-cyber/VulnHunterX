/**
 * @name Timing-unsafe comparison of secret
 * @description Comparing a secret with `==` short-circuits on the first
 *              differing byte. Use `hmac.compare_digest` or
 *              `secrets.compare_digest` for any HMAC / signature /
 *              token / password digest equality check.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision low
 * @id py/timing-unsafe-comparison
 * @tags external/cwe/cwe-208
 *       security
 */

import python

bindingset[name]
predicate looksLikeSecretName(string name) {
  name.toLowerCase().regexpMatch(
    ".*(hmac|signature|sig|token|password|passwd|pwd|secret|apikey|" +
    "api_key|hash|digest|mac|nonce|csrf|jwt|session).*"
  )
}

from Compare cmp, Cmpop op, Expr operand, string name
where
  op = cmp.getOp(0) and
  (op instanceof Eq or op instanceof NotEq) and
  (operand = cmp.getLeft() or operand = cmp.getComparator(0)) and
  (
    name = operand.(Name).getId()
    or
    name = operand.(Attribute).getName()
  ) and
  looksLikeSecretName(name)
select cmp,
  "Timing-unsafe comparison involving '" + name + "'. Use " +
  "hmac.compare_digest / secrets.compare_digest for secret equality."
