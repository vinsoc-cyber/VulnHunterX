/**
 * @name Non-constant-time comparison of a secret
 * @description Comparing a security-sensitive value (password, token, HMAC,
 *              signature, MAC, API key) with `==`, `!=`, `Equals`, or
 *              `SequenceEqual` short-circuits on the first differing byte,
 *              leaking length/content through timing (CWE-208). Such checks
 *              should use a constant-time comparator
 *              (`CryptographicOperations.FixedTimeEquals`). This pattern is
 *              not flagged by the built-in C# suite.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.9
 * @precision low
 * @id cs/timing-unsafe-comparison
 * @tags security
 *       external/cwe/cwe-208
 */

import csharp

/** Holds if `n` looks like the name of a security-sensitive value. */
bindingset[n]
predicate secretName(string n) {
  n.regexpMatch("(?i).*(password|passwd|secret|token|hmac|signature|apikey|api_key|auth|\\bmac\\b|digest|nonce).*")
}

/** An access to a variable or property whose name suggests a secret. */
predicate isSecretExpr(Expr e) {
  secretName(e.(VariableAccess).getTarget().getName())
  or
  secretName(e.(PropertyAccess).getTarget().getName())
}

from Expr cmp
where
  (
    cmp instanceof EqualityOperation
    or
    cmp.(MethodCall).getTarget().getName() = ["Equals", "SequenceEqual"]
  ) and
  isSecretExpr(cmp.getAChildExpr())
select cmp,
  "Security-sensitive value compared with a non-constant-time operator; use CryptographicOperations.FixedTimeEquals (CWE-208)."
