/**
 * @name TLS certificate validation disabled
 * @description Assigning a callback that unconditionally returns `true` to
 *              `ServerCertificateValidationCallback`,
 *              `ServerCertificateCustomValidationCallback`, or a
 *              `RemoteCertificateValidationCallback` disables TLS certificate
 *              validation, allowing man-in-the-middle attackers to intercept
 *              traffic (CWE-295). The built-in C# suite does not flag this
 *              pattern.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.4
 * @precision high
 * @id cs/certificate-validation-disabled
 * @tags security
 *       external/cwe/cwe-295
 */

import csharp

/**
 * Holds if `f` contains a `return true` (or is the expression-bodied `true`)
 * and never returns `false` — i.e. it accepts every certificate.
 */
predicate alwaysAcceptsCert(AnonymousFunctionExpr f) {
  exists(BoolLiteral t | t.getEnclosingCallable() = f and t.getValue() = "true") and
  not exists(BoolLiteral fa | fa.getEnclosingCallable() = f and fa.getValue() = "false")
}

from Assignment a, AnonymousFunctionExpr f
where
  a.getRightOperand() = f and
  alwaysAcceptsCert(f) and
  a.getLeftOperand().(PropertyAccess).getTarget().getName() =
    [
      "ServerCertificateValidationCallback", "ServerCertificateCustomValidationCallback",
      "RemoteCertificateValidationCallback"
    ]
select a,
  "TLS certificate validation callback unconditionally returns true, disabling certificate checks (CWE-295)."
