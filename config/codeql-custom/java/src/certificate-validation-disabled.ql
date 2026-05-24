/**
 * @name TrustManager or HostnameVerifier accepts any certificate / host
 * @description A `X509TrustManager` whose `checkClientTrusted` or
 *              `checkServerTrusted` body is empty, OR a `HostnameVerifier`
 *              whose `verify` returns `true` unconditionally, disables
 *              TLS authentication and exposes the connection to MITM.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @id java/certificate-validation-disabled
 * @tags external/cwe/cwe-295
 *       external/cwe/cwe-297
 *       security
 */

import java

/** A method that declares it `throws CertificateException` (or any subclass). */
class TrustManagerCheckMethod extends Method {
  TrustManagerCheckMethod() {
    this.hasName(["checkClientTrusted", "checkServerTrusted"]) and
    this.getDeclaringType().getASupertype*()
        .hasQualifiedName("javax.net.ssl", "X509TrustManager")
  }
}

/** Method body is empty / trivially returns. */
predicate isNoOp(Method m) {
  m.getBody().getNumStmt() = 0
  or
  // Only contains a single `return` statement
  (m.getBody().getNumStmt() = 1 and
   m.getBody().getStmt(0) instanceof ReturnStmt)
}

/** HostnameVerifier.verify that returns `true` unconditionally. */
class AlwaysTrueHostnameVerifier extends Method {
  AlwaysTrueHostnameVerifier() {
    this.hasName("verify") and
    this.getDeclaringType().getASupertype*()
        .hasQualifiedName("javax.net.ssl", "HostnameVerifier") and
    // Body returns true via a single return
    exists(ReturnStmt r |
      r = this.getBody().getAStmt() and
      r.getResult().(BooleanLiteral).getBooleanValue() = true
    )
  }
}

from Method m, string desc
where
  (m instanceof TrustManagerCheckMethod and isNoOp(m) and
   desc = "TrustManager." + m.getName() + " is a no-op")
  or
  (m instanceof AlwaysTrueHostnameVerifier and
   desc = "HostnameVerifier.verify unconditionally returns true")
select m,
  desc + " — TLS authentication is effectively disabled, exposing the " +
  "connection to MITM."
