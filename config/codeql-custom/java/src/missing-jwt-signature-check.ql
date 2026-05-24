/**
 * @name JWT decoded but signature not verified
 * @description A JWT decoded via `JWT.decode(token)` / `Jwts.parser().parse(token)`
 *              (rather than `parseClaimsJws` / `verify`) returns claims even
 *              when the signature is invalid or absent (`alg: none`). Trusting
 *              such a token enables authentication bypass.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision medium
 * @id java/missing-jwt-signature-check
 * @tags external/cwe/cwe-347
 *       security
 */

import java

/** A JWT-decode call that does NOT verify the signature. */
class UnsafeJwtDecode extends MethodCall {
  UnsafeJwtDecode() {
    // com.auth0.jwt: JWT.decode(token) — no verification
    this.getMethod().hasName("decode") and
    this.getMethod().getDeclaringType().hasQualifiedName("com.auth0.jwt", "JWT")
    or
    // jjwt: Jwts.parser().parse(token) — generic parse returns Jwt<?,?>, no verify
    this.getMethod().hasName("parse") and
    this.getMethod().getDeclaringType()
        .getQualifiedName().regexpMatch("io\\.jsonwebtoken\\..*")
    or
    // nimbus: SignedJWT.parse(token) without subsequent .verify()
    this.getMethod().hasName("parse") and
    this.getMethod().getDeclaringType().hasName("SignedJWT")
  }
}

/** A method call that does verify a JWT signature. */
class JwtVerifyCall extends MethodCall {
  JwtVerifyCall() {
    this.getMethod().hasName(["verify", "parseClaimsJws", "parseSignedClaims"])
  }
}

from UnsafeJwtDecode decode
where
  // No verify call appears in the same callable (very conservative — false positives
  // possible when verification happens in a helper, but the goal here is to flag
  // the structurally unsafe pattern).
  not exists(JwtVerifyCall verify |
    verify.getEnclosingCallable() = decode.getEnclosingCallable()
  )
select decode,
  "JWT decoded without signature verification. " +
  decode.getMethod().getDeclaringType().getName() + "." +
  decode.getMethod().getName() +
  " returns claims even for unsigned / forged tokens — use a verifying " +
  "parser (Algorithm + JWTVerifier, parseClaimsJws, SignedJWT.verify)."
