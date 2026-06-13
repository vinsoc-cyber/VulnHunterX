/**
 * @name Weak cryptographic hash algorithm
 * @description Creating an MD5 or SHA-1 hash object (`MD5.Create()`,
 *              `new SHA1Managed()`, `new HMACMD5()`, etc.) for security
 *              purposes is unsafe — both are vulnerable to collisions and must
 *              not be used for integrity, signatures, or password hashing
 *              (CWE-328). Use SHA-256 or stronger. The built-in C# suite flags
 *              weak symmetric ciphers but not weak hash construction.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id cs/weak-hash
 * @tags security
 *       external/cwe/cwe-327
 *       external/cwe/cwe-328
 */

import csharp

from Call c, string algo
where
  (
    (
      c.(MethodCall).getTarget().getName() = "Create" and
      algo = c.(MethodCall).getTarget().getDeclaringType().getName()
    )
    or
    algo = c.(ObjectCreation).getTarget().getDeclaringType().getName()
  ) and
  algo.regexpMatch("(?i).*(md5|sha1).*")
select c, "Weak hash algorithm '" + algo + "' used; prefer SHA-256 or stronger (CWE-328)."
