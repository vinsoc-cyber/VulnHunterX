/**
 * @name memcpy / memmove with sizeof of a pointer
 * @description A common bug: `memcpy(dst, src, sizeof(src))` where `src`
 *              is a pointer parameter (not an array) copies the pointer
 *              width (4 or 8 bytes) rather than the data it points to.
 *              The destination is silently truncated. Also catches the
 *              symmetric case where length is `sizeof(some_unrelated_var)`.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id cpp/overflow-destination
 * @tags external/cwe/cwe-805
 *       external/cwe/cwe-806
 *       security
 */

import cpp

/** A memcpy-like call. */
class BulkCopyCall extends FunctionCall {
  BulkCopyCall() {
    this.getTarget().hasGlobalOrStdName(["memcpy", "memmove", "strncpy", "strncat",
                                          "bcopy", "wmemcpy", "wmemmove"])
  }

  Expr getDest() { result = this.getArgument(0) }
  Expr getSrc() { result = this.getArgument(1) }
  Expr getLen() { result = this.getArgument(2) }
}

/** `sizeof(e)` where `e` is a pointer-typed variable access. */
predicate sizeofPointerExpr(SizeofExprOperator soe, Variable v) {
  exists(VariableAccess va |
    soe.getExprOperand() = va and
    va.getTarget() = v and
    va.getType().getUnspecifiedType() instanceof PointerType
  )
}

from BulkCopyCall call, SizeofExprOperator soe, Variable v
where
  soe = call.getLen() and
  sizeofPointerExpr(soe, v)
select call,
  "Length argument is `sizeof(" + v.getName() + ")` but '" + v.getName() +
  "' is a pointer — this copies the pointer width, not the buffer it " +
  "points to. The destination is silently truncated."
