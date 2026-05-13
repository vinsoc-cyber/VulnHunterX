/**
 * @name alloca() inside a loop
 * @description Calling `alloca()` inside a loop body causes the stack to grow
 *              by one allocation per iteration — for large iteration counts
 *              this leads to uncontrolled stack consumption and crash.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision high
 * @id cpp/alloca-in-loop
 * @tags external/cwe/cwe-674
 *       security
 */

import cpp

/** A call to `alloca`, `_alloca`, or `__builtin_alloca`. */
class AllocaCall extends FunctionCall {
  AllocaCall() {
    this.getTarget().getName().regexpMatch("_*alloca|__builtin_alloca")
  }
}

from AllocaCall alloca, Loop loop
where
  loop = alloca.getEnclosingStmt().getParentStmt*() and
  loop.getEnclosingFunction() = alloca.getEnclosingFunction()
select alloca,
  "alloca() called inside a " + loop.getAPrimaryQlClass() +
  " — stack grows by one allocation per iteration."
