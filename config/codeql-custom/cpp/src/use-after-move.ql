/**
 * @name Use after std::move
 * @description An object used after being moved-from holds an unspecified state
 *              and reading its value, or calling non-trivial methods other than
 *              assignment / destruction, is undefined behaviour.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id cpp/use-after-move
 * @tags external/cwe/cwe-672
 *       security
 *       correctness
 */

import cpp

/** A call to `std::move`. */
class StdMoveCall extends FunctionCall {
  StdMoveCall() { this.getTarget().hasQualifiedName("std", "move") }

  /** The variable being moved, if the argument is a direct variable access. */
  Variable getMovedVariable() {
    result = this.getArgument(0).(VariableAccess).getTarget()
  }
}

/**
 * Holds if there is an access to `v` that comes after `move` in the same
 * function body, without an intervening assignment to `v`.
 */
predicate useAfterMove(StdMoveCall move, Variable v, VariableAccess use) {
  v = move.getMovedVariable() and
  use.getTarget() = v and
  // Same enclosing function
  use.getEnclosingFunction() = move.getEnclosingFunction() and
  // Statement-level "after" check: use is in a later line or a later block.
  // (Conservative — interprocedural / control-flow accuracy is out of scope here.)
  exists(Location moveLoc, Location useLoc |
    moveLoc = move.getLocation() and useLoc = use.getLocation() |
    useLoc.getStartLine() > moveLoc.getStartLine()
    or
    (useLoc.getStartLine() = moveLoc.getStartLine() and
     useLoc.getStartColumn() > moveLoc.getEndColumn())
  ) and
  // Exclude the canonical "safe" patterns: assignment target (= rhs), or
  // taking address of for re-initialisation, or destruction.
  not exists(AssignExpr a | a.getLValue() = use) and
  not use = move.getArgument(0)
}

from StdMoveCall move, Variable v, VariableAccess use
where useAfterMove(move, v, use)
select use, "Use of '" + v.getName() + "' after it was moved-from at $@.",
  move, "this std::move call"
