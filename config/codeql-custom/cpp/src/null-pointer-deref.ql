/**
 * @name Possible NULL pointer dereference after allocation
 * @description A pointer returned from malloc / calloc / realloc that is
 *              dereferenced without first being compared against NULL is a
 *              guaranteed crash on allocation failure (CWE-476) and on
 *              attacker-influenced size-zero / out-of-memory paths can be
 *              promoted into a DoS or worse. Conservative: only flags
 *              allocations whose result reaches a dereference in the same
 *              function without an intervening NULL check.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id cpp/null-pointer-deref
 * @tags external/cwe/cwe-476
 *       security
 */

import cpp

/** A call returning a possibly-NULL heap pointer. */
class PossiblyNullAllocCall extends FunctionCall {
  PossiblyNullAllocCall() {
    this.getTarget().hasGlobalOrStdName(["malloc", "calloc", "realloc", "reallocarray",
                                          "aligned_alloc", "strdup", "strndup"])
  }
}

/** An assignment that stores the result of an allocation call into a variable. */
predicate allocAssignedTo(PossiblyNullAllocCall alloc, Variable v, AssignExpr assign) {
  assign.getRValue() = alloc and
  assign.getLValue().(VariableAccess).getTarget() = v
}

/** A NULL-comparison of variable `v` (either `v == NULL`, `!v`, or `v != NULL`). */
predicate nullChecks(Variable v, Expr check) {
  exists(EQExpr eq | eq = check |
    eq.getAnOperand().(VariableAccess).getTarget() = v and
    eq.getAnOperand() instanceof NullValue
  )
  or
  exists(NEExpr ne | ne = check |
    ne.getAnOperand().(VariableAccess).getTarget() = v and
    ne.getAnOperand() instanceof NullValue
  )
  or
  exists(NotExpr n | n = check and
    n.getOperand().(VariableAccess).getTarget() = v
  )
  or
  // Plain `if (v)` — the conditional itself is the check
  exists(IfStmt ifs | ifs.getCondition() = check and
    check.(VariableAccess).getTarget() = v
  )
}

/** A dereference of variable `v` (read, write, or member access through pointer). */
predicate derefsVar(Variable v, Expr deref) {
  exists(PointerDereferenceExpr pde | pde = deref and
    pde.getOperand().(VariableAccess).getTarget() = v
  )
  or
  exists(PointerFieldAccess pfa | pfa = deref and
    pfa.getQualifier().(VariableAccess).getTarget() = v
  )
  or
  exists(ArrayExpr ae | ae = deref and
    ae.getArrayBase().(VariableAccess).getTarget() = v
  )
}

from PossiblyNullAllocCall alloc, Variable v, AssignExpr assign, Expr deref
where
  allocAssignedTo(alloc, v, assign) and
  derefsVar(v, deref) and
  // Dereference is in the same function as the assignment
  deref.getEnclosingFunction() = assign.getEnclosingFunction() and
  // Dereference happens textually after the assignment
  deref.getLocation().getStartLine() > assign.getLocation().getStartLine() and
  // No NULL check on `v` between the assignment and the dereference
  not exists(Expr check |
    nullChecks(v, check) and
    check.getEnclosingFunction() = assign.getEnclosingFunction() and
    check.getLocation().getStartLine() > assign.getLocation().getStartLine() and
    check.getLocation().getStartLine() < deref.getLocation().getStartLine()
  ) and
  // Skip if pointer is reassigned between alloc and deref (would invalidate analysis)
  not exists(AssignExpr ra |
    ra.getLValue().(VariableAccess).getTarget() = v and
    ra != assign and
    ra.getEnclosingFunction() = assign.getEnclosingFunction() and
    ra.getLocation().getStartLine() > assign.getLocation().getStartLine() and
    ra.getLocation().getStartLine() < deref.getLocation().getStartLine()
  )
select deref,
  "Pointer '" + v.getName() + "' assigned from $@ is dereferenced without a NULL check.",
  alloc, "this allocation"
