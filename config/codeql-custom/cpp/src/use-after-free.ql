/**
 * @name Use of pointer after free / delete
 * @description A pointer that has been passed to `free()` (or destroyed by
 *              `delete` / `delete[]`) and is subsequently dereferenced or
 *              passed by value to another function without first being
 *              reassigned or NULLed is CWE-416 (use-after-free). Distinct
 *              from `cpp/dangling-pointer` which targets address-of-local
 *              escape patterns. Conservative: same-function AST scan only,
 *              precision medium.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @id cpp/use-after-free
 * @tags external/cwe/cwe-416
 *       security
 */

import cpp

/** A call to `free()` or a `delete`/`delete[]` expression that releases `v`. */
class FreeOrDelete extends Expr {
  Variable target;

  FreeOrDelete() {
    exists(FunctionCall fc |
      fc = this and
      fc.getTarget().hasGlobalOrStdName(["free", "g_free", "kfree", "vfree"]) and
      fc.getArgument(0).(VariableAccess).getTarget() = target
    )
    or
    exists(DeleteExpr de |
      de = this and
      de.getExpr().(VariableAccess).getTarget() = target
    )
    or
    exists(DeleteArrayExpr dae |
      dae = this and
      dae.getExpr().(VariableAccess).getTarget() = target
    )
  }

  Variable getTargetVar() { result = target }
}

/** A use of variable `v` as a pointer (deref, field access, or passed to a function). */
predicate pointerUse(Variable v, Expr use) {
  exists(PointerDereferenceExpr pde | pde = use and
    pde.getOperand().(VariableAccess).getTarget() = v
  )
  or
  exists(PointerFieldAccess pfa | pfa = use and
    pfa.getQualifier().(VariableAccess).getTarget() = v
  )
  or
  exists(ArrayExpr ae | ae = use and
    ae.getArrayBase().(VariableAccess).getTarget() = v
  )
  or
  // Passing the pointer to another function (potential further use)
  exists(FunctionCall fc, int i |
    fc.getArgument(i) = use and
    use.(VariableAccess).getTarget() = v and
    // Exclude free()/delete itself — handled by the FreeOrDelete class
    not fc.getTarget().hasGlobalOrStdName(["free", "g_free", "kfree", "vfree"])
  )
}

/** Reassignment of `v` (would invalidate UAF chain). */
predicate reassigns(Variable v, AssignExpr assign) {
  assign.getLValue().(VariableAccess).getTarget() = v
}

from FreeOrDelete fr, Variable v, Expr use
where
  v = fr.getTargetVar() and
  pointerUse(v, use) and
  fr.getEnclosingFunction() = use.getEnclosingFunction() and
  // Use textually follows the free
  use.getLocation().getStartLine() > fr.getLocation().getStartLine() and
  // No reassignment of `v` between the free and the use
  not exists(AssignExpr ra |
    reassigns(v, ra) and
    ra.getEnclosingFunction() = fr.getEnclosingFunction() and
    ra.getLocation().getStartLine() > fr.getLocation().getStartLine() and
    ra.getLocation().getStartLine() < use.getLocation().getStartLine()
  )
select use,
  "Pointer '" + v.getName() + "' is used after being freed at $@.",
  fr, "this free/delete"
