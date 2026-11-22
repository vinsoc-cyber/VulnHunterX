/**
 * @name Pointer to expired local object
 * @description A pointer that captures the address of a local variable
 *              becomes dangling once that variable's scope ends. Returning
 *              such a pointer or storing it in a longer-lived owner produces
 *              CWE-825 (expired pointer dereference).
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id cpp/dangling-pointer
 * @tags external/cwe/cwe-825
 *       security
 */

import cpp

/** An assignment that stores the address of a local variable into a non-local pointer. */
predicate storesAddressOfLocalToNonLocal(AssignExpr assign, LocalVariable local) {
  exists(AddressOfExpr addr |
    addr = assign.getRValue() and
    addr.getOperand().(VariableAccess).getTarget() = local and
    not local.isStatic() and
    not local.isThreadLocal()
  ) and
  exists(VariableAccess lhs |
    lhs = assign.getLValue() and
    not lhs.getTarget() instanceof LocalVariable
    or
    // Or LHS dereferences a parameter pointer (assigning through it)
    assign.getLValue() instanceof PointerDereferenceExpr
  )
}

from AssignExpr assign, LocalVariable local
where storesAddressOfLocalToNonLocal(assign, local)
select assign,
  "Address of local variable '" + local.getName() +
  "' stored in non-local pointer — becomes dangling on function return."
