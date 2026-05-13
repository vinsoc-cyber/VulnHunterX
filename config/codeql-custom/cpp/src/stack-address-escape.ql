/**
 * @name Returning address of a local (stack) variable
 * @description Returning a pointer to a stack-allocated local variable produces
 *              a dangling pointer the moment the function returns — the
 *              caller's dereference is undefined behaviour.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id cpp/stack-address-escape
 * @tags external/cwe/cwe-562
 *       security
 */

import cpp

from ReturnStmt ret, Variable local, AddressOfExpr addr
where
  // The return expression is &local
  addr = ret.getExpr() and
  addr.getOperand().(VariableAccess).getTarget() = local and
  // local is a local (stack) variable — not a parameter, not static, not global
  local instanceof LocalVariable and
  not local.isStatic() and
  not local.isThreadLocal() and
  // Function must return a pointer
  ret.getEnclosingFunction().getType().getUnderlyingType() instanceof PointerType
select ret,
  "Returning address of local variable '" + local.getName() +
  "' — caller will hold a dangling pointer."
