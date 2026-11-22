/**
 * @name Read of struct field allocated with malloc but never written
 * @description A struct allocated via `malloc` (not `calloc` / `new` / value
 *              initialisation) has indeterminate contents until each field
 *              is written. Reading a field that was never assigned on at
 *              least one path before the read is undefined behaviour and
 *              may leak heap contents.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision low
 * @id cpp/use-of-uninitialized-variable
 * @tags external/cwe/cwe-457
 *       external/cwe/cwe-200
 *       security
 */

import cpp

/** A call to malloc/realloc returning a pointer to a struct type. */
class MallocStructCall extends FunctionCall {
  MallocStructCall() {
    this.getTarget().hasGlobalOrStdName(["malloc", "realloc"]) and
    this.getActualType().(PointerType).getBaseType().(Struct).hasName(_)
  }

  Struct getStructType() {
    result = this.getActualType().(PointerType).getBaseType()
  }
}

/**
 * Holds if `field` is read via `read` somewhere reachable from `alloc`
 * (i.e. on the result variable of `alloc`) without any assignment to that
 * field in between.
 */
predicate fieldReadWithoutInit(MallocStructCall alloc, Variable v, Field field, FieldAccess read) {
  // `v` receives the malloc result
  exists(Initializer init |
    init.getExpr() = alloc and init.getDeclaration() = v
  ) and
  read.getTarget() = field and
  field.getDeclaringType() = alloc.getStructType() and
  // Read through `v`
  read.getQualifier().(VariableAccess).getTarget() = v and
  // Same enclosing function
  read.getEnclosingFunction() = alloc.getEnclosingFunction() and
  // Read comes after the alloc (by line)
  read.getLocation().getStartLine() > alloc.getLocation().getStartLine() and
  // No assignment to this field of `v` between alloc and read
  not exists(FieldAccess write, AssignExpr assign |
    write.getTarget() = field and
    write.getQualifier().(VariableAccess).getTarget() = v and
    assign.getLValue() = write and
    write.getEnclosingFunction() = alloc.getEnclosingFunction() and
    write.getLocation().getStartLine() > alloc.getLocation().getStartLine() and
    write.getLocation().getStartLine() < read.getLocation().getStartLine()
  ) and
  // Skip if zeroed via memset
  not exists(FunctionCall memset |
    memset.getTarget().hasGlobalOrStdName("memset") and
    memset.getArgument(0).(VariableAccess).getTarget() = v and
    memset.getEnclosingFunction() = alloc.getEnclosingFunction() and
    memset.getLocation().getStartLine() > alloc.getLocation().getStartLine() and
    memset.getLocation().getStartLine() < read.getLocation().getStartLine()
  )
}

from MallocStructCall alloc, Variable v, Field field, FieldAccess read
where fieldReadWithoutInit(alloc, v, field, read)
select read,
  "Field '" + field.getName() + "' of struct '" +
  alloc.getStructType().getName() + "' read at this point but never " +
  "initialised after $@. malloc returns indeterminate memory; switch to " +
  "calloc or memset to zero, or assign every field before use.",
  alloc, "allocation"
