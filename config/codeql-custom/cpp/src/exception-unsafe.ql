/**
 * @name Resource acquired without RAII can leak on exception
 * @description A bare new/malloc/fopen acquisition followed by code that may
 *              throw, without the resource owned by an RAII type
 *              (smart pointer, std::lock_guard, etc.), leaks the resource if
 *              the intermediate code throws.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision low
 * @id cpp/exception-unsafe
 * @tags external/cwe/cwe-755
 *       security
 *       correctness
 */

import cpp

/** A bare `new T` not immediately wrapped in a smart pointer. */
class BareNew extends NewExpr {
  BareNew() {
    // Not part of a std::make_unique / make_shared / smart_ptr construction
    not exists(FunctionCall mk |
      mk.getAnArgument().getAChild*() = this and
      mk.getTarget().getQualifiedName().regexpMatch("std::(make_unique|make_shared|unique_ptr|shared_ptr).*")
    )
  }
}

from BareNew alloc, Function f, ThrowExpr t
where
  f = alloc.getEnclosingFunction() and
  // Some throw in the same function after the allocation
  t.getEnclosingFunction() = f and
  t.getLocation().getStartLine() > alloc.getLocation().getStartLine()
select alloc,
  "Raw `new` allocation in a function that may throw at $@ — wrap in RAII " +
  "(std::unique_ptr / std::make_unique) to avoid leak on exception.",
  t, "this throw expression"
