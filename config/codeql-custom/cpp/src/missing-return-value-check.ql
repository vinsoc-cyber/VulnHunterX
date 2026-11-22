/**
 * @name Missing return-value check on error-returning function
 * @description Functions that signal failure via their return value (malloc /
 *              calloc / realloc / fopen / mmap / read / write / socket /
 *              recv / send) must have that value compared to an error
 *              sentinel before subsequent use. Discarded or unchecked
 *              returns hide errors and enable null-deref / partial-IO bugs.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id cpp/missing-return-value-check
 * @tags external/cwe/cwe-252
 *       external/cwe/cwe-253
 *       security
 */

import cpp

/** A function whose return value MUST be checked for failure. */
class ErrorReturningFunction extends Function {
  ErrorReturningFunction() {
    this.hasGlobalOrStdName([
        "malloc", "calloc", "realloc", "aligned_alloc",
        "fopen", "freopen", "tmpfile", "mmap",
        "read", "write", "pread", "pwrite",
        "recv", "send", "recvfrom", "sendto",
        "socket", "accept", "connect", "bind", "listen",
        "open", "openat", "creat", "dup", "dup2",
        "fork", "pipe", "execve",
        "getline", "getdelim"
      ])
  }
}

/**
 * Holds if `call`'s return value is discarded — appears as a statement
 * expression with no enclosing assignment, comparison, condition, or
 * use as an argument / return value.
 */
predicate discardedReturn(FunctionCall call) {
  call.getTarget() instanceof ErrorReturningFunction and
  exists(ExprStmt s | s.getExpr() = call) and
  not exists(call.getParent().(Assignment)) and
  not exists(call.getParent().(Initializer))
}

/**
 * Holds if `call`'s result is stored in `v` and `v` is then dereferenced or
 * passed onward without ever appearing in a comparison or condition.
 */
predicate unCheckedReturn(FunctionCall call, Variable v) {
  call.getTarget() instanceof ErrorReturningFunction and
  exists(Initializer init |
    init.getDeclaration() = v and init.getExpr() = call
  )
  and
  not exists(EqualityOperation eq |
    eq.getAnOperand().(VariableAccess).getTarget() = v
  )
  and
  not exists(ComparisonOperation cmp |
    cmp.getAnOperand().(VariableAccess).getTarget() = v
  )
  and
  not exists(IfStmt ifs |
    ifs.getCondition().(VariableAccess).getTarget() = v
    or
    ifs.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget() = v
  )
  and
  // Followed by at least one use (dereference, member access, pass-to-function)
  exists(VariableAccess use |
    use.getTarget() = v and
    use.getEnclosingFunction() = call.getEnclosingFunction() and
    use.getLocation().getStartLine() > call.getLocation().getStartLine()
  )
}

from FunctionCall call, string msg
where
  (discardedReturn(call) and
   msg = "Return value of '" + call.getTarget().getName() +
         "' is discarded — failures (NULL / -1 / 0) silently ignored.")
  or
  exists(Variable v |
    unCheckedReturn(call, v) and
    msg = "Return value of '" + call.getTarget().getName() +
          "' stored in '" + v.getName() +
          "' but never compared to error sentinel before use.")
select call, msg
