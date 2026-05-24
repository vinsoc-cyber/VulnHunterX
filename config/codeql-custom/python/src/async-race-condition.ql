/**
 * @name async function mutates module-level state without lock
 * @description An `async def` that reads-then-writes a module-level
 *              mutable (dict / list / set / Counter) without holding
 *              an `asyncio.Lock` can lose updates when interleaved
 *              between awaits.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.5
 * @precision low
 * @id py/async-race-condition
 * @tags external/cwe/cwe-362
 *       security
 */

import python

/** A module-level variable bound to a mutable container literal. */
class ModuleMutable extends Variable {
  ModuleMutable() {
    exists(AssignStmt a, Expr rhs |
      a.getATarget().(Name).getVariable() = this and
      a.getScope() instanceof Module and
      rhs = a.getValue() and
      (
        rhs instanceof Dict or
        rhs instanceof List or
        rhs instanceof Set or
        rhs.(Call).getFunc().toString() in [
          "dict", "list", "set", "Counter", "defaultdict"
        ]
      )
    )
  }
}

class AsyncFunction extends Function {
  AsyncFunction() { this.isAsync() }
}

predicate readsAndWritesVar(AsyncFunction f, Variable v) {
  exists(Name read | read.getScope*() = f and read.getVariable() = v and
         not exists(AssignStmt a | a.getATarget() = read)) and
  exists(Name write | write.getScope*() = f and write.getVariable() = v and
         exists(AssignStmt a | a.getATarget() = write or
                              exists(AugAssign aa | aa.getTarget() = write)))
}

predicate holdsLock(Function f) {
  // crude: any `async with` block in the function
  exists(With w | w.getScope*() = f and w.isAsync())
}

from AsyncFunction f, ModuleMutable v
where readsAndWritesVar(f, v) and not holdsLock(f)
select f,
  "Async function '" + f.getName() + "' reads and writes module-level " +
  "mutable '" + v.getId() + "' without holding an asyncio.Lock — " +
  "updates can be lost via await interleaving."
