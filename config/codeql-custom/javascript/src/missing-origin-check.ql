/**
 * @name window message handler without origin check
 * @description A handler registered via `window.addEventListener('message',
 *              fn)` or `window.onmessage = fn` that reads `event.data`
 *              without comparing `event.origin` against an allowlist
 *              accepts messages from any origin, allowing cross-frame
 *              attacks (e.g. exfiltrating data or triggering actions).
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id js/missing-origin-check
 * @tags external/cwe/cwe-346
 *       security
 */

import javascript

/** A function registered as a `message` event handler. */
class MessageHandler extends Function {
  MessageHandler() {
    exists(MethodCallExpr m |
      m.getMethodName() = "addEventListener" and
      m.getArgument(0).getStringValue() = "message" and
      this = m.getArgument(1).flow().getAFunctionValue().getFunction()
    )
    or
    exists(AssignExpr a |
      a.getTarget().toString() = "window.onmessage" and
      this = a.getRhs().flow().getAFunctionValue().getFunction()
    )
  }
}

/** Does this function read `event.origin` (any depth)? */
predicate readsOrigin(Function f) {
  exists(PropAccess pa |
    pa.getEnclosingFunction() = f and
    pa.getPropertyName() = "origin"
  )
}

/** Does this function read `event.data`? */
predicate readsData(Function f) {
  exists(PropAccess pa |
    pa.getEnclosingFunction() = f and
    pa.getPropertyName() = "data"
  )
}

from MessageHandler f
where readsData(f) and not readsOrigin(f)
select f,
  "Message handler reads event.data but never checks event.origin — " +
  "messages from any cross-origin frame are accepted."
