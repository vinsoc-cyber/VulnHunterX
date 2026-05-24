/**
 * @name Django/DRF lookup with request param without owner filter (IDOR)
 * @description `Model.objects.get(pk=request.GET['id'])` (or via
 *              `request.POST` / `kwargs`) without filtering by the
 *              authenticated user lets anyone fetch any user's record
 *              (CWE-639).
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision low
 * @id py/incorrect-authorization
 * @tags external/cwe/cwe-639
 *       external/cwe/cwe-285
 *       security
 */

import python

/** A `Model.objects.get(pk=...)` or similar lookup call. */
class ModelLookupCall extends Call {
  ModelLookupCall() {
    exists(Attribute a |
      a = this.getFunc() and
      a.getName() in ["get", "filter", "first"]
    )
  }
}

/** Does this call have a `pk=` / `id=` kwarg whose value comes from request? */
predicate looksUpByRequestId(ModelLookupCall c) {
  exists(Keyword k |
    k = c.getAKeyword() and
    k.getArg() in ["pk", "id"] and
    exists(Attribute a |
      a = k.getValue() and
      a.getObject().toString().regexpMatch("request\\..*")
    )
  )
  or
  // request.GET['id'] or kwargs['id'] via subscript
  exists(Subscript s |
    s.getObject().toString().regexpMatch("request\\.(GET|POST|data|query_params)") and
    exists(Keyword k |
      k = c.getAKeyword() and
      k.getArg() in ["pk", "id"] and
      k.getValue() = s
    )
  )
}

/** Does the call have a `user=` / `owner=` / `created_by=` filter kwarg? */
predicate hasOwnerFilter(ModelLookupCall c) {
  exists(Keyword k |
    k = c.getAKeyword() and
    k.getArg().regexpMatch("(?i)(user|owner|created_by|account|tenant)(__.+)?")
  )
}

from ModelLookupCall c
where looksUpByRequestId(c) and not hasOwnerFilter(c)
select c,
  "Model lookup by request-supplied id without an owner/user filter — " +
  "potential IDOR (CWE-639)."
