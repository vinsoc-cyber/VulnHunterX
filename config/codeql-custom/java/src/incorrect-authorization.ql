/**
 * @name Repository lookup with controller path/query parameter, no
 *       ownership check (IDOR)
 * @description A Spring controller handler reads a path/query parameter
 *              and passes it directly to a Spring Data repository
 *              `findById` / `getOne` / `getReferenceById` without any
 *              filter on the authenticated user. Anyone authenticated
 *              can fetch other users' records (CWE-639).
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision low
 * @id java/incorrect-authorization
 * @tags external/cwe/cwe-639
 *       external/cwe/cwe-285
 *       security
 */

import java

/** A Spring controller / REST method. */
class SpringHandler extends Method {
  SpringHandler() {
    exists(Annotation a |
      a = this.getAnAnnotation() and
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation",
        ["GetMapping", "PostMapping", "PutMapping", "DeleteMapping",
         "PatchMapping", "RequestMapping"])
    )
  }
}

/** A parameter annotated `@PathVariable` or `@RequestParam`. */
class PathOrRequestParam extends Parameter {
  PathOrRequestParam() {
    exists(Annotation a |
      a = this.getAnAnnotation() and
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation",
        ["PathVariable", "RequestParam"])
    )
  }
}

/** A Spring Data findById-style call. */
class RepoFindByIdCall extends MethodCall {
  RepoFindByIdCall() {
    this.getMethod().hasName(["findById", "getOne", "getReferenceById", "findOne"])
  }
}

predicate hasAuthAnnotation(Method m) {
  exists(Annotation a |
    a = m.getAnAnnotation() and
    a.getType().getName() in [
      "PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed", "DenyAll"
    ]
  )
}

from SpringHandler handler, PathOrRequestParam p, RepoFindByIdCall find
where
  p.getCallable() = handler and
  find.getEnclosingCallable() = handler and
  // The lookup uses the parameter as the id argument
  find.getArgument(0).(VarAccess).getVariable() = p and
  not hasAuthAnnotation(handler)
select find,
  "Repository '" + find.getMethod().getName() + "' called with path/query " +
  "parameter '" + p.getName() + "' in handler '" + handler.getName() +
  "' that has no @PreAuthorize / @Secured / role check — potential IDOR."
