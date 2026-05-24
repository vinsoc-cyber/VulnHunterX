/**
 * @name Spring @RequestBody bound to JPA entity with @Id/@Version fields
 * @description A Spring controller method that binds `@RequestBody` or
 *              `@ModelAttribute` directly to a JPA entity class containing
 *              `@Id`, `@Version`, or `@Column(updatable=false)` fields
 *              allows attackers to override those fields by including
 *              them in the request body. Use a dedicated DTO or annotate
 *              sensitive fields `@JsonIgnore`.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id java/mass-assignment
 * @tags external/cwe/cwe-915
 *       security
 */

import java

/** A parameter annotated `@RequestBody` or `@ModelAttribute`. */
class BoundRequestParam extends Parameter {
  BoundRequestParam() {
    exists(Annotation a |
      a = this.getAnAnnotation() and
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation",
                                   ["RequestBody", "ModelAttribute"])
    )
  }
}

/** A field that should never be set from a user request. */
class SensitiveField extends Field {
  SensitiveField() {
    exists(Annotation a |
      a = this.getAnAnnotation() and
      a.getType().getName() in [
        "Id", "GeneratedValue", "Version", "CreatedDate", "CreatedBy"
      ]
    )
    or
    // @Column(updatable=false)
    exists(Annotation a, AnnotationElement e |
      a = this.getAnAnnotation() and
      a.getType().hasName("Column") and
      a.getValue(_) = e and
      e.toString().regexpMatch(".*updatable.*false.*")
    )
    or
    // Names that strongly suggest sensitivity
    this.getName().regexpMatch("(?i)(role|isAdmin|admin|permissions|enabled|locked|" +
                               "passwordHash|password)")
  }
}

predicate hasJsonIgnore(Field f) {
  f.getAnAnnotation().getType().hasName(["JsonIgnore", "Transient"])
}

from BoundRequestParam param, RefType bound, SensitiveField field
where
  bound = param.getType() and
  field.getDeclaringType() = bound and
  not hasJsonIgnore(field)
select param,
  "Request body bound to entity '" + bound.getName() +
  "' which exposes sensitive field '" + field.getName() +
  "' to mass assignment. Use a DTO or annotate the field @JsonIgnore."
