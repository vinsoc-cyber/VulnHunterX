/**
 * @name Django ModelForm / DRF Serializer with fields='__all__'
 * @description A `ModelForm.Meta.fields = '__all__'` or DRF
 *              `ModelSerializer.Meta.fields = '__all__'` allows any field
 *              on the model — including `is_staff`, `is_superuser`,
 *              `password`, `user`, `created_by`, `pk` — to be set from
 *              the request body. Use an explicit field allowlist.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id py/mass-assignment
 * @tags external/cwe/cwe-915
 *       security
 */

import python

/** A Class with `Meta.fields = '__all__'`. */
class WildcardFieldsForm extends Class {
  WildcardFieldsForm() {
    exists(Class meta, AssignStmt a, StrConst s |
      meta = this.getInnerClass("Meta") and
      a.getScope() = meta and
      a.getATarget().(Name).getId() = "fields" and
      a.getValue() = s and
      s.getText() = "__all__"
    )
  }
}

/** Inherits from ModelForm / ModelSerializer / Serializer. */
predicate inheritsFromModelForm(Class c) {
  exists(string n |
    n = c.getABase().toString() and
    n.regexpMatch(".*(ModelForm|ModelSerializer|Serializer)$")
  )
}

from WildcardFieldsForm c
where inheritsFromModelForm(c)
select c,
  "Class '" + c.getName() + "' inherits a form/serializer with " +
  "Meta.fields='__all__' — all model fields are mass-assignable. " +
  "Replace with an explicit allowlist."
