// SPDX-License-Identifier: MIT
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract every write to a struct/class field
 * @description Maps `<TypeName>.<field>` to every site that writes to that
 *              field across the repo. Used for `field_writes:<T.f>` context
 *              requests that catch shared-state UAF / TOCTOU patterns where
 *              one method frees `obj->ptr` while another method still uses it.
 * @kind table
 * @id cpp/tool-field-writes
 */

import cpp

from FieldAccess fa, Field f, Function fn, Type t, Assignment a
where
  fa.getTarget() = f and
  f.getDeclaringType() = t and
  fa.getEnclosingFunction() = fn and
  fn.hasDefinition() and
  // Only writes — assignments where the field-access is the LHS
  a.getLValue() = fa
select
  t.getName() + "." + f.getName() as type_field,
  fn.getName() as in_function,
  fa.getFile().getRelativePath() as file,
  fa.getLocation().getStartLine() as line
