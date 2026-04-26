// SPDX-License-Identifier: MIT
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract destructor / cleanup methods per type
 * @description Maps each class/struct type name to its destructor (or
 *              cleanup-like member function) so VulnHunterX can answer
 *              "what kills this object?" via the `destructor:<type>` request.
 *              Picks up: C++ destructors (~T()), member functions named
 *              cleanup/release/destroy/dispose/close, and free-function
 *              cleanup helpers whose name contains the type name.
 * @kind table
 * @id cpp/tool-destructors
 */

import cpp

/** Member functions that look like destructors / disposers. */
predicate isCleanupName(string name) {
  name = "release" or
  name = "cleanup" or
  name = "destroy" or
  name = "dispose" or
  name = "Close" or
  name = "close" or
  name = "shutdown" or
  name.matches("~%")
}

from Class c, MemberFunction m
where
  c.hasDefinition() and
  m.getDeclaringType() = c and
  m.hasDefinition() and
  (m instanceof Destructor or isCleanupName(m.getName()))
select
  c.getName() as type_name,
  m.getName() as method_name,
  m.getFile().getRelativePath() as file,
  m.getLocation().getStartLine() as start_line,
  m.getBlock().getLocation().getEndLine() as end_line
