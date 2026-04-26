// SPDX-License-Identifier: MIT
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract free / delete / destructor call sites
 * @description Maps each pointer expression to every site that releases its memory.
 *              Used by VulnHunterX's `free_sites:<pointer_name>` context request to
 *              answer "where is this pointer freed?" without snippet-grepping.
 *              Picks up free(), kfree(), delete, delete[], and any function call whose
 *              name matches a free-like pattern (free, release, destroy, dispose, close).
 * @kind table
 * @id cpp/tool-free-sites
 */

import cpp

/**
 * Best-effort textual representation of a pointer expression — the variable
 * or member access used as the argument to a free-like call. Stripped of
 * leading address-of / cast noise so callers can match on simple names.
 */
string ptrText(Expr e) {
  result = e.toString()
}

/** Holds if `name` looks like a deallocator / disposer function. */
predicate isFreeName(string name) {
  name = "free" or
  name = "kfree" or
  name = "vfree" or
  name = "kzfree" or
  name = "g_free" or
  name = "xfree" or
  name = "release" or
  name = "destroy" or
  name = "dispose" or
  name = "Close" or
  name = "close_socket" or
  name.matches("%_free") or
  name.matches("%_destroy") or
  name.matches("%_release") or
  name.matches("%_dispose") or
  name.matches("free_%") or
  name.matches("destroy_%") or
  name.matches("release_%")
}

from FunctionCall fc, Expr arg, Function caller, string kind
where
  fc.getEnclosingFunction() = caller and
  caller.hasDefinition() and
  isFreeName(fc.getTarget().getName()) and
  arg = fc.getArgument(0) and
  kind = fc.getTarget().getName()
select
  ptrText(arg) as pointer_name,
  kind as free_kind,
  caller.getName() as in_function,
  fc.getFile().getRelativePath() as file,
  fc.getLocation().getStartLine() as line
