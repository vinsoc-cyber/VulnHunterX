// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract function caller relationships
 * @description Maps each function to its callers for context expansion
 * @kind table
 * @id js/tool-callers
 */

import javascript

from InvokeExpr call, Function callee, Function caller
where
  call.getCallee().(VarAccess).getVariable().getAnAssignedExpr() = callee and
  call.getEnclosingFunction() = caller
select
  callee.getName() as callee_name,
  callee.getFile().getRelativePath() as callee_file,
  caller.getName() as caller_name,
  caller.getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_start_line,
  caller.getLocation().getEndLine() as caller_end_line
