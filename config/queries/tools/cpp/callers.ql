// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract function caller relationships
 * @description Maps each function to its callers for context expansion
 * @kind table
 * @id cpp/tool-callers
 */

import cpp

from Function callee, Function caller, FunctionCall call
where
  call.getTarget() = callee and
  call.getEnclosingFunction() = caller and
  callee.hasDefinition()
select
  callee.getName() as callee_name,
  callee.getFile().getRelativePath() as callee_file,
  caller.getName() as caller_name,
  caller.getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_start_line,
  caller.getBlock().getLocation().getEndLine() as caller_end_line
