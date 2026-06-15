// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract method caller relationships
 * @description Maps each method to its callers for context expansion
 * @kind table
 * @id java/tool-callers
 */

import java

from Call call, Callable callee, Callable caller
where
  call.getCallee() = callee and
  call.getEnclosingCallable() = caller and
  callee.fromSource() and
  caller.fromSource()
select
  callee.getName() as callee_name,
  callee.getFile().getRelativePath() as callee_file,
  caller.getName() as caller_name,
  caller.getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_start_line,
  caller.getLocation().getEndLine() as caller_end_line
