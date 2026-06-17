// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract function caller relationships
 * @description Maps each function to its callers for context expansion
 * @kind table
 * @id py/tool-callers
 */

import python

from Call call, Function callee, Function caller
where
  call.getFunc().(Name).getId() = callee.getName() and
  call.getScope() = caller
select
  callee.getName() as callee_name,
  callee.getLocation().getFile().getRelativePath() as callee_file,
  caller.getName() as caller_name,
  caller.getLocation().getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_start_line,
  caller.getLocation().getEndLine() as caller_end_line
