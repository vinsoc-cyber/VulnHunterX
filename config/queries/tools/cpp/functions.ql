// SPDX-License-Identifier: MIT
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract all function boundaries
 * @description Extracts function name, file, start line, end line for context lookup
 * @kind table
 * @id cpp/tool-functions
 */

import cpp

from Function f, string is_static
where
  f.hasDefinition() and
  (
    f.isStatic() and is_static = "true"
    or
    not f.isStatic() and is_static = "false"
  )
select
  f.getName() as name,
  f.getFile().getRelativePath() as file,
  f.getLocation().getStartLine() as start_line,
  f.getBlock().getLocation().getEndLine() as end_line,
  f.getNumberOfParameters() as param_count,
  is_static
