// SPDX-License-Identifier: MIT
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract all function/method definitions
 * @description Extracts function name, file, start line, end line for context lookup
 * @kind table
 * @id py/tool-functions
 */

import python

int getFunctionEndLine(Function f) {
  if exists(f.getLastStatement())
  then result = f.getLastStatement().getLocation().getEndLine()
  else result = f.getLocation().getEndLine()
}

from Function f
select
  f.getName() as name,
  f.getLocation().getFile().getRelativePath() as file,
  f.getLocation().getStartLine() as start_line,
  getFunctionEndLine(f) as end_line,
  f.getScope().toString() as scope
