// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract all function and method definitions
 * @description Extracts function name, file, start line, end line for context lookup
 * @kind table
 * @id go/tool-functions
 */

import go

from FuncDecl fd
where exists(fd.getName())
select
  fd.getName() as name,
  fd.getFile().getRelativePath() as file,
  fd.getLocation().getStartLine() as start_line,
  fd.getLocation().getEndLine() as end_line,
  fd.getNumParameter() as param_count
