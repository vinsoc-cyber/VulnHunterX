// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract all function definitions
 * @description Extracts function name, file, start line, end line for context lookup
 * @kind table
 * @id php/tool-functions
 */

import php

from Function f
where exists(f.getName())
select
  f.getName() as name,
  f.getFile().getRelativePath() as file,
  f.getLocation().getStartLine() as start_line,
  f.getLocation().getEndLine() as end_line,
  f.getNumberOfParameters() as param_count
