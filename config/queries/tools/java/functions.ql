// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract all method and constructor definitions
 * @description Extracts callable name, file, start line, end line for context lookup
 * @kind table
 * @id java/tool-functions
 */

import java

from Callable c
where
  c.fromSource() and
  exists(c.getName())
select
  c.getName() as name,
  c.getFile().getRelativePath() as file,
  c.getLocation().getStartLine() as start_line,
  c.getLocation().getEndLine() as end_line,
  c.getNumberOfParameters() as param_count
