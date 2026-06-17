// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract class definitions
 * @description Extracts class definitions for context lookup
 * @kind table
 * @id js/tool-classes
 */

import javascript

from ClassDefinition c
select
  c.getName() as name,
  c.getFile().getRelativePath() as file,
  c.getLocation().getStartLine() as start_line,
  c.getLocation().getEndLine() as end_line
