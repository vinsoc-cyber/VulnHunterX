/**
 * @name Extract class definitions
 * @description Extracts class definitions for context lookup
 * @kind table
 * @id php/tool-classes
 */

import php

from Class c
select
  c.getName() as name,
  c.getFile().getRelativePath() as file,
  c.getLocation().getStartLine() as start_line,
  c.getLocation().getEndLine() as end_line
