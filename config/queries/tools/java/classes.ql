/**
 * @name Extract class and interface definitions
 * @description Extracts class/interface definitions for context lookup
 * @kind table
 * @id java/tool-classes
 */

import java

from RefType t
where
  t.fromSource() and
  exists(t.getName())
select
  t.getName() as name,
  t.getFile().getRelativePath() as file,
  t.getLocation().getStartLine() as start_line,
  t.getLocation().getEndLine() as end_line
