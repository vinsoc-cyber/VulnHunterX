/**
 * @name Extract struct/class definitions with member types
 * @description Extracts struct and class definitions including member types for context lookup
 * @kind table
 * @id cpp/tool-structs
 */

import cpp

from Struct s, Field f
where
  s.hasDefinition() and
  f = s.getAMember()
select
  s.getName() as name,
  s.getFile().getRelativePath() as file,
  s.getLocation().getStartLine() as start_line,
  s.getLocation().getEndLine() as end_line,
  f.getName() as member_name,
  f.getType().toString() as member_type
