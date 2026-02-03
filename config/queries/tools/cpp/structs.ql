/**
 * @name Extract struct/class definitions
 * @description Extracts struct and class definitions for context lookup
 * @kind table
 * @id cpp/tool-structs
 */

import cpp

from Struct s
where s.hasDefinition()
select
  s.getName() as name,
  s.getFile().getRelativePath() as file,
  s.getLocation().getStartLine() as start_line,
  s.getLocation().getEndLine() as end_line,
  s.getAMember().getName() as member_name
