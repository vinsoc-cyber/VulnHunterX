/**
 * @name Extract all function boundaries
 * @description Extracts function name, file, start line, end line for context lookup
 * @kind table
 * @id cpp/tool-functions
 */

import cpp

from Function f
where f.hasDefinition()
select
  f.getName() as name,
  f.getFile().getRelativePath() as file,
  f.getLocation().getStartLine() as start_line,
  f.getBlock().getLocation().getEndLine() as end_line,
  f.getNumberOfParameters() as param_count,
  f.isStatic() as is_static
