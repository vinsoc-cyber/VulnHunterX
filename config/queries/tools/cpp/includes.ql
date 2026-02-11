/**
 * @name Extract #include directives per file
 * @description File and its included path (for fuzz harness includes)
 * @kind table
 * @id cpp/tool-includes
 */

import cpp

from Include inc
select
  inc.getFile().getRelativePath() as file,
  inc.getIncludeText() as include_text
