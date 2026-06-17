// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract function signatures (name, file, params with types)
 * @description For fuzz driver generation: function + parameter types and names
 * @kind table
 * @id cpp/tool-function-signatures
 */

import cpp

from Function f, int i
where
  f.hasDefinition() and
  i >= 0 and
  i < f.getNumberOfParameters()
select
  f.getName() as name,
  f.getFile().getRelativePath() as file,
  f.getLocation().getStartLine() as start_line,
  f.getBlock().getLocation().getEndLine() as end_line,
  i as param_index,
  f.getParameter(i).getType().toString() as param_type,
  f.getParameter(i).getName() as param_name
