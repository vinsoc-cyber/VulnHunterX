// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract global variables
 * @description Extracts global and namespace-scope variables for context lookup
 * @kind table
 * @id cpp/tool-globals
 */

import cpp

from GlobalOrNamespaceVariable g
select
  g.getName() as name,
  g.getFile().getRelativePath() as file,
  g.getLocation().getStartLine() as start_line,
  g.getLocation().getEndLine() as end_line,
  g.getType().toString() as type
