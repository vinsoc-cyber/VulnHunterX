// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

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
