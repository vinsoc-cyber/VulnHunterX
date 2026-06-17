// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract typedef definitions
 * @description Extracts typedef and type alias definitions with underlying types
 * @kind table
 * @id cpp/tool-typedefs
 */

import cpp

from TypedefType td
select
  td.getName() as name,
  td.getFile().getRelativePath() as file,
  td.getLocation().getStartLine() as line,
  td.getBaseType().toString() as underlying_type
