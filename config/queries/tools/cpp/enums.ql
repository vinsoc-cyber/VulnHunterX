// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract enum definitions
 * @description Extracts enum definitions with enumerator names and values
 * @kind table
 * @id cpp/tool-enums
 */

import cpp

from Enum e, EnumConstant ec
where ec = e.getAnEnumConstant()
select
  e.getName() as name,
  e.getFile().getRelativePath() as file,
  ec.getName() as member,
  ec.getValue().toString() as value
