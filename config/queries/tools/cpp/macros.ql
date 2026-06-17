// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract macro definitions
 * @description Extracts preprocessor macro definitions for context lookup
 * @kind table
 * @id cpp/tool-macros
 */

import cpp

from Macro m
where m.getBody().length() > 0
select
  m.getName() as name,
  m.getFile().getRelativePath() as file,
  m.getLocation().getStartLine() as line,
  m.getBody() as body
