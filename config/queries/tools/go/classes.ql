// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 VinSOC Cyber

/**
 * @name Extract type declarations (structs and interfaces)
 * @description Extracts Go type definitions for context lookup
 * @kind table
 * @id go/tool-classes
 */

import go

from TypeSpec ts
where ts.getFile().getRelativePath() != ""
select
  ts.getName() as name,
  ts.getFile().getRelativePath() as file,
  ts.getLocation().getStartLine() as start_line,
  ts.getLocation().getEndLine() as end_line
