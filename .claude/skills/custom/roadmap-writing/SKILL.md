---
name: roadmap-writing
description: Help design, write, and maintain roadmap sections for mcp-offsec, including per-server roadmaps in READMEs and the root docs roadmap. Use when the user mentions ROADMAP, roadmap conventions, future features, timelines, or planning servers/features in this repo.
---

# Roadmap Writing for mcp-offsec

This skill standardizes how to create and update roadmap documentation in the **mcp-offsec** repo.
Use it whenever working on:

- The **root roadmap** in `docs/` (covering implemented/planned servers)
- **Per-server roadmap sections** in each server's `README.md`
- Conventions for checkboxes, structure, and update responsibilities

Keep outputs **concise and checklist-driven**; avoid long prose.

## Core Conventions

- **Per-server roadmap lives in its README**
  - Location: `servers/<server-name>/README.md`
  - Section name: `## Roadmap`
  - Content focuses on that server's functionality, milestones, and future features.

- **Root roadmap lives under docs/**
  - Typical location: `docs/ROADMAP.md`
  - Scope: which **servers** are implemented or planned, plus a few cross-cutting themes/milestones.

- **Checkbox semantics (GLOBAL)**
  - `[]` = **planned** / agreed but not implemented yet.
  - `[x]` = **implemented/shipped** and available in the repo.

Always respect these meanings when proposing or updating roadmap content.

## When to Use This Skill

Trigger this skill when the user:

- Mentions **roadmap**, **timeline**, **future features**, or **planned servers**
- Wants to add or update a `## Roadmap` section in a server `README.md`
- Wants to create or refine the root `docs/ROADMAP.md`
- Asks about **roadmap conventions** or how to represent planned vs implemented work

If the request is not about planning, status, or future work, this skill is probably not needed.

## Per-Server Roadmap Pattern (README)

For any server under `servers/<name>/`, use this pattern inside `README.md`:

```markdown
## Roadmap

### Current Functionality
- Short bullets describing what this server does today.
- No checkboxes; this section describes the current state.

### Timeline
- [x] Initial PoC
- [x] First usable version (core use case working)
- [] Next milestone (e.g., result persistence, better reporting)

### Features

#### Near-Term
- [x] Feature already implemented
- [] Feature planned for upcoming work

#### Mid-Term
- [] Feature or integration planned but not scheduled yet

#### Long-Term / Ideas
- [] Ideas that might be explored in the future
```

Guidelines:

- Prefer **short, concrete bullets** (1 line each).
- For features, optionally include references:
  - `[] Add TLS configuration options (see issue #42)`
- Only mark `[x]` once the feature is actually implemented and available.

## Root Roadmap Pattern (docs/)

The root roadmap file (e.g. `docs/ROADMAP.md`) gives a **high-level view** of servers and major themes.

Suggested structure:

```markdown
# mcp-offsec Roadmap

## Servers Overview

- [x] recon-http — HTTP recon MCP server (see \`servers/recon-http/README.md\`)
- [x] exploit-sqli — SQLi exploit MCP server (see \`servers/exploit-sqli/README.md\`)
- [] recon-infra — Planned infrastructure recon MCP server
- [] exploit-xss — Planned XSS exploit MCP server

## Themes
- Short bullets describing cross-cutting themes (e.g. better recon coverage, shared models).

## High-Level Timeline
- [x] Initial recon + exploit servers available
- [] Coverage for top 5 OWASP web vulnerabilities
- [] Docker images and CI for all production servers
```

Conventions:

- In **Servers Overview**, the checkbox reflects whether the **server exists and is usable**:
  - `[]` = server planned but not yet implemented.
  - `[x]` = server implemented in the repo and has a roadmap in its `README.md`.
- Keep descriptions short; detailed per-feature plans belong in each server's `README.md` `## Roadmap` section.

## Workflow for Updates

When generating or editing roadmap content, follow this workflow:

1. **Identify scope**
   - Are we editing a **specific server** README?
   - Or updating the **root docs roadmap**?

2. **Infer current status from context**
   - Use existing README, code, and docs to infer what is already implemented.
   - Mark those as `[x]`, and keep future work as `[]`.
   - If status is unclear, avoid guessing; phrase as a neutral planned item with `[]`.

3. **Apply the correct pattern**
   - For a server: inject or update `## Roadmap` with the per-server pattern.
   - For root docs: maintain the `Servers Overview` list and high-level milestones.

4. **Keep changes minimal and readable**
   - Avoid huge new sections; keep lists short and focused.
   - Group features under `Near-Term`, `Mid-Term`, `Long-Term / Ideas`.

5. **Align with repo naming conventions**
   - Servers under `servers/` use directory names like `recon-http`, `exploit-sqli`.
   - Use those names in the root roadmap and link to their `README.md`.

## Checklist Before Finalizing

Before finalizing roadmap-related changes or suggestions, verify:

- **Checkbox meaning is consistent**
  - No `[x]` items that are clearly not yet implemented.
  - No `[]` items describing already-completed work (unless intentionally phrased as a future enhancement).

- **Sections are present and ordered**
  - Server README: `## Roadmap` → `### Current Functionality` → `### Timeline` → `### Features` (with Near/Mid/Long term subsections).
  - Root docs: `## Servers Overview` and at least one of `## Themes` or `## High-Level Timeline`.

- **Links and names are accurate**
  - Server names match directories under `servers/`.
  - README paths and references are correct.

If something is ambiguous, prefer **conservative, clearly planned** items (using `[]`) over speculative `[x]` claims.

