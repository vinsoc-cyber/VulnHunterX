# Review of the agent guidance templates

The six documents in `.tmp` describe a Telegram intelligence application, rather than VulnHunterX. Their engineering principles are useful, but their product rules, architecture, validation gates, and phase workflow would misdirect Claude and Codex in this repository. The replacements below use the checked-in code and configuration as evidence.

## Template findings and replacements

| Reference | Finding | Project replacement |
| --- | --- | --- |
| `.tmp/AGENTS.md` | References Telegram collection, Python 3.13, missing build/architecture documents and ADRs, and an 85% coverage gate | [AGENTS.md](../AGENTS.md) provides shared Claude/Codex instructions, the actual pipeline, module map, and available validation |
| `.tmp/CLAUDE.md` | Good shared-policy pattern, but all security examples concern the other application | [CLAUDE.md](../CLAUDE.md) links shared instructions and highlights verification and feature-removal pitfalls |
| `.tmp/SECURITY_RULES.md` | Contains concrete but unrelated claims about Telegram permissions, web roles, provider policy tables, retention, and database grants | [SECURITY_RULES.md](SECURITY_RULES.md) covers source scope, prompt input, build execution, credentials, evidence, and artifacts |
| `.tmp/CODE_STANDARDS.md` | Assumes FastAPI, PostgreSQL, async collectors, a frontend, and another package name | [CODE_STANDARDS.md](CODE_STANDARDS.md) follows the current Python settings, scanner/context interfaces, tests, and benchmarks |
| `.tmp/GIT_WORKFLOW.md` | Requires sequential phase merges, immediate pushes/draft PRs, and checks not configured here | [GIT_WORKFLOW.md](GIT_WORKFLOW.md) follows the existing contributor process without initiating external Git actions |
| `.tmp/SECURITY.md` | Describes Telegram sessions, notification destinations, and web security | [SECURITY.md](../SECURITY.md) documents VulnHunterX's security scope and the existing private-reporting guidance |

The root `AGENTS.md` is the shared entry point for Codex and other coding agents. Root `CLAUDE.md` adds Claude guidance without copying the shared policy. A root-only exception in `.gitignore` allows this shared file to be versioned; nested local `CLAUDE.md` files and `.claude/` remain ignored.

## What was retained

The replacements retain secret hygiene, treatment of external content as data, bounded I/O, typed boundaries, synthetic fixtures, reviewable changes, and truthful reporting of executed checks. They apply those principles to source code, SARIF, context CSVs, build logs, model responses, and verification artifacts.

The reference documents were left intact. Their implementation claims were not adopted as facts about this repository.

## Evidence from this checkout

- [pyproject.toml](../pyproject.toml) specifies Python `>=3.12,<3.14`, Ruff `py312`, MyPy 3.12, and pytest `testpaths = ["tests"]`. It configures coverage output but no percentage gate.
- [CONTRIBUTING.md](../CONTRIBUTING.md) specifies Ruff, MyPy, pytest, focused PRs, and private security reporting. No committed workflow exists under `.github/workflows/` in the reviewed checkout.
- [cli/commands.py](../src/vuln_hunter_x/cli/commands.py) composes the four supported stages in `cmd_scan()`. The completed cleanup plan records the removed legacy interfaces and migration policy.
- [context/repo_paths.py](../src/vuln_hunter_x/context/repo_paths.py) resolves source within the named repository and supports symlinked checkout roots. [context/evidence.py](../src/vuln_hunter_x/context/evidence.py) defines typed evidence states and kinds.
- [core/config.py](../src/vuln_hunter_x/core/config.py) defaults raw-response persistence to false, while [confirm_findings.yaml](../config/confirm_findings.yaml) configures a conversation log. Privacy guidance must account for both.
- [llm/completion.py](../src/vuln_hunter_x/llm/completion.py) supports CodeQL build advice and report translation; legacy feature cleanup cannot justify deleting that helper.
- [benchmark/README.md](../benchmark/README.md) and [benchmarks/README.md](../benchmarks/README.md) describe two distinct benchmark systems. Their tests, fixtures, and stored baselines must be treated accordingly.

## Scope and limitations

This is a local document and code review, dated 4 October 2026. It does not establish remote branch protection, a completed security audit, or current external provider capabilities. Current documentation describes the four supported stages. Runtime cleanup has been implemented; the completed removal plan records the compatibility policy and validation limits.
