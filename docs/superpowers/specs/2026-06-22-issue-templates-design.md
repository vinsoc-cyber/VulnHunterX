# Design: GitHub Issue Templates + Label Taxonomy

**Date:** 2026-06-22
**Status:** Approved (design)
**Reference:** [`Finsys/dockhand`](https://github.com/Finsys/dockhand) `.github/ISSUE_TEMPLATE` — we adapt its *structure* (YAML issue forms + a `config.yml` chooser), not its content.

## Goal

Give VulnHunterX a set of structured GitHub **issue forms** so reporters supply the information triage needs up front, and a **label taxonomy** so issues can be categorized by component. Templates and labels work together: each form auto-applies a *type* label and offers an **Area** dropdown for component categorization (e.g. a feature request about CodeQL coverage → `codeql`).

Today the repo has **no** `.github/ISSUE_TEMPLATE` and only GitHub's default labels.

## Decisions

- **Format:** GitHub issue forms (YAML), mirroring dockhand's structure. Not classic markdown templates.
- **Categorization via labels, not template sprawl.** A small template set; an Area dropdown carries the component choice.
- **Labeling mechanism: native dropdown + manual triage.** GitHub issue forms cannot turn a dropdown answer into a label. The *type* label is auto-applied via each form's `labels:` key; the **Area** label is applied by a maintainer during triage (the dropdown answer is visible in the issue body). No GitHub Action, zero maintenance.
- **Verdict / false-positive report gets its own template** — its fields differ enough from a generic bug, and triage accuracy is the tool's core value proposition.
- **Security vulnerabilities do NOT use a template.** Per `CONTRIBUTING.md` they are reported privately via GitHub Security Advisories; `config.yml` routes there.

## Deliverables

```
.github/ISSUE_TEMPLATE/
├── bug-report.yml          # type label: bug
├── feature-request.yml     # type label: enhancement
├── verdict-report.yml      # type label: triage-quality
└── config.yml              # blank issues off + contact links
scripts/setup-labels.sh     # one-shot creation of Area + triage-quality labels
```

## Label taxonomy

**Type** (auto-applied by a template's `labels:` key):

| Label | Source | Status |
|---|---|---|
| `bug` | bug-report.yml | exists |
| `enhancement` | feature-request.yml | exists |
| `triage-quality` | verdict-report.yml | **create** |

**Triage-error sub-labels** (applied alongside `triage-quality` at triage; derivable from the verdict dropdowns):

| Label | Meaning |
|---|---|
| `over-confirmed` | VHX said TP, truth is FP (over-confirmation) |
| `over-dismissed` | VHX said FP, truth is TP (real bug dismissed) |
| `false-negative` | Vulnerability never surfaced at all (coverage gap) — filed via the Feature request form |

**Area** (selected in the dropdown, applied by a maintainer at triage). Maps to `src/vuln_hunter_x/` modules and `config/`:

| Label | Covers | Dropdown option text |
|---|---|---|
| `codeql` | `codeql/`, `config/codeql-custom/` | CodeQL |
| `semgrep` | `semgrep/`, `config/semgrep-custom/` | Semgrep |
| `opengrep` | `opengrep/`, `config/opengrep-rules/` | OpenGrep |
| `rules` | custom detection rules (any engine) | Custom detection rules |
| `llm-verification` | `llm/`, `verification/`, `questions/`, `context/` | LLM verification / triage |
| `sarif` | `sarif/` | SARIF parsing |
| `cli` | `cli/` | CLI |
| `fuzzing` | `fuzz/` | Fuzzing |
| `reporting` | `reporting/` | Reporting |
| `config` | `config/`, env/setup | Configuration |

The dropdown also offers **Other / not sure** (no label). The same Area dropdown appears in `bug-report.yml` and `feature-request.yml`. `verdict-report.yml` uses a narrower **SAST engine** dropdown instead (codeql/semgrep/opengrep), since the area is inherently triage.

`scripts/setup-labels.sh` creates the Area labels + `triage-quality` + the triage-error sub-labels via `gh label create --force`, so the taxonomy is reproducible.

## Template specifications

Field conventions: `*` = required. Textareas that hold console output use `render: bash`.

### `bug-report.yml`
- **name:** Bug report · **description:** Something isn't working · **title:** `[Bug] ` · **labels:** `["bug"]`
- **markdown intro:** thanks + "before you file": check the README Quick Start / Troubleshooting, and [search existing issues & discussions](https://github.com/vinsoc-cyber/VulnHunterX/issues).
- **Description*** (textarea) — what's wrong; screenshots if applicable.
- **Steps to reproduce*** (textarea) — numbered steps.
- **Command run*** (textarea, `render: bash`) — the exact `vulnhunterx` / CLI invocation.
- **Expected behavior*** (textarea).
- **Logs / output*** (textarea, `render: bash`) — console error and any relevant SARIF/verdict output.
- **Area** (dropdown) — the Area options above.
- **VHX version / commit*** (input) — placeholder shows how to get it (e.g. `pip show vulnhunterx`, or git commit).
- **Python version*** (input) — e.g. 3.12.x.
- **OS*** (input) — e.g. Ubuntu 24.04.
- **SAST engine*** (dropdown) — CodeQL / Semgrep / OpenGrep / Multiple / N/A.
- **LLM provider + model** (input) — e.g. `anthropic / claude-opus-4-8` (optional; blank if not reached).
- **Confirmations*** (checkboxes) — searched existing issues/discussions; updated the title.

### `feature-request.yml`
- **name:** Feature request · **description:** Suggest an idea for VulnHunterX · **title:** `[Feature] ` · **labels:** `["enhancement"]`
- **markdown intro:** thanks.
- **Problem statement*** (textarea) — what problem this solves.
- **Proposed solution*** (textarea) — how it should work.
- **Alternatives considered** (textarea, optional).
- **Area** (dropdown) — the Area options above (e.g. "CodeQL" for a new CodeQL rule request).
- **Additional context** (textarea, optional).
- **Confirmation*** (checkbox) — searched existing issues/discussions.

### `verdict-report.yml`
For when VHX assigned a wrong verdict (TP / FP / NMD), bad confidence, or flawed reasoning.
- **name:** Verdict / false-positive report · **description:** A finding was mis-triaged · **title:** `[Verdict] ` · **labels:** `["triage-quality"]`
- **markdown intro:** explain when to use this vs. a bug; ask reporter to paste from VHX output where possible; point false-negative (missed-detection) reports to the Feature request form.
- **Target analyzed** (input, optional) — repo + commit/version that was scanned. *Provide this and/or a minimal snippet below — at least one is needed to reproduce.*
- **Minimal reproducible code** (textarea, optional) — the smallest snippet that reproduces the mis-triage; note the language/filename. *Provide this and/or a target above.*
- **Engine + rule*** (input) — SAST engine and rule ID that produced the finding.
- **Finding location*** (input) — `path/to/file.ext:line` (in the repo, or the line within the snippet above).
- **VHX verdict*** (dropdown) — TP / FP / NMD (what VHX said).
- **VHX confidence** (input, optional) — the score VHX reported.
- **Expected verdict*** (dropdown) — TP / FP / NMD (what it should be).
- **VHX's reasoning*** (textarea) — pasted from the verdict output.
- **Why it's wrong*** (textarea) — evidence for the correct verdict.
- **LLM provider + model*** (input) — the model that produced the verdict.
- **Command run** (textarea, `render: bash`, optional).
- **Confirmations*** (checkboxes) — (1) searched existing issues/discussions; (2) provided a target or a minimal reproducible snippet.

### `config.yml`
```yaml
blank_issues_enabled: false
contact_links:
  - name: 🤔 Questions & Help
    url: https://github.com/vinsoc-cyber/VulnHunterX/discussions
    about: General questions or support for using VulnHunterX.
  - name: 🔒 Report a security vulnerability
    url: https://github.com/vinsoc-cyber/VulnHunterX/security/advisories/new
    about: Report vulnerabilities privately — do NOT open a public issue (see CONTRIBUTING.md).
  - name: 📖 Documentation
    url: https://github.com/vinsoc-cyber/VulnHunterX#readme
    about: README, Quick Start, and CLI reference.
```

## Out of scope

- No GitHub Action for auto-labeling (deferred; revisit only if manual triage becomes a burden).
- No pull-request template changes (dockhand has one; not requested here).
- No changes to existing default labels.

## Success criteria

1. The four `.github/ISSUE_TEMPLATE/` files are valid YAML and parse as GitHub issue forms (the "New issue" chooser shows three forms; blank issues are disabled).
2. Each form's required fields and dropdowns match this spec; type labels auto-apply.
3. `scripts/setup-labels.sh` creates the Area labels + `triage-quality` + triage-error sub-labels (`over-confirmed`, `over-dismissed`, `false-negative`) idempotently.
4. `config.yml` routes questions → Discussions and security reports → Security Advisories.
