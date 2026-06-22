# Issue Templates + Label Taxonomy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add GitHub issue forms (bug, feature, verdict/false-positive) plus a config chooser and a label-setup script to VulnHunterX, adapting the structure of `Finsys/dockhand`.

**Architecture:** Four YAML files under `.github/ISSUE_TEMPLATE/` (three issue forms + one `config.yml` chooser) and one idempotent shell script `scripts/setup-labels.sh`. Categorization uses labels: each form auto-applies a *type* label via its `labels:` key; an **Area** dropdown lets the reporter signal the component, and a maintainer applies the matching Area label at triage (no automation).

**Tech Stack:** GitHub issue forms (YAML schema), `gh` CLI (label creation), Python + PyYAML 6.0.1 (local validation only — no committed test suite).

**Spec:** `docs/superpowers/specs/2026-06-22-issue-templates-design.md`

## Global Constraints

- Branch: `feat/issue-templates` (already checked out; the spec is already committed here).
- All files are GitHub-config YAML/shell — there is **no** pytest suite. Each task's "test" is a local validation command (PyYAML parse + structural asserts) that fails before the file exists and passes after.
- Commit message convention (from `CONTRIBUTING.md`): imperative, prefixed `chore:` for repo-meta files.
- Every commit ends with the trailer line `Claude-Session: https://claude.ai/code/session_01VWakvTYWCobyatPUWwMsr2` (passed as a second `-m`).
- Repo slug for `gh`: `vinsoc-cyber/VulnHunterX`.
- Existing labels reused as-is: `bug`, `enhancement`. New label `triage-quality` plus the Area labels are created by `scripts/setup-labels.sh`.
- Area dropdown option list (identical in `bug-report.yml` and `feature-request.yml`): CodeQL, Semgrep, OpenGrep, Custom detection rules, LLM verification / triage, SARIF parsing, CLI, Fuzzing, Reporting, Configuration, Other / not sure.
- Verdict options (identical in both verdict dropdowns): "True Positive (TP)", "False Positive (FP)", "Needs More Data (NMD)".

## Spec coverage map

| Spec item | Task |
|---|---|
| `config.yml` (blank off + 3 contact links) | Task 1 |
| `bug-report.yml` | Task 2 |
| `feature-request.yml` | Task 3 |
| `verdict-report.yml` (incl. minimal-repro snippet) | Task 4 |
| `scripts/setup-labels.sh` (Area + `triage-quality`) | Task 5 |
| Success criteria 1 & 4 (live GitHub chooser/routing), live label creation | Task 6 |

---

### Task 1: `config.yml` — the issue chooser

**Files:**
- Create: `.github/ISSUE_TEMPLATE/config.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: the `.github/ISSUE_TEMPLATE/` directory; disables blank issues; routes Questions → Discussions, Security → Advisories, Docs → README.

- [ ] **Step 1: Write the failing validation check**

Run:
```bash
python3 - <<'PY'
import yaml
P=".github/ISSUE_TEMPLATE/config.yml"
d=yaml.safe_load(open(P))
assert d.get("blank_issues_enabled") is False, "blank_issues_enabled must be false"
links=d.get("contact_links") or []
assert len(links)>=3, f"expected >=3 contact links, got {len(links)}"
for c in links:
    assert c.get("name") and c.get("url") and c.get("about"), f"incomplete contact link: {c}"
urls=" ".join(c["url"] for c in links)
assert "discussions" in urls, "must link Discussions"
assert "security/advisories" in urls, "must link Security Advisories"
print("OK", P)
PY
```

- [ ] **Step 2: Run it to verify it fails**

Expected: `FileNotFoundError: ... config.yml` (non-zero exit) — the file does not exist yet.

- [ ] **Step 3: Create the file**

`.github/ISSUE_TEMPLATE/config.yml`:
```yaml
blank_issues_enabled: false
contact_links:
  - name: 🤔 Questions & Help
    url: https://github.com/vinsoc-cyber/VulnHunterX/discussions
    about: General questions or support for using VulnHunterX.
  - name: 🔒 Report a security vulnerability
    url: https://github.com/vinsoc-cyber/VulnHunterX/security/advisories/new
    about: Report vulnerabilities privately — please do NOT open a public issue (see CONTRIBUTING.md).
  - name: 📖 Documentation
    url: https://github.com/vinsoc-cyber/VulnHunterX#readme
    about: README, Quick Start, and CLI reference.
```

- [ ] **Step 4: Run the check to verify it passes**

Re-run the Step 1 command. Expected: `OK .github/ISSUE_TEMPLATE/config.yml`

- [ ] **Step 5: Commit**

```bash
git add .github/ISSUE_TEMPLATE/config.yml
git commit -m "chore: add issue template chooser (config.yml)" -m "Claude-Session: https://claude.ai/code/session_01VWakvTYWCobyatPUWwMsr2"
```

---

### Task 2: `bug-report.yml`

**Files:**
- Create: `.github/ISSUE_TEMPLATE/bug-report.yml`

**Interfaces:**
- Consumes: existing `bug` label (auto-applied).
- Produces: a form whose Area dropdown answer is applied as an Area label by maintainers (Task 5 creates those labels).

- [ ] **Step 1: Write the failing validation check**

Run:
```bash
python3 - <<'PY'
import yaml
P=".github/ISSUE_TEMPLATE/bug-report.yml"
REQUIRED={"description","reproduction","command","expected","logs","area",
          "version","python-version","os","engine","llm","confirmations"}
d=yaml.safe_load(open(P))
assert d.get("name") and d.get("description"), "name/description required"
assert d.get("labels")==["bug"], f'labels must be ["bug"], got {d.get("labels")}'
body=d.get("body") or []
for e in body:
    assert e.get("type") in {"markdown","input","textarea","dropdown","checkboxes"}, f"bad type {e.get('type')}"
    if e["type"]!="markdown":
        assert e.get("id"), f"non-markdown element missing id: {e}"
    if e["type"] in {"dropdown","checkboxes"}:
        assert e["attributes"].get("options"), f"{e.get('id')} needs options"
ids={e.get("id") for e in body if e.get("type")!="markdown"}
missing=REQUIRED-ids
assert not missing, f"missing fields: {missing}"
print("OK", P)
PY
```

- [ ] **Step 2: Run it to verify it fails**

Expected: `FileNotFoundError: ... bug-report.yml` (non-zero exit).

- [ ] **Step 3: Create the file**

`.github/ISSUE_TEMPLATE/bug-report.yml`:
```yaml
name: Bug report
description: Something isn't working
title: "[Bug] "
labels: ["bug"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for taking the time to report a bug!

        **Before you file, please check:**
        - The [Quick Start](https://github.com/vinsoc-cyber/VulnHunterX#quick-start) and [Troubleshooting](https://github.com/vinsoc-cyber/VulnHunterX#troubleshooting) sections.
        - [Existing issues](https://github.com/vinsoc-cyber/VulnHunterX/issues) and [discussions](https://github.com/vinsoc-cyber/VulnHunterX/discussions).
  - type: textarea
    id: description
    attributes:
      label: Description
      description: A clear and concise description of what the bug is. Add screenshots if they help.
      placeholder: When I run ... VulnHunterX does ...
    validations:
      required: true
  - type: textarea
    id: reproduction
    attributes:
      label: Steps to reproduce
      placeholder: |
        1. Run '...'
        2. With config '...'
        3. See error
    validations:
      required: true
  - type: textarea
    id: command
    attributes:
      label: Command run
      description: The exact VulnHunterX command you ran.
      render: bash
      placeholder: vuln-hunter-x scan --repo ...
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected behavior
      description: What you expected to happen instead.
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Logs / output
      description: Console error output and any relevant SARIF or verdict output.
      render: bash
    validations:
      required: true
  - type: dropdown
    id: area
    attributes:
      label: Area
      description: Which component does this affect? A best guess is fine.
      options:
        - CodeQL
        - Semgrep
        - OpenGrep
        - Custom detection rules
        - LLM verification / triage
        - SARIF parsing
        - CLI
        - Fuzzing
        - Reporting
        - Configuration
        - Other / not sure
    validations:
      required: false
  - type: input
    id: version
    attributes:
      label: VulnHunterX version / commit
      description: Run `pip show vulnhunterx` for the version, or paste the git commit.
      placeholder: e.g. 0.1.0 (commit eda2fd0)
    validations:
      required: true
  - type: input
    id: python-version
    attributes:
      label: Python version
      placeholder: e.g. 3.12.3
    validations:
      required: true
  - type: input
    id: os
    attributes:
      label: Operating system
      placeholder: e.g. Ubuntu 24.04
    validations:
      required: true
  - type: dropdown
    id: engine
    attributes:
      label: SAST engine
      description: Which static-analysis engine was in use?
      options:
        - CodeQL
        - Semgrep
        - OpenGrep
        - Multiple
        - N/A
    validations:
      required: true
  - type: input
    id: llm
    attributes:
      label: LLM provider + model
      description: The provider and model used for verification, if reached.
      placeholder: e.g. anthropic / claude-opus-4-8
    validations:
      required: false
  - type: checkboxes
    id: confirmations
    attributes:
      label: Please confirm
      options:
        - label: I have searched existing issues and discussions for this problem.
          required: true
        - label: I have updated the title above with a concise description.
          required: true
```

- [ ] **Step 4: Run the check to verify it passes**

Re-run the Step 1 command. Expected: `OK .github/ISSUE_TEMPLATE/bug-report.yml`

- [ ] **Step 5: Commit**

```bash
git add .github/ISSUE_TEMPLATE/bug-report.yml
git commit -m "chore: add bug report issue form" -m "Claude-Session: https://claude.ai/code/session_01VWakvTYWCobyatPUWwMsr2"
```

---

### Task 3: `feature-request.yml`

**Files:**
- Create: `.github/ISSUE_TEMPLATE/feature-request.yml`

**Interfaces:**
- Consumes: existing `enhancement` label (auto-applied).
- Produces: a form with the same Area dropdown as Task 2 (e.g. choose "CodeQL" for a new CodeQL-rule request).

- [ ] **Step 1: Write the failing validation check**

Run:
```bash
python3 - <<'PY'
import yaml
P=".github/ISSUE_TEMPLATE/feature-request.yml"
REQUIRED={"problem","solution","alternatives","area","additional","confirmations"}
d=yaml.safe_load(open(P))
assert d.get("name") and d.get("description"), "name/description required"
assert d.get("labels")==["enhancement"], f'labels must be ["enhancement"], got {d.get("labels")}'
body=d.get("body") or []
for e in body:
    assert e.get("type") in {"markdown","input","textarea","dropdown","checkboxes"}, f"bad type {e.get('type')}"
    if e["type"]!="markdown":
        assert e.get("id"), f"non-markdown element missing id: {e}"
    if e["type"] in {"dropdown","checkboxes"}:
        assert e["attributes"].get("options"), f"{e.get('id')} needs options"
ids={e.get("id") for e in body if e.get("type")!="markdown"}
missing=REQUIRED-ids
assert not missing, f"missing fields: {missing}"
print("OK", P)
PY
```

- [ ] **Step 2: Run it to verify it fails**

Expected: `FileNotFoundError: ... feature-request.yml` (non-zero exit).

- [ ] **Step 3: Create the file**

`.github/ISSUE_TEMPLATE/feature-request.yml`:
```yaml
name: Feature request
description: Suggest an idea for VulnHunterX
title: "[Feature] "
labels: ["enhancement"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for taking the time to suggest a feature!
  - type: textarea
    id: problem
    attributes:
      label: Problem statement
      description: What problem does this feature solve?
      placeholder: Describe the problem you're facing.
    validations:
      required: true
  - type: textarea
    id: solution
    attributes:
      label: Proposed solution
      description: How would you like it to work?
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives considered
      description: Any alternative solutions or features you considered?
    validations:
      required: false
  - type: dropdown
    id: area
    attributes:
      label: Area
      description: Which component does this feature touch? (e.g. choose CodeQL for a new CodeQL rule.)
      options:
        - CodeQL
        - Semgrep
        - OpenGrep
        - Custom detection rules
        - LLM verification / triage
        - SARIF parsing
        - CLI
        - Fuzzing
        - Reporting
        - Configuration
        - Other / not sure
    validations:
      required: false
  - type: textarea
    id: additional
    attributes:
      label: Additional context
      description: Add any other context or screenshots here.
    validations:
      required: false
  - type: checkboxes
    id: confirmations
    attributes:
      label: Please confirm
      options:
        - label: I have searched existing issues and discussions for this request.
          required: true
```

- [ ] **Step 4: Run the check to verify it passes**

Re-run the Step 1 command. Expected: `OK .github/ISSUE_TEMPLATE/feature-request.yml`

- [ ] **Step 5: Commit**

```bash
git add .github/ISSUE_TEMPLATE/feature-request.yml
git commit -m "chore: add feature request issue form" -m "Claude-Session: https://claude.ai/code/session_01VWakvTYWCobyatPUWwMsr2"
```

---

### Task 4: `verdict-report.yml`

**Files:**
- Create: `.github/ISSUE_TEMPLATE/verdict-report.yml`

**Interfaces:**
- Consumes: the `triage-quality` label (auto-applied) — created by Task 5; until then GitHub silently drops it, so Task 5 must run on the live repo for the label to stick.
- Produces: the VHX-specific triage-accuracy report; reproduction via a target repo and/or a minimal code snippet.

- [ ] **Step 1: Write the failing validation check**

Run:
```bash
python3 - <<'PY'
import yaml
P=".github/ISSUE_TEMPLATE/verdict-report.yml"
REQUIRED={"target","snippet","engine-rule","location","vhx-verdict","confidence",
          "expected-verdict","reasoning","why-wrong","llm","command","confirmations"}
VERDICTS=["True Positive (TP)","False Positive (FP)","Needs More Data (NMD)"]
d=yaml.safe_load(open(P))
assert d.get("name") and d.get("description"), "name/description required"
assert d.get("labels")==["triage-quality"], f'labels must be ["triage-quality"], got {d.get("labels")}'
body=d.get("body") or []
by_id={}
for e in body:
    assert e.get("type") in {"markdown","input","textarea","dropdown","checkboxes"}, f"bad type {e.get('type')}"
    if e["type"]!="markdown":
        assert e.get("id"), f"non-markdown element missing id: {e}"
        by_id[e["id"]]=e
    if e["type"] in {"dropdown","checkboxes"}:
        assert e["attributes"].get("options"), f"{e.get('id')} needs options"
missing=REQUIRED-set(by_id)
assert not missing, f"missing fields: {missing}"
for vid in ("vhx-verdict","expected-verdict"):
    assert by_id[vid]["attributes"]["options"]==VERDICTS, f"{vid} options must be {VERDICTS}"
print("OK", P)
PY
```

- [ ] **Step 2: Run it to verify it fails**

Expected: `FileNotFoundError: ... verdict-report.yml` (non-zero exit).

- [ ] **Step 3: Create the file**

`.github/ISSUE_TEMPLATE/verdict-report.yml`:
```yaml
name: Verdict / false-positive report
description: VulnHunterX mis-triaged a finding (wrong TP/FP/NMD, bad confidence, or flawed reasoning)
title: "[Verdict] "
labels: ["triage-quality"]
body:
  - type: markdown
    attributes:
      value: |
        Use this when VulnHunterX assigned the **wrong verdict** to a finding — a false positive it confirmed, a real bug it dismissed, or reasoning that doesn't hold up.
        Please paste directly from VulnHunterX's output where possible.
  - type: input
    id: target
    attributes:
      label: Target analyzed
      description: Repo + commit/version that was scanned. Provide this and/or a minimal snippet below — at least one is needed to reproduce.
      placeholder: e.g. github.com/org/repo @ a1b2c3d
    validations:
      required: false
  - type: textarea
    id: snippet
    attributes:
      label: Minimal reproducible code
      description: The smallest snippet that reproduces the mis-triage. Note the language/filename. Provide this and/or a target above.
      placeholder: |
        # vulnerable.py
        def handler(req):
            ...
    validations:
      required: false
  - type: input
    id: engine-rule
    attributes:
      label: Engine + rule
      description: SAST engine and rule ID that produced the finding.
      placeholder: e.g. semgrep / python.lang.security.audit.dangerous-subprocess-use
    validations:
      required: true
  - type: input
    id: location
    attributes:
      label: Finding location
      description: path/to/file.ext:line (in the repo, or the line within the snippet above).
      placeholder: e.g. src/app/views.py:142
    validations:
      required: true
  - type: dropdown
    id: vhx-verdict
    attributes:
      label: VulnHunterX verdict
      description: What VulnHunterX said.
      options:
        - "True Positive (TP)"
        - "False Positive (FP)"
        - "Needs More Data (NMD)"
    validations:
      required: true
  - type: input
    id: confidence
    attributes:
      label: VulnHunterX confidence
      description: The confidence score VulnHunterX reported, if shown.
      placeholder: e.g. 0.86
    validations:
      required: false
  - type: dropdown
    id: expected-verdict
    attributes:
      label: Expected verdict
      description: What the verdict should be.
      options:
        - "True Positive (TP)"
        - "False Positive (FP)"
        - "Needs More Data (NMD)"
    validations:
      required: true
  - type: textarea
    id: reasoning
    attributes:
      label: VulnHunterX's reasoning
      description: Paste the verdict reasoning from the output.
      render: text
    validations:
      required: true
  - type: textarea
    id: why-wrong
    attributes:
      label: Why it's wrong
      description: Evidence for the correct verdict.
    validations:
      required: true
  - type: input
    id: llm
    attributes:
      label: LLM provider + model
      description: The model that produced the verdict.
      placeholder: e.g. anthropic / claude-opus-4-8
    validations:
      required: true
  - type: textarea
    id: command
    attributes:
      label: Command run
      render: bash
    validations:
      required: false
  - type: checkboxes
    id: confirmations
    attributes:
      label: Please confirm
      options:
        - label: I have searched existing issues and discussions for this finding.
          required: true
        - label: I provided a target or a minimal reproducible snippet.
          required: true
```

- [ ] **Step 4: Run the check to verify it passes**

Re-run the Step 1 command. Expected: `OK .github/ISSUE_TEMPLATE/verdict-report.yml`

- [ ] **Step 5: Commit**

```bash
git add .github/ISSUE_TEMPLATE/verdict-report.yml
git commit -m "chore: add verdict/false-positive issue form" -m "Claude-Session: https://claude.ai/code/session_01VWakvTYWCobyatPUWwMsr2"
```

---

### Task 5: `scripts/setup-labels.sh`

**Files:**
- Create: `scripts/setup-labels.sh`

**Interfaces:**
- Consumes: `gh` CLI authenticated with write access to the repo.
- Produces: the `triage-quality` type label and the ten Area labels referenced by the dropdowns. Idempotent via `gh label create --force`.

- [ ] **Step 1: Write the failing validation check**

Run:
```bash
test -x scripts/setup-labels.sh && bash -n scripts/setup-labels.sh && echo "OK setup-labels.sh"
```

- [ ] **Step 2: Run it to verify it fails**

Expected: non-zero exit (the file does not exist / is not executable yet), no `OK` printed.

- [ ] **Step 3: Create the file**

`scripts/setup-labels.sh`:
```bash
#!/usr/bin/env bash
# Create/update VulnHunterX issue labels: the triage-quality type label plus
# the Area taxonomy used by the issue-form dropdowns.
# Idempotent (re-running updates existing labels via --force).
# Requires: gh CLI authenticated with write access to the repo.
#
# Usage: scripts/setup-labels.sh [owner/repo]   (default: vinsoc-cyber/VulnHunterX)
set -euo pipefail

REPO="${1:-vinsoc-cyber/VulnHunterX}"

# Type label used by the verdict-report form (bug/enhancement already exist).
gh label create triage-quality   --repo "$REPO" --force --color "5319e7" --description "Verdict accuracy / false-positive reports"

# Area labels (applied by maintainers at triage; chosen via the Area dropdown).
gh label create codeql           --repo "$REPO" --force --color "0e8a16" --description "CodeQL engine / queries"
gh label create semgrep          --repo "$REPO" --force --color "0e8a16" --description "Semgrep engine / rules"
gh label create opengrep         --repo "$REPO" --force --color "0e8a16" --description "OpenGrep engine / rules"
gh label create rules            --repo "$REPO" --force --color "1d76db" --description "Custom detection rules (any engine)"
gh label create llm-verification --repo "$REPO" --force --color "1d76db" --description "LLM verification / triage / questions"
gh label create sarif            --repo "$REPO" --force --color "fbca04" --description "SARIF parsing"
gh label create cli              --repo "$REPO" --force --color "fbca04" --description "Command-line interface"
gh label create fuzzing          --repo "$REPO" --force --color "fbca04" --description "Fuzzing stages"
gh label create reporting        --repo "$REPO" --force --color "fbca04" --description "Report generation"
gh label create config           --repo "$REPO" --force --color "fbca04" --description "Configuration / setup / env"

echo "Labels created/updated on $REPO."
```

- [ ] **Step 4: Make it executable and verify the check passes**

```bash
chmod +x scripts/setup-labels.sh
```
Re-run the Step 1 command. Expected: `OK setup-labels.sh`

- [ ] **Step 5: Commit**

```bash
git add scripts/setup-labels.sh
git commit -m "chore: add gh script to create issue Area + triage-quality labels" -m "Claude-Session: https://claude.ai/code/session_01VWakvTYWCobyatPUWwMsr2"
```

---

### Task 6: Integration & live verification

**Files:** none (verification + outward actions).

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces: a verified, pushed branch; labels live on the repo. The push, PR, and label creation are **outward-facing** — only run them once the user authorizes.

- [ ] **Step 1: Validate all four YAML files parse together**

```bash
python3 - <<'PY'
import glob, yaml
for f in sorted(glob.glob(".github/ISSUE_TEMPLATE/*.yml")):
    yaml.safe_load(open(f)); print("parsed", f)
PY
```
Expected: four `parsed ...` lines, no traceback.

- [ ] **Step 2 (optional, needs network): Schema-validate against SchemaStore**

```bash
uvx check-jsonschema --schemafile https://json.schemastore.org/github-issue-forms.json \
  .github/ISSUE_TEMPLATE/bug-report.yml \
  .github/ISSUE_TEMPLATE/feature-request.yml \
  .github/ISSUE_TEMPLATE/verdict-report.yml
uvx check-jsonschema --schemafile https://json.schemastore.org/github-issue-config.json \
  .github/ISSUE_TEMPLATE/config.yml
```
Expected: `ok -- validation done`. (Skip if offline.)

- [ ] **Step 3: Create the labels on the live repo** *(authorized, mutates GitHub)*

```bash
scripts/setup-labels.sh
gh label list --repo vinsoc-cyber/VulnHunterX | grep -E "triage-quality|codeql|semgrep|opengrep|rules|llm-verification|sarif|cli|fuzzing|reporting|config"
```
Expected: all created labels listed. (Run before relying on the verdict form's `triage-quality` auto-label.)

- [ ] **Step 4: Push the branch and open a PR** *(authorized, outward-facing)*

```bash
git push -u origin feat/issue-templates
gh pr create --repo vinsoc-cyber/VulnHunterX --base main --head feat/issue-templates \
  --title "Add GitHub issue templates + label taxonomy" \
  --body "Adds bug/feature/verdict issue forms, a config chooser, and a label-setup script. Design: docs/superpowers/specs/2026-06-22-issue-templates-design.md

https://claude.ai/code/session_01VWakvTYWCobyatPUWwMsr2"
```

- [ ] **Step 5: Verify on GitHub (manual)**

On the repo: **Issues → New issue** shows three forms (Bug report, Feature request, Verdict / false-positive report); blank issues are disabled; the chooser shows the Questions/Security/Docs contact links. Confirm a newly opened test issue from each form receives its type label.
