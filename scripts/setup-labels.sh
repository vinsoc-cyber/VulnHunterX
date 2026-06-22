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

# Triage-error sub-labels (applied alongside triage-quality during triage).
gh label create over-confirmed   --repo "$REPO" --force --color "e99695" --description "VulnHunterX said TP but the finding is FP (over-confirmation)"
gh label create over-dismissed   --repo "$REPO" --force --color "d93f0b" --description "VulnHunterX said FP but the finding is TP (real bug dismissed)"
gh label create false-negative   --repo "$REPO" --force --color "b60205" --description "Vulnerability never surfaced by the scanner (coverage gap)"

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
