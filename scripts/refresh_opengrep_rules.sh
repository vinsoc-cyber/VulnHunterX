#!/usr/bin/env bash
#
# Refresh the vendored, registry-free OpenGrep rule snapshot under
# config/opengrep-rules/. OpenGrep runs these offline instead of pulling
# auto/p-pack rules from registry.semgrep.dev — see config/opengrep-rules/NOTICE.md.
#
# Upstream (github.com/opengrep/opengrep-rules) was archived 2025-11-28, so this
# pins an explicit commit. Pass a commit-ish to bump it; defaults to the SHA
# currently recorded in NOTICE.md.
#
# IMPORTANT: these rules are LGPL-2.1 + Commons Clause (NOT MIT). This script
# copies their LICENSE verbatim. Do not strip it.
#
# Usage:
#   scripts/refresh_opengrep_rules.sh [<commit-ish>]
set -euo pipefail

REPO_URL="https://github.com/opengrep/opengrep-rules.git"
DEFAULT_COMMIT="f1d2b562b414783763fd02a6ed2736eaed622efa"
COMMIT="${1:-$DEFAULT_COMMIT}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/config/opengrep-rules"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Cloning $REPO_URL @ $COMMIT ..."
git clone --quiet "$REPO_URL" "$TMP/src"
git -C "$TMP/src" checkout --quiet "$COMMIT"
RESOLVED="$(git -C "$TMP/src" rev-parse HEAD)"

# project ${LANG} key -> upstream source dir
declare -A LANG_MAP=(
  [python]=python [javascript]=javascript [typescript]=typescript
  [java]=java [php]=php [go]=go [csharp]=csharp [c]=c [cpp]=c
)

copy_lang() {
  local dst="$1" src="$2"
  rm -rf "${DEST:?}/$dst"
  mkdir -p "$DEST/$dst"
  rsync -rm --include='*/' --include='*.yaml' --include='*.yml' --exclude='*' \
    "$TMP/src/$src/" "$DEST/$dst/"
  echo "  $dst <- $src ($(find "$DEST/$dst" -name '*.y*ml' | wc -l | tr -d ' ') rules)"
}

echo "Vendoring rule YAML (test-target source files are skipped) ..."
for lang in "${!LANG_MAP[@]}"; do
  copy_lang "$lang" "${LANG_MAP[$lang]}"
done

cp "$TMP/src/LICENSE" "$DEST/LICENSE"

echo
echo "Done. Resolved commit: $RESOLVED"
echo "Update the Commit/Imported fields in $DEST/NOTICE.md if this changed."
