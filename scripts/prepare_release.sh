#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber
#
# Prepare a release archive for upload (GitHub Releases / PyPI).
#
# What it does:
#   1. Resolves the release version from pyproject.toml (or --version).
#   2. Verifies the version is consistent across pyproject.toml,
#      src/vuln_hunter_x/__init__.py, and CHANGELOG.md.
#   3. Warns if the working tree is dirty or the git tag is missing / not
#      pointing at HEAD (does not block — pass --strict to make these fatal).
#   4. Builds the sdist + wheel into dist/ (uv build, falling back to
#      python -m build).
#   5. Runs `twine check` on the artifacts when twine is installed.
#   6. Extracts this version's CHANGELOG section to dist/RELEASE_NOTES.md.
#   7. Writes dist/SHA256SUMS over the artifacts.
#   8. Bundles everything into dist/vulnhunterx-<version>-release.tar.gz,
#      ready to attach to a GitHub Release.
#
# Usage:
#   scripts/prepare_release.sh [--version X.Y.Z] [--strict] [--no-build]
#
# After it runs, upload with either:
#   gh release create <version> dist/vulnhunterx-<version>* \
#       --title "<version>" --notes-file dist/RELEASE_NOTES.md
#   # or publish the package to PyPI:
#   twine upload dist/vulnhunterx-<version>.tar.gz dist/vulnhunterx-<version>-*.whl

set -euo pipefail

# --- locate repo root (script lives in scripts/) ---------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
cd "$ROOT"

# --- pick a python: prefer the project venv --------------------------------
if [[ -x "$ROOT/.venv/bin/python" ]]; then
    PY="$ROOT/.venv/bin/python"
else
    PY="$(command -v python3 || command -v python)"
fi

# --- args ------------------------------------------------------------------
VERSION=""
STRICT=0
DO_BUILD=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --strict)  STRICT=1; shift ;;
        --no-build) DO_BUILD=0; shift ;;
        -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "error: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

# warn() honors --strict: warnings become fatal errors.
fail=0
warn() {
    if [[ "$STRICT" == "1" ]]; then red "ERROR: $*"; fail=1; else yellow "WARN: $*"; fi
}
die() { red "ERROR: $*"; exit 1; }

# --- resolve & cross-check version -----------------------------------------
pyproject_version() {
    "$PY" - "$ROOT/pyproject.toml" <<'EOF'
import sys, re
text = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', text)
print(m.group(1) if m else "")
EOF
}

PYPROJECT_VERSION="$(pyproject_version)"
[[ -n "$PYPROJECT_VERSION" ]] || die "could not read version from pyproject.toml"

if [[ -z "$VERSION" ]]; then
    VERSION="$PYPROJECT_VERSION"
elif [[ "$VERSION" != "$PYPROJECT_VERSION" ]]; then
    warn "--version $VERSION != pyproject.toml version $PYPROJECT_VERSION"
fi
green "Preparing release: $VERSION"

# __init__.py
INIT="$ROOT/src/vuln_hunter_x/__init__.py"
INIT_VERSION="$(grep -oE '__version__\s*=\s*"[^"]+"' "$INIT" | grep -oE '"[^"]+"' | tr -d '"' || true)"
if [[ "$INIT_VERSION" != "$VERSION" ]]; then
    warn "__init__.py version ($INIT_VERSION) != $VERSION"
else
    green "  __init__.py version OK ($INIT_VERSION)"
fi

# CHANGELOG must have a matching section heading
if grep -qE "^##\s*\[$( printf '%s' "$VERSION" | sed 's/\./\\./g')\]" "$ROOT/CHANGELOG.md"; then
    green "  CHANGELOG.md has a [$VERSION] section"
else
    warn "CHANGELOG.md has no '## [$VERSION]' section"
fi

# --- git sanity (non-fatal unless --strict) --------------------------------
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    if [[ -n "$(git -C "$ROOT" status --porcelain)" ]]; then
        warn "working tree is dirty; archive may not match a clean tag"
    fi
    if git -C "$ROOT" rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
        if [[ "$(git -C "$ROOT" rev-list -n1 "$VERSION")" != "$(git -C "$ROOT" rev-parse HEAD)" ]]; then
            warn "tag $VERSION does not point at HEAD"
        else
            green "  git tag $VERSION points at HEAD"
        fi
    else
        warn "git tag $VERSION does not exist yet (create with: git tag -a $VERSION -m \"Release $VERSION\")"
    fi
fi

[[ "$fail" == "0" ]] || die "aborting due to --strict failures above"

# --- build -----------------------------------------------------------------
DIST="$ROOT/dist"
if [[ "$DO_BUILD" == "1" ]]; then
    echo "Cleaning $DIST ..."
    rm -rf "$DIST"
    echo "Building sdist + wheel ..."
    if command -v uv >/dev/null 2>&1; then
        uv build
    else
        "$PY" -m build
    fi
else
    yellow "--no-build: reusing existing artifacts in $DIST"
fi

SDIST="$DIST/vulnhunterx-$VERSION.tar.gz"
WHEEL=$(ls "$DIST"/vulnhunterx-"$VERSION"-*.whl 2>/dev/null | head -1 || true)
[[ -f "$SDIST" ]] || die "expected sdist not found: $SDIST"
[[ -n "$WHEEL" && -f "$WHEEL" ]] || die "expected wheel for $VERSION not found in $DIST"
green "  built: $(basename "$SDIST"), $(basename "$WHEEL")"

# --- twine check (optional) ------------------------------------------------
if "$PY" -c "import twine" >/dev/null 2>&1; then
    echo "Running twine check ..."
    "$PY" -m twine check "$SDIST" "$WHEEL"
    green "  twine check passed"
else
    yellow "twine not installed; skipping metadata check (pip install twine to enable)"
fi

# --- extract release notes for this version --------------------------------
NOTES="$DIST/RELEASE_NOTES.md"
"$PY" - "$ROOT/CHANGELOG.md" "$VERSION" >"$NOTES" <<'EOF'
import sys, re
path, version = sys.argv[1], sys.argv[2]
lines = open(path, encoding="utf-8").read().splitlines()
start = None
pat = re.compile(r'^##\s*\[' + re.escape(version) + r'\]')
for i, ln in enumerate(lines):
    if pat.match(ln):
        start = i
        break
if start is None:
    print(f"# {version}\n\n(no CHANGELOG section found)")
    sys.exit(0)
out = [lines[start]]
for ln in lines[start + 1:]:
    if re.match(r'^##\s*\[', ln):   # next version heading
        break
    out.append(ln)
print("\n".join(out).rstrip() + "\n")
EOF
green "  release notes -> $(basename "$NOTES")"

# --- checksums -------------------------------------------------------------
( cd "$DIST" && sha256sum "vulnhunterx-$VERSION.tar.gz" "$(basename "$WHEEL")" >SHA256SUMS )
green "  checksums -> SHA256SUMS"

# --- bundle a single upload archive ----------------------------------------
BUNDLE="$DIST/vulnhunterx-$VERSION-release.tar.gz"
tar -czf "$BUNDLE" -C "$DIST" \
    "vulnhunterx-$VERSION.tar.gz" \
    "$(basename "$WHEEL")" \
    "RELEASE_NOTES.md" \
    "SHA256SUMS"
green "  upload bundle -> $(basename "$BUNDLE")"

# --- summary + next steps --------------------------------------------------
echo
green "Release $VERSION is ready in $DIST:"
( cd "$DIST" && ls -1 "vulnhunterx-$VERSION"* RELEASE_NOTES.md SHA256SUMS 2>/dev/null | sort -u | sed 's/^/  /' )
cat <<EOF

Next steps — upload with whichever applies:

  # GitHub Release (attach sdist, wheel, checksums; notes from CHANGELOG):
  gh release create "$VERSION" \\
      "dist/vulnhunterx-$VERSION.tar.gz" \\
      "$(basename "$WHEEL" | sed 's@^@dist/@')" \\
      dist/SHA256SUMS \\
      --title "$VERSION" --notes-file dist/RELEASE_NOTES.md

  # PyPI (requires twine + credentials):
  twine upload dist/vulnhunterx-$VERSION.tar.gz dist/vulnhunterx-$VERSION-*.whl
EOF
