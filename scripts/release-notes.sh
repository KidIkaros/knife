#!/usr/bin/env bash
# Print the CHANGELOG section for a version, plus a compare-link trailer.
# Usage: release-notes.sh 1.8.0
set -euo pipefail
version="${1:?usage: release-notes.sh VERSION}"
awk -v v="$version" '
  $0 == "## v" v { found = 1; next }
  found && /^## v/ { exit }
  found { print }
' CHANGELOG.md > notes.md
if [ ! -s notes.md ]; then
  echo "no CHANGELOG section for v$version" >&2
  exit 1
fi
previous="$(git describe --abbrev=0 --tags "v$version^" 2>/dev/null || true)"
printf '\n**Full Changelog**: https://github.com/%s/compare/%s\n' \
  "$GITHUB_REPOSITORY" "${previous}...v$version" >> notes.md
