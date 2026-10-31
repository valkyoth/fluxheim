#!/usr/bin/env bash
set -euo pipefail

# macOS's default /var/folders TMPDIR crosses /var's symlink. Production
# filesystem checks intentionally reject that path, including in test fixtures.
directory="$(mktemp -d "$HOME/.fluxheim-ci-tmp.XXXXXX")"
directory="$(cd "$directory" && pwd -P)"
printf 'TMPDIR=%s\n' "$directory" >> "${GITHUB_ENV:?GITHUB_ENV is required}"
