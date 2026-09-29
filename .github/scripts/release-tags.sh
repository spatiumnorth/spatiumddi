#!/usr/bin/env bash
# release-tags.sh — the tags a release decision may rank against (#1226).
#
#   usage: .github/scripts/release-tags.sh      (prints one tag per line)
#
# release.yml decides "which release came before this one" and "is this the
# newest release" (scripts/release_version.py) by ranking tags. Ranking
# against every tag in the repository lets one stray tag take over the
# ordering for good: a `2027.01.01-1` typo, or a `9.0.0` pushed on a feature
# branch, is refused by release.yml's own gate but stays in `git tag -l`,
# and from then on no real release would ever become :latest. So a tag
# counts only when it is on main AND has a published (non-draft) GitHub
# release, which only release.yml creates, and only past its gates.
#
# Needs a checkout with history (fetch-depth: 0), GH_TOKEN, and
# GITHUB_REPOSITORY. Any git or gh failure is fatal: an empty list would
# read as "no earlier release", which makes every tag the newest.
set -euo pipefail

git fetch --no-tags --quiet origin +refs/heads/main:refs/remotes/origin/main
git fetch --tags --force --quiet origin

merged=$(git tag --merged origin/main)
published=$(gh release list --repo "$GITHUB_REPOSITORY" --limit 1000 --exclude-drafts \
  --json tagName --jq '.[].tagName')

comm -12 <(printf '%s\n' "$merged" | sort -u) <(printf '%s\n' "$published" | sort -u)
