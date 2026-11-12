#!/usr/bin/env bash
# Names a nightly build, from the ref it builds (#3950).
#
#   nightly-names.sh <ref> <YYYYMMDD night date> <full commit sha>
#
# Prints key=value lines for $GITHUB_OUTPUT. <ref> is `main` (the nightly as it
# has always been) or `release/X.Y.Z` (a release branch's own nightly); anything
# else is refused. A release branch's names carry X.Y.Z so its tags, images and
# pre-releases form a ring of their own, and neither ring's prune can match the
# other's. A branch's pre-release tag must NOT start with "nightly": the QA
# harness (ddi-pg) takes the newest pre-release whose tag starts with
# "nightly" as main's nightly, so it is "branch-nightly-...":
#
#                main                          release/1.0.1
#   date_tag     nightly-20261112              nightly-1.0.1-20261112
#   pointer_tag  nightly                       nightly-1.0.1
#   release_tag  nightly-2026.11.12            branch-nightly-1.0.1-2026.11.12
#   version      0.0.0-nightly-20261112+abc1234
#                                              0.0.0-nightly-20261112+release-1.0.1.abc1234
#
# The version stays 0.0.0-nightly-YYYYMMDD so backend/app/core/versions.py (and
# its frontend mirror) keep reading it as a nightly: an UNKNOWN version, never
# newer than a release. Writing it 1.0.1-nightly... would parse as a SemVer
# pre-release of 1.0.1, i.e. a known release newer than 1.0.0. The branch rides
# in the build metadata, which both parsers allow and ignore.
set -euo pipefail

REF="${1:-main}"
NIGHT_DATE="${2:?night date YYYYMMDD required}"
SHA="${3:?commit sha required}"

if [[ ! "$NIGHT_DATE" =~ ^[0-9]{8}$ ]]; then
  echo "::error::night date '${NIGHT_DATE}' is not YYYYMMDD" >&2
  exit 1
fi

DOTTED="${NIGHT_DATE:0:4}.${NIGHT_DATE:4:2}.${NIGHT_DATE:6:2}"

if [ "$REF" = "main" ]; then
  echo "ref=main"
  echo "branch_version="
  echo "date_tag=nightly-${NIGHT_DATE}"
  echo "pointer_tag=nightly"
  echo "release_tag=nightly-${DOTTED}"
  echo "version=0.0.0-nightly-${NIGHT_DATE}+${SHA::7}"
  echo "cache_scope=nightly"
  echo 'image_ring_re=^nightly-[0-9]{8}$'
  echo 'release_ring_re=^nightly-[0-9]{4}\.[0-9]{2}\.[0-9]{2}$'
elif [[ "$REF" =~ ^release/([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  V="${BASH_REMATCH[1]}"
  VRE="${V//./\\.}"
  echo "ref=${REF}"
  echo "branch_version=${V}"
  echo "date_tag=nightly-${V}-${NIGHT_DATE}"
  echo "pointer_tag=nightly-${V}"
  echo "release_tag=branch-nightly-${V}-${DOTTED}"
  echo "version=0.0.0-nightly-${NIGHT_DATE}+release-${V}.${SHA::7}"
  echo "cache_scope=nightly-${V}"
  echo "image_ring_re=^nightly-${VRE}-[0-9]{8}\$"
  echo "release_ring_re=^branch-nightly-${VRE}-[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}\$"
else
  echo "::error::ref '${REF}' must be 'main' or match ^release/[0-9]+\\.[0-9]+\\.[0-9]+\$" >&2
  exit 1
fi
