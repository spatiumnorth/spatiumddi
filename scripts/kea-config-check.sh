#!/usr/bin/env bash
# kea-config-check.sh — load the golden rendered Kea config into a Kea image
# with `kea-dhcp4 -t` (`make kea-config-check`, build-dhcp-images.yml).
#
#   usage: scripts/kea-config-check.sh <image>
#
# The golden (agent/dhcp/tests/fixtures/kea_golden_dhcp4*.json) is what
# render_kea produces for a fixture bundle; the agent test
# test_render_kea_relay_retention.py fails when the renderer and the golden
# disagree, so this checks the current render. Before #54 nothing in the repo
# ran Kea's own parser over a rendered config: every "measured against
# kea-dhcp4 3.0.3" note was a manual run, and a key Kea rejects was found by
# an agent reverting a live bundle.
#
# Exit status: 0 every golden loads, 1 Kea rejected one, 2 the check could
# not run (no golden, or Docker could not start the image).

set -uo pipefail

image="${1:?usage: $0 <kea image>}"
here="$(cd "$(dirname "$0")/.." && pwd)"
fixtures="$here/agent/dhcp/tests/fixtures"

shopt -s nullglob
goldens=("$fixtures"/kea_golden_dhcp4*.json)
if [ "${#goldens[@]}" -eq 0 ]; then
  echo "✗ no golden Kea config under $fixtures" >&2
  exit 2
fi

status=0
for golden in "${goldens[@]}"; do
  name="$(basename "$golden")"
  # /run/kea ships 0755 and the entrypoint tightens it to 0750 at start; Kea
  # 3.0 refuses a control-socket directory looser than that, so do the same
  # before `-t`, which validates the socket path.
  if docker run --rm --network none \
    -v "$fixtures:/golden:ro" \
    --entrypoint sh "$image" \
    -c 'chmod 0750 /run/kea || exit 125; exec kea-dhcp4 -t "/golden/$1"' sh "$name"; then
    echo "✓ $name loads in $image"
  else
    rc=$?
    if [ "$rc" -ge 125 ]; then
      echo "✗ could not run $image (docker exit $rc)" >&2
      exit 2
    fi
    echo "✗ kea-dhcp4 -t rejected $name (exit $rc)" >&2
    status=1
  fi
done
exit "$status"
