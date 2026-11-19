#!/usr/bin/env bash
# fetch-k3s.sh — issue #183 Phase 1.
#
# Downloads the pinned k3s release into the appliance's mkosi.extra/
# tree so the slot image ships a fully-airgapped Kubernetes runtime.
#
# The slot rootfs ends up carrying:
#   /usr/local/bin/k3s                                  static binary
#   /usr/local/bin/{kubectl,crictl,ctr}                 symlinks → k3s
#   /var/lib/rancher/k3s/agent/images/
#       k3s-airgap-images-<arch>.tar.zst                CoreDNS / pause /
#                                                       local-path-provisioner /
#                                                       metrics-server /
#                                                       traefik (auto-imported
#                                                       on first start)
#   /usr/share/doc/k3s/LICENSE
#   /usr/share/doc/k3s/NOTICE                           (when present
#                                                       upstream — older
#                                                       releases skip it)
#   /usr/share/doc/k3s/k3s-images.txt                   pinned-version manifest
#                                                       (debug + future image
#                                                       overrides)
#
# Re-runs are cheap — every artifact short-circuits if the destination
# already exists AND the pinned version matches the stamped sidecar.
# Bumping ``K3S_VERSION`` invalidates the cache + forces a re-download.
#
# Air-gap rationale: every byte the appliance needs at runtime ships
# in the slot image. The CI build runner has outbound — that's where
# the fetch happens. The fielded appliance does NOT reach github.com
# / get.k3s.io at first boot. See issue #183's air-gap section.

set -euo pipefail

# Pinned k3s version. The canonical pin lives in the top-level
# Makefile (``K3S_VERSION ?= ...``) and is exported into this script
# via the env. The default below is a fallback for operators who run
# this script directly (without ``make``); CI + the Makefile always
# override it. Keep this in sync with the Makefile pin so a direct
# invocation never silently pulls a stale release tag.
K3S_VERSION="${K3S_VERSION:-v1.36.5+k3s1}"

# Target architecture. Defaults to the build host's arch; release CI
# overrides per matrix entry so each arch carries its own k3s + airgap
# tarball.
ARCH="${ARCH:-$(uname -m)}"
case "$ARCH" in
    x86_64|amd64) K3S_ARCH="" ; AIRGAP_ARCH="amd64" ;;  # k3s amd64 binary has no suffix
    aarch64|arm64) K3S_ARCH="-arm64" ; AIRGAP_ARCH="arm64" ;;
    armv7l|armv7|armhf) K3S_ARCH="-armhf" ; AIRGAP_ARCH="arm" ;;
    *)
        echo "ERROR: unsupported architecture '$ARCH' — k3s ships amd64 / arm64 / armhf" >&2
        exit 2
        ;;
esac

# Paths inside the appliance source tree. The mkosi build later
# copies mkosi.extra/ verbatim into the rootfs.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLIANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MKOSI_EXTRA="$APPLIANCE_DIR/mkosi.extra"
K3S_BIN="$MKOSI_EXTRA/usr/local/bin/k3s"
AIRGAP_DIR="$MKOSI_EXTRA/var/lib/rancher/k3s/agent/images"
AIRGAP_TARBALL="$AIRGAP_DIR/k3s-airgap-images-$AIRGAP_ARCH.tar.zst"
DOC_DIR="$MKOSI_EXTRA/usr/share/doc/k3s"
VERSION_STAMP="$DOC_DIR/.version"

mkdir -p "$(dirname "$K3S_BIN")" "$AIRGAP_DIR" "$DOC_DIR"

# Cache short-circuit: if the stamp matches the pinned version AND the
# architecture, every artifact has been fetched against the same release
# tag for the same silicon — skip.
#
# #1026 — THE ARCHITECTURE IS PART OF THE STAMP, and it has to be. The
# airgap tarball is arch-named so both can sit side by side, but the
# binary is a single un-suffixed path (``usr/local/bin/k3s``). Keyed on
# the version alone, building arm64 and then amd64 again found a
# matching stamp, an existing amd64 tarball and an existing binary — and
# skipped, leaving the ARM binary in place. The ISO builds, boots, and
# k3s never starts: "cannot execute binary file". Nothing in the build
# log says a word, because from the fetcher's point of view everything
# it was asked for was already there.
STAMP_VALUE="$K3S_VERSION $AIRGAP_ARCH"
if [ -f "$VERSION_STAMP" ] && [ "$(cat "$VERSION_STAMP")" = "$STAMP_VALUE" ] \
        && [ -x "$K3S_BIN" ] && [ -f "$AIRGAP_TARBALL" ]; then
    echo "→ k3s $K3S_VERSION already fetched for $AIRGAP_ARCH (skip)"
    exit 0
fi

# Drop any OTHER architecture's airgap tarball before fetching. They are
# arch-named so they do not collide, which is exactly the problem: left
# behind, mkosi bakes ~250 MiB of the wrong architecture's container
# images into the rootfs, and k3s imports them at startup.
for _stale in "$AIRGAP_DIR"/k3s-airgap-images-*.tar.zst; do
    [ -e "$_stale" ] || continue
    case "$_stale" in
        "$AIRGAP_TARBALL") ;;
        *) echo "  → dropping other-arch airgap tarball $(basename "$_stale")"
           rm -f "$_stale" ;;
    esac
done

BASE_URL="https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}"

fetch() {
    local url="$1" dest="$2"
    echo "  → $url"
    # --fail returns non-zero on 4xx/5xx so a bad version pin doesn't
    # silently produce a "Not Found" HTML body. -L follows redirects
    # (GitHub serves release assets via objects.githubusercontent.com).
    curl --fail --silent --show-error --location \
         --connect-timeout 15 --max-time 600 \
         -o "$dest" "$url"
}

echo "→ Fetching k3s $K3S_VERSION for $AIRGAP_ARCH"

# 1. k3s binary itself
TMP_BIN="${K3S_BIN}.partial"
fetch "${BASE_URL}/k3s${K3S_ARCH}" "$TMP_BIN"
mv "$TMP_BIN" "$K3S_BIN"
chmod 0755 "$K3S_BIN"

# 2. Symlink kubectl / crictl / ctr to k3s. The k3s binary dispatches
# on argv[0]: ``kubectl`` → embedded kubectl, ``crictl`` → embedded
# crictl, ``ctr`` → embedded containerd CLI. Operators get the full
# k8s + containerd surface without extra binaries.
for name in kubectl crictl ctr; do
    ln -sfn k3s "$MKOSI_EXTRA/usr/local/bin/$name"
done

# 3. Air-gap images tarball — auto-imported by k3s on first start when
# placed under /var/lib/rancher/k3s/agent/images/. Carries:
#   rancher/mirrored-coredns-coredns
#   rancher/mirrored-library-traefik   (we disable traefik but the
#                                       tarball includes it)
#   rancher/local-path-provisioner
#   rancher/mirrored-metrics-server
#   rancher/mirrored-pause             (containerd sandbox container)
TMP_AIRGAP="${AIRGAP_TARBALL}.partial"
fetch "${BASE_URL}/k3s-airgap-images-${AIRGAP_ARCH}.tar.zst" "$TMP_AIRGAP"
mv "$TMP_AIRGAP" "$AIRGAP_TARBALL"

# 4. Image manifest — list of images + tags that ship in this k3s
# release. Useful for ``kubectl describe`` diagnostics and future
# image-override config.
fetch "${BASE_URL}/k3s-images.txt" "$DOC_DIR/k3s-images.txt"

# 5. License + NOTICE — Apache 2.0 distribution obligation.
# Source the LICENSE from the release tag (not HEAD) so the text
# matches the binary's actual provenance.
fetch "https://raw.githubusercontent.com/k3s-io/k3s/${K3S_VERSION}/LICENSE" \
      "$DOC_DIR/LICENSE"
# NOTICE may not exist on every k3s release tag — keep the fetch
# soft so a missing file doesn't break the build.
if ! fetch "https://raw.githubusercontent.com/k3s-io/k3s/${K3S_VERSION}/NOTICE" \
           "$DOC_DIR/NOTICE" 2>/dev/null; then
    echo "  (NOTICE not present at this release tag — skipping)"
    rm -f "$DOC_DIR/NOTICE"
fi

# 6. Stamp the version so re-runs short-circuit.
# Written LAST, and carrying the architecture (#1026) so the
# short-circuit above can tell an arch switch from a no-op.
echo "$STAMP_VALUE" > "$VERSION_STAMP"

# Sanity: confirm the binary is statically linked + executable.
# A failed download or wrong-arch binary would surface as a libc
# mismatch at first boot otherwise.
if ! file "$K3S_BIN" 2>/dev/null | grep -q 'statically linked\|static-pie linked'; then
    echo "WARN: k3s binary doesn't report 'statically linked' from file(1)" >&2
    echo "      (continuing anyway — file(1) may be missing in the build env)" >&2
fi

SIZE_BIN=$(du -h "$K3S_BIN" | awk '{print $1}')
SIZE_AIR=$(du -h "$AIRGAP_TARBALL" | awk '{print $1}')
echo "✓ k3s $K3S_VERSION baked into mkosi.extra/"
echo "  k3s binary:       $SIZE_BIN"
echo "  airgap tarball:   $SIZE_AIR"
echo "  arch:             $AIRGAP_ARCH"
