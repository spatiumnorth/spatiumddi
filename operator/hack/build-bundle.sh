#!/usr/bin/env bash
# Build the OLM bundle for one release, and optionally lay it out for the two
# OperatorHub catalog repositories.
#
#   operator/hack/build-bundle.sh VERSION [--out DIR] [--community DIR] [--validate]
#
#   VERSION        SemVer of the release, no leading "v": 1.0.0, 1.0.0-rc.2.
#                  CalVer tags (2026.09.04-1) are not SemVer and OLM cannot
#                  order them; the operator starts at 1.0.0.
#   --out DIR      where the bundle (manifests/ metadata/) is written.
#                  Default: operator/bundle (the checked-in dev bundle).
#   --community D  also write D/operators/spatiumddi/<VERSION>/{manifests,
#                  metadata} and D/operators/spatiumddi/ci.yaml, the layout
#                  k8s-operatorhub/community-operators and
#                  redhat-openshift-ecosystem/community-operators-prod expect.
#   --validate     run `operator-sdk bundle validate` with the
#                  operatorframework optional suite on the result.
#
# Everything that needs operator-sdk runs in the pinned operator-sdk image
# (through docker), so nothing is installed on the host. The checked-in
# operator/bundle is generated at VERSION=0.0.0-dev, the same placeholder the
# chart carries; CI regenerates it and fails when it differs.
#
# HOW A RELEASE BUMPS IT: nothing is edited by hand. The release runs
#   make operator-bundle VERSION=<release> COMMUNITY=<dir>
# and the image build gets --build-arg VERSION=<release>. The bundle's CSV
# version, its image tag, and the chart version / appVersion baked into the
# operator image are the one release version, so a CSV, an image and a chart
# can never disagree about what they are.
set -euo pipefail

SDK_IMAGE="${OPERATOR_SDK_IMAGE:-quay.io/operator-framework/operator-sdk:v1.42.3}"
IMAGE_REPO="${OPERATOR_IMAGE_REPO:-ghcr.io/spatiumnorth/spatiumddi-operator}"
PACKAGE="spatiumddi"
# The OperatorHub minimum: OpenShift 4.18 is Kubernetes 1.31, the chart's floor.
OCP_VERSIONS="${OPERATOR_OCP_VERSIONS:-v4.18}"
# Fixed so the generated bundle is reproducible; a release passes its own.
CREATED_AT="${OPERATOR_CREATED_AT:-1970-01-01T00:00:00Z}"

die() { echo "build-bundle: $*" >&2; exit 1; }

VERSION="${1:-}"; [ -n "$VERSION" ] || die "usage: build-bundle.sh VERSION [--out DIR] [--community DIR] [--validate]"
shift
OUT=""; COMMUNITY=""; VALIDATE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --community) COMMUNITY="$2"; shift 2 ;;
    --validate) VALIDATE=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

# SemVer 2.0.0 (https://semver.org), the regex it publishes.
SEMVER='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*))?(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$'
[[ "$VERSION" =~ $SEMVER ]] || die "VERSION '$VERSION' is not SemVer (OLM orders releases by it; CalVer tags do not qualify)"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # operator/
REPO="$(cd "$HERE/.." && pwd)"
# The checked-in dev bundle is the default target, unless only a community
# layout was asked for (so that run never rewrites it as a side effect).
if [ -z "$OUT" ] && [ -z "$COMMUNITY" ]; then OUT="$HERE/bundle"; fi
RUN="${DOCKRUN:-}"   # the dev boxes set DOCKRUN=~/.spatium-ops/work/dockrun

# A pre-release goes to the candidate channel ONLY, so a release candidate is
# never offered to a subscription tracking stable.
if [[ "$VERSION" == *-* ]]; then CHANNELS="candidate"; DEFAULT_CHANNEL="candidate"
else CHANNELS="stable,candidate"; DEFAULT_CHANNEL="stable"; fi

STAGE="$(mktemp -d "$HERE/.stage.XXXXXX")"
[ -n "${KEEP_STAGE:-}" ] || trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/out"
cp "$HERE/PROJECT" "$STAGE/PROJECT"

IMAGE="$IMAGE_REPO:$VERSION"
ICON="$(base64 -w0 "$REPO/docs/assets/logo-icon.svg")"
sed -e "s|@ICON@|$ICON|" \
    -e "s|containerImage: .*|containerImage: $IMAGE|" \
    -e "s|createdAt: .*|createdAt: \"$CREATED_AT\"|" \
    "$HERE/config/manifests/bases/spatiumddi.clusterserviceversion.yaml" \
    > "$STAGE/csv-base.yaml"

# operator-sdk reads the manifests as one multi-document stream, which is what
# `kustomize build` would hand it; there is nothing to kustomize here, so the
# stream is just the files, with the image stamped.
{
  cat "$HERE/config/crd/"*.yaml; echo '---'
  for f in service_account role role_binding cluster_role cluster_role_binding; do
    cat "$HERE/config/rbac/$f.yaml"; echo '---'
  done
  sed "s|image: .*spatiumddi-operator:.*|image: $IMAGE|" "$HERE/config/manager/manager.yaml"; echo '---'
  cat "$HERE/config/samples/"*.yaml; echo '---'
  # The CSV base rides in the same stream (in a kustomize setup it is a
  # resource of config/manifests); operator-sdk merges the rest into it.
  cat "$STAGE/csv-base.yaml"
} > "$STAGE/stream.yaml"

sdk() {
  # shellcheck disable=SC2086
  $RUN docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$STAGE:/w" -w /w "$SDK_IMAGE" "$@"
}

# operator-sdk reads the stream on stdin and insists it is a pipe. It is piped INSIDE the container
# rather than into `docker run -i`, because a docker wrapper that
# offloads to another host (dockrun) drops stdin and operator-sdk then
# silently builds a bundle from nothing.
# shellcheck disable=SC2086
$RUN docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$STAGE:/w" -w /w \
  --entrypoint sh "$SDK_IMAGE" -c "cat stream.yaml | operator-sdk generate bundle -q --overwrite \
    --version '$VERSION' --package '$PACKAGE' --channels '$CHANNELS' \
    --default-channel '$DEFAULT_CHANNEL' --output-dir out --manifests --metadata"
test -s "$STAGE/out/manifests/ddi.spatiumddi.com_spatiumddis.yaml" || die "operator-sdk produced no CRD: the manifest stream was not read"

# operator-sdk stamps createdAt with the wall clock, which would make the
# checked-in bundle differ on every run; pin it.
sed -i "s|^    createdAt: .*|    createdAt: \"$CREATED_AT\"|" "$STAGE/out/manifests/$PACKAGE.clusterserviceversion.yaml"

# OpenShift's catalog reads the supported-OCP range from the bundle metadata.
# The metadata file is operator-sdk's; append instead of re-templating it.
ANN="$STAGE/out/metadata/annotations.yaml"
grep -q 'com.redhat.openshift.versions' "$ANN" || \
  printf '\n  # Minimum OpenShift (4.18 = Kubernetes 1.31, the chart floor).\n  com.redhat.openshift.versions: "%s"\n' "$OCP_VERSIONS" >> "$ANN"

if [ "$VALIDATE" = 1 ]; then
  sdk bundle validate ./out --select-optional suite=operatorframework \
    --optional-values=k8s-version=1.31
fi

place() { # place DIR  -> DIR/manifests DIR/metadata
  rm -rf "$1/manifests" "$1/metadata"; mkdir -p "$1"
  cp -r "$STAGE/out/manifests" "$STAGE/out/metadata" "$1/"
}
[ -z "$OUT" ] || place "$OUT"
# bundle.Dockerfile builds the bundle image from the OLM layout; it is built
# with operator/ as the context, so it copies from bundle/. (The catalogs
# build their own bundle image from the community layout below.)
if [ "$OUT" = "$HERE/bundle" ]; then
  sed -e 's|^COPY out/|COPY bundle/|' "$STAGE/bundle.Dockerfile" > "$HERE/bundle.Dockerfile"
  printf '\n# OpenShift catalog: the minimum OpenShift this bundle installs on.\nLABEL com.redhat.openshift.versions="%s"\n' "$OCP_VERSIONS" >> "$HERE/bundle.Dockerfile"
fi

if [ -n "$COMMUNITY" ]; then
  PKGDIR="$COMMUNITY/operators/$PACKAGE"
  place "$PKGDIR/$VERSION"
  # ci.yaml is per package, not per version: reviewers who may approve the
  # catalog PRs, and the upgrade graph mode (semver-mode orders by version).
  cat > "$PKGDIR/ci.yaml" <<CI
---
# https://k8s-operatorhub.github.io/community-operators/operator-ci-yaml/
updateGraph: semver-mode
reviewers:
  - mzac
  - amoona6
CI
  echo "community layout: $PKGDIR/$VERSION"
fi
echo "bundle $VERSION (channels: $CHANNELS) -> $OUT"
