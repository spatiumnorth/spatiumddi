#!/usr/bin/env bash
# bake-images.sh — issue #183 Phase 7.
#
# Replaces the pre-Phase-7 docker-overlay.img approach. The k3s
# appliance preloads its container images by dropping ``*.tar.zst``
# archives into /var/lib/rancher/k3s/agent/images/. k3s scans that
# directory at startup and imports anything new into containerd —
# native, no firstboot shell-out needed.
#
# We tag each image as ``ghcr.io/spatiumnorth/<name>:${SPATIUMDDI_VERSION}``
# before save so the imported image matches the reference the chart's
# values.yaml uses. SPATIUMDDI_VERSION resolves from the Makefile (CI
# release sets it to the release tag; local dev gets ``dev-<short-sha>-
# <rand>``).
#
# Also writes /usr/lib/spatiumddi/spatiumddi-version so firstboot can
# sync .env's SPATIUMDDI_VERSION line to the baked tag — without that
# sidecar the chart's image reference would resolve to ``:latest``
# which doesn't exist in containerd, and pods would CrashLoopBackOff
# with ``ErrImagePull`` (air-gap: fatal).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLIANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$APPLIANCE_DIR/.." && pwd)"
IMAGES_DIR="$APPLIANCE_DIR/mkosi.extra/var/lib/rancher/k3s/agent/images"
VERSION_FILE="$APPLIANCE_DIR/mkosi.extra/usr/lib/spatiumddi/spatiumddi-version"

SPATIUMDDI_VERSION="${SPATIUMDDI_VERSION:-dev}"
BAKE_SOURCE="${BAKE_SOURCE:-local}"  # local (docker :dev) | ghcr (pull from ghcr.io)

# #272 follow-up — stale-source-image guard. A local bake saves whatever
# ``make build`` last produced; if the operator edited code but forgot to
# rebuild, the ISO silently ships stale images. Refuse when any SpatiumDDI
# source image is older than STALE_MAX_AGE_S unless explicitly allowed.
# ghcr pulls are always fresh, so this only applies to BAKE_SOURCE=local.
ALLOW_STALE_IMAGES="${ALLOW_STALE_IMAGES:-0}"
STALE_MAX_AGE_S="${STALE_MAX_AGE_S:-86400}"  # 24h
LIST_IMAGES_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --allow-stale-images) ALLOW_STALE_IMAGES=1 ;;
        # Print every image this script would bake, one per line, and
        # exit. ``make appliance-verify-arch`` consumes it so the
        # architecture check and the bake read ONE list — a second copy
        # (a sed scrape of the arrays below) covered only SpatiumDDI's
        # own images, which are the ones that cannot be wrong.
        --list-images) LIST_IMAGES_ONLY=1 ;;
        *) echo "WARN: ignoring unknown arg '$arg'" >&2 ;;
    esac
done

# SpatiumDDI service images. Tagged with SPATIUMDDI_VERSION so the
# chart's ``image: ghcr.io/spatiumnorth/<name>:${SPATIUMDDI_VERSION}``
# reference resolves locally without a pull.
IMAGES=(
    "ghcr.io/spatiumnorth/spatium-supervisor"
    "ghcr.io/spatiumnorth/dns-bind9"
    "ghcr.io/spatiumnorth/dns-powerdns"
    "ghcr.io/spatiumnorth/dns-technitium"
    "ghcr.io/spatiumnorth/dhcp-kea"
    # Issue #566 — BGP Looking Glass collector (GoBGP). Baked into
    # every slot per decision D3 (can_run_looking_glass hardcodes
    # True the same way DNS/DHCP do — not a conditional/optional add).
    "ghcr.io/spatiumnorth/looking-glass"
    # Phase 11 (#183) — control-plane images for the AIO + Core
    # install variants. Application-role appliances don't run these
    # pods, but baking them keeps the slot consistent across all
    # three variants (no "I built a Core but my image set was for
    # Application" gotcha) — disk cost ~250 MB extra on the slot.
    #
    # NOTE — only ``spatiumddi-api`` + ``spatiumddi-frontend`` are
    # separately-built images. The umbrella chart's worker / beat /
    # migrate Deployments + Jobs all run the SAME spatiumddi-api
    # image with different ``command:`` overrides (verified across
    # docker-compose.yml + charts/spatiumddi/templates/{api,worker,
    # beat,migrate}.yaml). Don't add ``spatiumddi-worker`` /
    # ``-beat`` / ``-migrate`` here — they don't exist in ghcr.
    "ghcr.io/spatiumnorth/spatiumddi-api"
    "ghcr.io/spatiumnorth/spatiumddi-frontend"
)

# Issue #183 Phase 8 — 3rd-party observability images. Tagged with
# the upstream version (NOT SPATIUMDDI_VERSION) since they're
# distributed-as-binaries upstream. The chart references them with
# their canonical names (``registry.k8s.io/kube-state-metrics/...:
# v2.13.0`` etc); we pull + save without retag.
#
# Format: ``<full-image>:<tag>``. Keep in lock-step with
# ``charts/spatiumddi-appliance/values.yaml`` ``observability.*``
# image refs.
OBSERVABILITY_IMAGES=(
    "registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.20.0"
    "quay.io/prometheus/node-exporter:v1.12.1"
    # Agent landing page — always-on nginx serving the rendered
    # /var/lib/spatiumddi/agent-landing/index.html on :80. Pinned to
    # 1.31.5-alpine matching values.yaml's ``agentLanding.image.tag``.
    "nginx:1.31.6-alpine"
    # Phase 11 (#183) — Redis datastore for the control plane.
    # Tag follows the umbrella chart's ``redis.image.tag`` default.
    # NOTE: the standalone ``postgres:16-alpine`` image is intentionally
    # NOT baked anymore (#277). The appliance now runs PostgreSQL under
    # CloudNativePG on every install (single instance → 3/5/7 on
    # promote); the CNPG runtime image (ghcr.io/cloudnative-pg/postgresql)
    # + operator are baked in CNPG_IMAGES below. The chart's standalone
    # StatefulSet path stays for non-appliance docker/k8s users, but the
    # appliance never renders it, so its image is dead weight in the ISO.
    "redis:8.10.2-alpine"
)

# #272 Phase 5 — MetalLB (control-plane HTTPS VIP + Phase 10 DNS/DHCP
# VIPs). Official upstream images (NOT bitnami), tagged with the chart
# appVersion. Baked so multi-node HA promotion works in air-gapped
# environments with zero outbound pulls — same as every other image.
#
# KEEP these refs in lock-step with the metallb.controller.image /
# metallb.speaker.image pins + the metallb dependency version in
# charts/spatiumddi-metallb (#286 moved MetalLB into its own wrapper
# chart + metallb-system namespace).
#
# Pinned to the full v0.15.3 release (chart + images + CRDs), NOT
# v0.16.0: v0.16.0 regressed the speaker's ServiceL2Status reconciler
# into an apiserver-flooding create-fail/not-found loop —
# metallb/metallb#3063. An image-only pin on the v0.16.0 chart does NOT
# work (its speaker probe hits /healthz:17472, which v0.15.3 doesn't
# serve → crashloop), so charts/spatiumddi-metallb pins the 0.15.3 chart
# end-to-end. Bump back to the chart default once #3063 is fixed upstream.
#
# #566 decision D1 — BGP mode (frr-k8s backend). Bake all three images
# the frr-k8s DaemonSet's pod spec pulls unconditionally: the FRR daemon
# itself (GPL v2 — flag distinctly in NOTICE), the frr-k8s reconciler
# (Apache 2.0), and the kube-rbac-proxy metrics sidecar (present TWICE
# per pod, same image, Apache 2.0) that the vendored charts/frr-k8s
# templates/controller.yaml wires in unconditionally. Tags verified
# against charts/frr-k8s/values.yaml inside the vendored
# metallb-0.15.3.tgz (frr-k8s@0.0.21) — keep in lock-step with the
# charts/spatiumddi-metallb/values.yaml `metallb.frr-k8s.frrk8s.image` /
# `.frr.image` pins, and `metallb.frr-k8s.prometheus.rbacProxy.*` for the
# kube-rbac-proxy sidecar. #575 — kube-rbac-proxy moved off the sunset
# `gcr.io/kubebuilder` mirror (now 404, which broke this bake + any
# non-airgap frr-k8s pull) to its upstream home `quay.io/brancz`; the chart
# override and the bake entry below MUST match so the baked image name is
# exactly what the frr-k8s pod pulls.
# ``metallb.speaker.frr.enabled`` stays FALSE (the
# in-speaker FRR sidecar is mutually exclusive with the frr-k8s backend
# and unused either way) so no image is baked for that path.
METALLB_IMAGES=(
    "quay.io/metallb/controller:v0.15.3"
    "quay.io/metallb/speaker:v0.15.3"
    "quay.io/metallb/frr-k8s:v0.0.21"
    "quay.io/frrouting/frr:10.4.1"
    # #575 — was gcr.io/kubebuilder/kube-rbac-proxy (sunset → 404); same image,
    # maintained registry. Keep in lock-step with charts/spatiumddi-metallb
    # values.yaml `metallb.frr-k8s.prometheus.rbacProxy.repository`.
    "quay.io/brancz/kube-rbac-proxy:v0.12.0"
)

# CloudNativePG (#272 / #277) — PostgreSQL is CNPG on every appliance
# (single-node = 1 instance, scales to 3/5/7 on control-plane promote).
# The operator runs from the spatiumddi-appliance chart's cnpg subchart;
# the runtime image is what each Cluster instance pod runs. Both MUST be
# baked or a fresh airgap install can't bring postgres up.
#   * operator tag = cloudnative-pg chart 0.29.0 appVersion (1.30.0).
#   * runtime tag  = charts/spatiumddi values.yaml postgresql.cnpg.imageName.
# KEEP in lock-step with the subchart pin in
# charts/spatiumddi-appliance/Chart.yaml (dependencies[].version) and
# charts/spatiumddi/values.yaml (cnpg.imageName). The chart VERSION is
# what that file pins; the operator tag here is its appVersion, which is
# a different number and is not written down anywhere tracked — the
# vendored tarball and Chart.lock that carry it are both gitignored
# (see .gitignore: charts/**/charts/, charts/**/Chart.lock). Read it back
# after a bump with:
#   helm dependency update charts/spatiumddi-appliance
#   helm show chart charts/spatiumddi-appliance/charts/cloudnative-pg-*.tgz | grep appVersion
CNPG_IMAGES=(
    "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.1"
    "ghcr.io/cloudnative-pg/postgresql:16"
)

if [ "$LIST_IMAGES_ONLY" = 1 ]; then
    for repo in "${IMAGES[@]}"; do printf '%s\n' "$repo"; done
    for image in "${OBSERVABILITY_IMAGES[@]}" "${METALLB_IMAGES[@]}" "${CNPG_IMAGES[@]}"; do
        printf '%s\n' "$image"
    done
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker CLI required on the build host (used to save + retag images)." >&2
    echo "       The APPLIANCE itself ships zero docker; this is build-host tooling only." >&2
    exit 2
fi
if ! command -v zstd >/dev/null 2>&1; then
    echo "ERROR: zstd required on the build host (compresses image archives)." >&2
    exit 2
fi

mkdir -p "$IMAGES_DIR" "$(dirname "$VERSION_FILE")"

# Stamp the version file BEFORE the loop so a partial run still
# carries something the firstboot reconcile can find (chart bytes
# may already match an earlier successful bake).
echo "$SPATIUMDDI_VERSION" > "$VERSION_FILE"
echo "→ SPATIUMDDI_VERSION = $SPATIUMDDI_VERSION (stamped at $VERSION_FILE)"

resolve_source_tag() {
    # ``BAKE_SOURCE=local``: use the operator's local :dev images.
    # Three naming conventions in the wild:
    #   * ``ghcr.io/spatiumnorth/<short>:dev`` — ``make build-supervisor``
    #     dual-tags this form, and dev-iso flows that tag manually.
    #   * ``spatiumddi-<short>:dev`` — ``docker compose build`` uses
    #     the compose project name (``spatiumddi``) as the image
    #     prefix.
    #   * ``<short>:dev`` — direct ``docker build`` without prefix.
    # Try them in order of specificity; the first one that exists
    # locally is the source tag we save from. On total miss the
    # caller fails with a clear error.
    #
    # ``BAKE_SOURCE=ghcr``: pull from ghcr at the requested version
    # (CI release path). Always the fully-qualified canonical name.
    local repo="$1"
    local short
    short="$(basename "$repo")"
    case "$BAKE_SOURCE" in
        local)
            for candidate in \
                "${repo}:dev" \
                "spatiumddi-${short}:dev" \
                "${short}:dev"; do
                if docker image inspect "$candidate" >/dev/null 2>&1; then
                    echo "$candidate"
                    return 0
                fi
            done
            # Nothing matched — return the canonical name so the
            # error message points at the most-likely-correct tag.
            echo "${repo}:dev"
            ;;
        ghcr)
            echo "${repo}:${SPATIUMDDI_VERSION}"
            ;;
        *)
            echo "ERROR: unknown BAKE_SOURCE=${BAKE_SOURCE}" >&2
            exit 2
            ;;
    esac
}

# Stale-source-image pre-scan (local only). Fails BEFORE baking anything
# so the operator fixes it in one rebuild rather than discovering a stale
# image after a 10-minute ISO build. Missing images aren't flagged here —
# the main loop's inspect handles those with a more specific error.

# RFC3339 → epoch seconds, on GNU *and* BSD date (#991 §4).
#
# This guard ran only on Linux until the arm64 cross-build work put it on
# macOS, where ``date -d`` is not a thing: the parse failed, the function
# returned non-zero, and the caller's ``|| continue`` skipped the check for
# every image. So the >24 h staleness guard the 2026-07 build notes rely on
# simply did not exist there — silently, which is the worst way for a guard
# not to exist. Hence both dialects, and a loud report below when neither
# works rather than a third silent skip.
rfc3339_to_epoch() {
    local ts="$1" out
    # Docker emits nanosecond precision; BSD date cannot parse it and
    # neither dialect needs it.
    ts="${ts%.*}"
    ts="${ts%Z}"
    if out="$(date -u -d "${ts}Z" +%s 2>/dev/null)"; then
        echo "$out"
        return 0
    fi
    if out="$(date -u -j -f '%Y-%m-%dT%H:%M:%S' "$ts" +%s 2>/dev/null)"; then
        echo "$out"
        return 0
    fi
    return 1
}

image_age_seconds() {
    local created_epoch
    created_epoch="$(image_created_epoch "$1")" || return 1
    echo $(( $(date +%s) - created_epoch ))
}

image_created_epoch() {
    local created
    created="$(docker image inspect "$1" --format '{{.Created}}' 2>/dev/null)" || return 1
    rfc3339_to_epoch "$created" || return 1
}

# ── Input-drift staleness (#1029) ──────────────────────────────────────
#
# The guard below used to be "is this image more than 24 h old?", which
# cannot express the thing it is actually asking. A ``docker build`` that
# is a COMPLETE CACHE HIT produces the identical image — same digest,
# same ID, same ``.Created`` — so an image whose inputs have not changed
# can never refresh its own timestamp. It simply ages past 24 h and then
# blocks every bake until somebody passes ``--allow-stale-images``, which
# is how a guard stops being read at all.
#
# Observed on the #999 ISO: ``make build`` rebuilt all eight images, and
# exactly the three whose Dockerfiles a Dependabot bump had NOT touched
# failed at 60 h. A ``docker build --pull`` reproducing the same image ID
# proved the base digest and every build input were unchanged — i.e.
# there was no action the operator could take to satisfy it.
#
# So the question is now "was this image built AFTER its inputs last
# moved?", answered from git: the last commit touching the paths that
# image's Dockerfile copies, plus the mtime of anything dirty or
# untracked under them (an uncommitted edit is exactly the "I forgot to
# rebuild" case #272 filed this guard for, and a commit-time-only
# comparison would miss it).
#
# STATED LIMIT, and the reason the wall-clock check survives as a
# WARNING: a floating base tag rebuilt upstream (``alpine:3.23`` gaining
# a CVE fix) moves nothing in git, so this cannot see it. Option 2 in
# #1029 — comparing the base image's registry digest — would, at the cost
# of a network round trip per image on every bake. Not taken; the warning
# names it instead.

#: Build inputs per image, as repo-relative paths. Keep in lock-step with
#: the ``docker build`` lines in the Makefile's ``build`` target — a
#: missing entry degrades that image to the wall-clock rule rather than
#: leaving it unguarded, and ``appliance/tests/test_bake_input_staleness.py``
#: fails when an IMAGES entry has no mapping here.
#:
#: The three DNS images deliberately do NOT share one coarse
#: ``agent/dns`` entry: a change under ``images/bind9/`` would then flag
#: powerdns and technitium as stale, and rebuilding those is a cache hit
#: that does not advance ``.Created`` — the operator would be stuck on a
#: false alarm they cannot clear, which is the very bug being fixed.
image_source_paths() {
    case "${1##*/}" in
        spatium-supervisor)  echo "agent/supervisor" ;;
        dns-bind9)           echo "agent/dns/pyproject.toml agent/dns/spatium_dns_agent agent/dns/images/bind9" ;;
        dns-powerdns)        echo "agent/dns/pyproject.toml agent/dns/spatium_dns_agent agent/dns/images/powerdns" ;;
        dns-technitium)      echo "agent/dns/pyproject.toml agent/dns/spatium_dns_agent agent/dns/images/technitium" ;;
        dhcp-kea)            echo "agent/dhcp" ;;
        looking-glass)       echo "agent/looking-glass" ;;
        spatiumddi-api)      echo "backend" ;;
        spatiumddi-frontend) echo "frontend" ;;
        *) return 1 ;;
    esac
}

# Newest mtime among ``$@`` that exists; echoes 0 when none do.
# Both stat dialects, for the same reason ``rfc3339_to_epoch`` carries
# both date dialects — this runs on the macOS cross-build host.
file_mtime() {
    stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || return 1
}

# Epoch seconds at which this image's build inputs last changed.
#   0  echoed the timestamp
#   1  git is unavailable / not a repo — caller falls back
#   2  no path mapping for this image — caller falls back
image_inputs_mtime() {
    local paths newest t f d
    paths="$(image_source_paths "$1")" || return 2
    git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1 || return 1
    # $paths is a space-separated path list we control; none of the
    # entries contain whitespace, so the split is intended. (The
    # directive must sit alone on its line — shellcheck reads trailing
    # prose as another key=value pair and IGNORES the whole disable,
    # SC1125, which is how the first cut of this suppression did
    # nothing.)
    # shellcheck disable=SC2086
    newest="$(git -C "$REPO_ROOT" log -1 --format=%ct -- $paths 2>/dev/null)" || return 1
    [ -n "$newest" ] || newest=0
    # Dirty + untracked. ``diff --name-only`` and ``ls-files --others``
    # emit BARE paths, unlike ``status --porcelain`` whose XY prefix and
    # rename arrows would have to be parsed; ``-z`` removes the quoting
    # git otherwise applies to unusual filenames.
    while IFS= read -r -d "" f; do
        # A listed path that does not exist is an uncommitted DELETION,
        # which is a source change like any other — skipping it (the
        # first cut did) left an image judged FRESH after a file was
        # removed without a rebuild. There is no file to stat, so use
        # the nearest existing ancestor directory: unlink() updates the
        # parent's mtime, and unlike stamping "now" it does not make the
        # image permanently stale on every subsequent run.
        t=""
        if [ -e "$REPO_ROOT/$f" ]; then
            t="$(file_mtime "$REPO_ROOT/$f")" || t=""
        else
            d="$(dirname "$REPO_ROOT/$f")"
            while [ ! -d "$d" ] && [ "$d" != "/" ] && [ "$d" != "." ]; do
                d="$(dirname "$d")"
            done
            [ -d "$d" ] && { t="$(file_mtime "$d")" || t=""; }
        fi
        [ -n "$t" ] || continue
        [ "$t" -gt "$newest" ] && newest="$t"
    done < <(
        # shellcheck disable=SC2086
        {
            git -C "$REPO_ROOT" diff --name-only -z HEAD -- $paths
            git -C "$REPO_ROOT" ls-files --others --exclude-standard -z -- $paths
        } 2>/dev/null
    )
    echo "$newest"
}
if [ "$BAKE_SOURCE" = "local" ] && [ "$ALLOW_STALE_IMAGES" != "1" ]; then
    stale=()
    undated=()
    unmapped=()
    aged=()
    for repo in "${IMAGES[@]}"; do
        src="$(resolve_source_tag "$repo")"
        docker image inspect "$src" >/dev/null 2>&1 || continue
        if ! created="$(image_created_epoch "$src")"; then
            undated+=("$src")
            continue
        fi
        age=$(( $(date +%s) - created ))

        # ``inputs=$(...)`` as a BARE assignment takes the command
        # substitution's exit status as its own, and this script runs
        # under ``set -e`` — so rc=1 (no git) and rc=2 (no path mapping)
        # killed the whole bake right here instead of reaching the
        # fallback below, which was therefore dead code. Outside a git
        # repo the bake exited 1 straight after the version banner, with
        # nothing said. Putting the assignment in a ``||`` list is what
        # exempts it; ``rc`` must be pre-seeded because ``$?`` is
        # consumed by the assignment itself.
        rc=0
        inputs="$(image_inputs_mtime "$repo")" || rc=$?
        case "$rc" in
            0)
                if [ "$created" -lt "$inputs" ]; then
                    stale+=("$src (built $(( (inputs - created) / 3600 ))h BEFORE its last source change)")
                elif [ "$age" -gt "$STALE_MAX_AGE_S" ]; then
                    # Inputs unchanged, so this is NOT the "you forgot to
                    # rebuild" case — it is reported only because a
                    # floating base tag can move without moving git.
                    aged+=("$src ($(( age / 3600 ))h old)")
                fi
                ;;
            *)
                # No mapping, or no git. Fall back to the wall-clock rule
                # so the image is not left unguarded — but record WHY, so
                # "the check ran a weaker test" is never silent.
                unmapped+=("$src")
                if [ "$age" -gt "$STALE_MAX_AGE_S" ]; then
                    stale+=("$src ($(( age / 3600 ))h old, inputs not determinable)")
                fi
                ;;
        esac
    done
    if [ "${#undated[@]}" -gt 0 ]; then
        # Not fatal — an unreadable timestamp says nothing about whether
        # the image is stale, and refusing the build over it would be
        # worse than the risk. But it is SAID, because a guard that
        # quietly evaluates nothing is indistinguishable from a guard
        # that passed.
        echo "WARN: could not read a build date for $(( ${#undated[@]} )) source image(s);" >&2
        echo "      the staleness check did NOT run for them:" >&2
        for u in "${undated[@]}"; do echo "        $u" >&2; done
    fi
    if [ "${#unmapped[@]}" -gt 0 ]; then
        echo "WARN: no build-input mapping (or no git) for $(( ${#unmapped[@]} )) image(s);" >&2
        echo "      they fell back to the weaker >$(( STALE_MAX_AGE_S / 3600 ))h wall-clock rule:" >&2
        for u in "${unmapped[@]}"; do echo "        $u" >&2; done
        echo "      Add them to image_source_paths() in this script." >&2
    fi
    if [ "${#aged[@]}" -gt 0 ]; then
        echo "NOTE: $(( ${#aged[@]} )) source image(s) are over $(( STALE_MAX_AGE_S / 3600 ))h old" >&2
        echo "      but their git inputs have NOT moved since they were built, so they" >&2
        echo "      are current and the bake continues (#1029). A floating base tag" >&2
        echo "      rebuilt upstream is the one drift this cannot see — 'make build'" >&2
        echo "      with --pull if you want to be sure:" >&2
        for a in "${aged[@]}"; do echo "        $a" >&2; done
    fi
    if [ "${#stale[@]}" -gt 0 ]; then
        echo "ERROR: stale local source image(s) — built before their own sources:" >&2
        for s in "${stale[@]}"; do echo "         $s" >&2; done
        echo "       Rebuild with 'make build' (+ 'make build-supervisor'), or bake them" >&2
        echo "       as-is with --allow-stale-images (or ALLOW_STALE_IMAGES=1)." >&2
        exit 4
    fi
fi

# ``BAKE_SAVE_PLATFORM`` (optional, e.g. ``linux/amd64``): passed as
# ``docker save --platform``. Required on a Docker host that uses the
# containerd image store (Docker Desktop on Apple Silicon): a registry
# image's index there lists platforms whose blobs were never pulled, and a
# plain ``docker save`` fails with "content digest … not found". Also
# guarantees the archive carries the appliance's architecture rather than
# the build host's. Empty (the CI default) keeps the historical behaviour.
SAVE_PLATFORM_FLAG=()
if [ -n "${BAKE_SAVE_PLATFORM:-}" ]; then
    SAVE_PLATFORM_FLAG=(--platform "$BAKE_SAVE_PLATFORM")
fi

for repo in "${IMAGES[@]}"; do
    short="$(basename "$repo")"
    source_tag="$(resolve_source_tag "$repo")"
    target_tag="${repo}:${SPATIUMDDI_VERSION}"
    out_tar="$IMAGES_DIR/${short}.tar.zst"

    if [ "$BAKE_SOURCE" = "ghcr" ]; then
        echo "→ Pulling $source_tag …"
        docker pull "$source_tag" >/dev/null
    elif ! docker image inspect "$source_tag" >/dev/null 2>&1; then
        echo "ERROR: no local image found for $repo. Tried:" >&2
        echo "         ${repo}:dev" >&2
        echo "         spatiumddi-${short}:dev" >&2
        echo "         ${short}:dev" >&2
        echo "       Run 'make build' (control plane :dev images)" >&2
        echo "       and 'make build-supervisor' (supervisor :dev) first." >&2
        exit 3
    fi

    # Retag so containerd registers the image under the chart's
    # expected ghcr name. ``docker save`` writes whatever RepoTags
    # the image has at save time; without this step, the archive
    # would carry ``<short>:dev`` (local) — chart references
    # ``ghcr.io/spatiumnorth/<short>:${SPATIUMDDI_VERSION}`` and the
    # kubelet would say ``ErrImagePull``.
    docker tag "$source_tag" "$target_tag"

    echo "→ Baking $target_tag → $out_tar"
    # docker save | zstd → containerd-readable archive. Atomic via
    # .new sibling so a crash mid-bake doesn't ship a torn tarball.
    tmp="${out_tar}.new"
    # A bake that died mid-save leaves ``.new`` behind, and zstd refuses to
    # overwrite it — which made every later bake fail on the same file.
    rm -f "$tmp"
    docker save "${SAVE_PLATFORM_FLAG[@]}" "$target_tag" | zstd -T0 -19 -o "$tmp"
    mv "$tmp" "$out_tar"

    size="$(du -h "$out_tar" | awk '{print $1}')"
    echo "  ✓ $size"
done

# Issue #183 Phase 8 — 3rd-party observability images. Pull + save
# at upstream tags; no retag, no SPATIUMDDI_VERSION involvement.
# Operator opts in via ``observability.kubeStateMetrics.enabled`` /
# ``observability.nodeExporter.enabled`` in the chart's values.yaml;
# the bake always ships them so the toggle works air-gap.
#
# Slugged output filenames so two images from the same registry
# path prefix don't collide. ``kube-state-metrics`` + ``node-exporter``
# are distinct enough that ``basename`` works.
for image in "${OBSERVABILITY_IMAGES[@]}" "${METALLB_IMAGES[@]}" "${CNPG_IMAGES[@]}"; do
    short="$(basename "${image%%:*}")"
    out_tar="$IMAGES_DIR/${short}.tar.zst"

    # With a save platform pinned, always pull for that platform: a local
    # copy pulled for the build host's own arch (a dev-compose ``redis``
    # on an arm64 laptop) satisfies ``image inspect`` but cannot be saved
    # as the appliance's arch.
    if [ -n "${BAKE_SAVE_PLATFORM:-}" ]; then
        docker pull --platform "$BAKE_SAVE_PLATFORM" "$image" >/dev/null
    elif ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "→ Pulling $image …"
        docker pull "$image" >/dev/null
    fi

    echo "→ Baking $image → $out_tar"
    tmp="${out_tar}.new"
    # A bake that died mid-save leaves ``.new`` behind, and zstd refuses to
    # overwrite it — which made every later bake fail on the same file.
    rm -f "$tmp"
    docker save "${SAVE_PLATFORM_FLAG[@]}" "$image" | zstd -T0 -19 -o "$tmp"
    mv "$tmp" "$out_tar"

    size="$(du -h "$out_tar" | awk '{print $1}')"
    echo "  ✓ $size"
done

# Prune stale image archives that this bake no longer produces (#277).
# bake-images.sh appends but never cleaned, so an image dropped from the
# lists above (e.g. the standalone ``postgres:16-alpine`` once the
# appliance went CNPG-only) left its ~100 MB ``.tar.zst`` behind to be
# baked into the ISO forever as dead weight. Compute the expected
# basenames from every list, then remove any other ``*.tar.zst`` — but
# NEVER the externally-fetched k3s airgap bundle (produced by
# ``appliance-fetch-k3s``, not this script). That bundle is arch-tagged
# (``k3s-airgap-images-<arch>.tar.zst``), so match it by glob rather than
# a hardcoded ``-amd64`` — hardcoding would prune the arm64 bundle on a
# multi-arch build and break the ISO.
expected=()
for repo in "${IMAGES[@]}" "${OBSERVABILITY_IMAGES[@]}" "${METALLB_IMAGES[@]}" "${CNPG_IMAGES[@]}"; do
    expected+=("$(basename "${repo%%:*}").tar.zst")
done
for f in "$IMAGES_DIR"/*.tar.zst; do
    [ -e "$f" ] || continue
    base="$(basename "$f")"
    # Keep the k3s airgap bundle for any arch (amd64 / arm64).
    case "$base" in
        k3s-airgap-images-*.tar.zst) continue ;;
    esac
    keep=false
    for e in "${expected[@]}"; do
        [ "$base" = "$e" ] && { keep=true; break; }
    done
    if [ "$keep" = false ]; then
        echo "→ Pruning stale baked image (no longer in the bake list): $base"
        rm -f "$f"
    fi
done

# Total AFTER the prune so the reported size matches what's actually baked.
TOTAL="$(du -hc "$IMAGES_DIR"/*.tar.zst 2>/dev/null | tail -1 | awk '{print $1}')"
TOTAL_COUNT=$((${#IMAGES[@]} + ${#OBSERVABILITY_IMAGES[@]} + ${#METALLB_IMAGES[@]} + ${#CNPG_IMAGES[@]}))
echo "✓ ${TOTAL_COUNT} images baked into $IMAGES_DIR ($TOTAL)"
echo "  k3s auto-imports these at startup (no firstboot shell-out required)"
