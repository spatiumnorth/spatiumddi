#!/usr/bin/env bash
# Prune heavy appliance release assets with version-aware retention (#392).
#
# Every appliance release attaches ~4.6 GB of large binaries (a versioned
# + a generic-named ISO, and a versioned + a generic-named slot .raw.xz,
# plus tiny .sha256 sidecars). Nothing prunes them, so the Releases page
# grows ~4.6 GB per cut. This script trims that in two tiers:
#
#   Tier 1 — on every NON-latest release, delete the generic-named
#            duplicate assets:
#              spatiumddi-appliance-amd64.iso
#              spatiumddi-appliance-slot-amd64.raw.xz
#              spatiumddi-appliance-slot-amd64.sha256
#            They exist only to back the stable
#            releases/latest/download/<name> URLs, which always resolve to
#            the newest release — so on any older release they are pure
#            duplication of the versioned copies. Safe to drop everywhere
#            except the current latest.
#
#   Tier 2 — beyond the keep window (the KEEP_VERSIONED newest releases),
#            also delete the heavy VERSIONED binaries:
#              spatiumddi-appliance-<tag>.iso
#              spatiumddi-appliance-slot-<tag>-amd64.raw.xz
#            The versioned slot .sha256 provenance sidecar, the release,
#            the tag, and the notes are ALWAYS kept — provenance is tiny
#            and the binary can be rebuilt from the tag if ever needed.
#
# Pre-releases (SemVer release candidates, 1.0.0-rc.N — #1182, #1226) do
# NOT take keep-window slots: cutting eight candidates before a release
# would otherwise push eight final releases out of the window early, and
# operators pinned to those lose their install media. A pre-release keeps
# its heavy assets until a final release is published after it, and loses
# them then — a candidate the release has superseded is not something to
# install.
#
# Also drops the stray mkosi-ImageVersion-named slot sha (e.g.
# spatiumddi-appliance-slot-0.1.0.sha256) from every release — a
# historical artefact of the pre-#392 release workflow (now fixed at
# source in release.yml, but old releases still carry it).
#
# Version-aware honesty: the appliance OS-upgrade picker
# (backend releases_service._pick_upgrade_assets) only offers a release
# that still has BOTH a slot .raw.xz AND its .sha256. A Tier-2-pruned
# release keeps only the .sha256, so _pick_upgrade_assets returns None and
# the release auto-drops out of the picker — "Apply" never offers a dead
# link. Keep KEEP_VERSIONED wide enough to cover the window of releases you
# want operators to be able to pin / roll back / air-gap to.
#
# Deletes ASSETS only — never the release, tag, or notes.
#
# Env:
#   REPO            owner/repo (default: $GITHUB_REPOSITORY)
#   KEEP_VERSIONED  newest releases to keep versioned heavy assets on
#                   (default: 15)
#   DRY_RUN         "true" => log only, delete nothing (default: false)
#   GH_TOKEN        token with contents:write (delete-asset)
set -euo pipefail

REPO="${REPO:-${GITHUB_REPOSITORY:?REPO or GITHUB_REPOSITORY required}}"
KEEP_VERSIONED="${KEEP_VERSIONED:-15}"
DRY_RUN="${DRY_RUN:-false}"
# The just-cut tag, passed by release.yml's post-release prune step. Its
# generic /latest/-backing assets are never pruned even if GitHub hasn't
# propagated isLatest=true to it yet (the release-time race). Empty on the
# scheduled run, which correctly keys "latest" off GitHub's isLatest.
PROTECT_TAG="${PROTECT_TAG:-}"

if ! [[ "$KEEP_VERSIONED" =~ ^[0-9]+$ ]] || [ "$KEEP_VERSIONED" -lt 1 ]; then
    echo "ERROR: KEEP_VERSIONED must be a positive integer, got '${KEEP_VERSIONED}'" >&2
    exit 2
fi

echo "→ Prune release assets on ${REPO}"
echo "  keep newest ${KEEP_VERSIONED} releases' versioned heavy assets; dry_run=${DRY_RUN}"

# Newest-first list of releases. ``--exclude-drafts``: drafts have no public
# /latest/ URLs and must NOT consume keep-window index slots — a lingering
# draft would shift a real release a slot earlier into the prune window.
# ``isLatest`` marks the single release the /latest/ URLs resolve to (GitHub
# computes it; not necessarily index 0 if a prerelease was cut afterwards).
# Limit 1000 covers all foreseeable history. Capture into a var with an
# explicit rc check so a gh auth/network/rate-limit failure FAILS LOUD
# instead of looking like "no releases" (which would silently skip pruning).
# TSV: "<tag>\t<isLatest>\t<isPrerelease>".
if ! releases_tsv=$(
    gh release list --repo "$REPO" --limit 1000 --exclude-drafts \
        --json tagName,isLatest,isPrerelease,createdAt \
        -q 'sort_by(.createdAt) | reverse | .[] | [.tagName, (.isLatest|tostring), (.isPrerelease|tostring)] | @tsv'
); then
    echo "ERROR: 'gh release list' failed (auth / network / rate-limit?)" >&2
    exit 1
fi
if [ -z "$releases_tsv" ]; then
    echo "  no releases found — nothing to do"
    exit 0
fi
mapfile -t RELEASES <<<"$releases_tsv"

deleted=0
kept_releases=0

del() {
    # del <tag> <asset-name>
    local tag="$1" asset="$2"
    if [ "$DRY_RUN" = "true" ]; then
        echo "    [dry-run] would delete ${tag} :: ${asset}"
        deleted=$((deleted + 1))
        return
    fi
    if gh release delete-asset --repo "$REPO" "$tag" "$asset" --yes 2>/dev/null; then
        echo "    deleted ${tag} :: ${asset}"
        deleted=$((deleted + 1))
    else
        echo "    WARN: could not delete ${tag} :: ${asset} (already gone?)" >&2
    fi
}

idx=0
# Set once the newest-first walk has passed a final release: every
# pre-release after that point has been superseded by it.
seen_final="false"
# #1026 — every architecture the release pipeline publishes appliance
# assets for. Keep in lock-step with the ``arch`` matrix in release.yml:
# an architecture built there and missing here is one whose heavy assets
# are never reclaimed.
APPLIANCE_ARCHES=(amd64 arm64)

# Exact-match membership. A ``case`` glob cannot express "one of these
# N names" without either a generated pattern or a fallthrough that
# also swallows names it should not.
_in_list() {
    local needle="$1"; shift
    local x
    for x in "$@"; do
        [ "$x" = "$needle" ] && return 0
    done
    return 1
}

for line in "${RELEASES[@]}"; do
    IFS=$'\t' read -r tag is_latest is_prerelease <<<"$line"

    # Nightly pre-releases are NOT this sweep's problem: nightly.yml's own
    # prune-releases job deletes the whole release (assets, tag and all)
    # after 7 days. They must also not consume keep-window index slots —
    # up to 7 of them sit newest-first at any time, and counting them
    # would silently shrink the real releases' asset window from
    # KEEP_VERSIONED to KEEP_VERSIONED-7.
    case "$tag" in
        nightly | nightly-*)
            echo "  [--] ${tag} — nightly pre-release: skipped (nightly.yml owns its retention)"
            continue
            ;;
    esac

    # release-time race guard: the freshly-published tag IS (about to be)
    # latest; treat it as latest regardless of isLatest propagation lag so
    # its generic /latest/-backing assets are never Tier-1 pruned.
    if [ -n "$PROTECT_TAG" ] && [ "$tag" = "$PROTECT_TAG" ]; then
        is_latest="true"
    fi

    # Per-tag asset name conventions (must match release.yml's wrap-iso +
    # build-slot-image steps).
    #
    # #1026 — ONE SET PER ARCHITECTURE, and the two are treated as a pair
    # rather than one being the real release and the other an oddity. The
    # ``*)`` fallthrough below leaves unrecognised assets alone, which is
    # the right default for a genuinely new artifact and exactly wrong
    # here: an unlisted arm64 ISO is not "future", it is a 1.6 GB binary
    # per release that nothing ever removes, on a repo whose whole reason
    # for having a pruner is that those add up.
    GENERIC=()
    VER_HEAVY=()
    VER_SHA=()
    for _a in "${APPLIANCE_ARCHES[@]}"; do
        GENERIC+=("spatiumddi-appliance-${_a}.iso"
                  "spatiumddi-appliance-slot-${_a}.raw.xz"
                  "spatiumddi-appliance-slot-${_a}.sha256")
        VER_HEAVY+=("spatiumddi-appliance-${tag}-${_a}.iso"
                    "spatiumddi-appliance-slot-${tag}-${_a}.raw.xz")
        VER_SHA+=("spatiumddi-appliance-slot-${tag}-${_a}.sha256")
    done
    # Pre-#1026 releases carry an ISO with no architecture in the name.
    # Still prunable on the same terms — dropping it from the list would
    # silently stop reclaiming every ISO cut before this change.
    VER_HEAVY+=("spatiumddi-appliance-${tag}.iso")

    beyond_window="false"
    if [ "$is_prerelease" = "true" ]; then
        # Not counted against the window; superseded once a final release
        # was published after it.
        beyond_window="$seen_final"
    elif [ "$idx" -ge "$KEEP_VERSIONED" ]; then
        beyond_window="true"
    fi

    mapfile -t ASSETS < <(
        gh release view "$tag" --repo "$REPO" --json assets \
            -q '.assets[].name' 2>/dev/null || true
    )

    if [ "$is_latest" = "true" ]; then
        echo "  [${idx}] ${tag} — LATEST: keeping full asset set"
    elif [ "$is_prerelease" = "true" ]; then
        if [ "$beyond_window" = "true" ]; then
            echo "  [--] ${tag} — pre-release superseded by a final release: dropping generic + versioned heavy assets"
        else
            echo "  [--] ${tag} — pre-release newer than every final release: dropping generic dupes only"
        fi
    elif [ "$beyond_window" = "true" ]; then
        echo "  [${idx}] ${tag} — beyond keep window: dropping generic + versioned heavy assets"
    else
        echo "  [${idx}] ${tag} — within window: dropping generic dupes only"
    fi

    for a in "${ASSETS[@]}"; do
        if _in_list "$a" "${VER_SHA[@]}"; then
            : # always keep the versioned provenance sidecar
        elif _in_list "$a" "${GENERIC[@]}"; then
            # Tier 1 — generic dupes are dead weight on any non-latest.
            [ "$is_latest" = "true" ] || del "$tag" "$a"
        elif _in_list "$a" "${VER_HEAVY[@]}"; then
            # Tier 2 — heavy versioned binaries beyond the keep window.
            if [ "$beyond_window" = "true" ] && [ "$is_latest" != "true" ]; then
                del "$tag" "$a"
            fi
        else
            case "$a" in
                spatiumddi-appliance-slot-*.sha256)
                    # Stray mkosi-ImageVersion sha (e.g. …-slot-0.1.0.sha256)
                    # — neither versioned nor generic. Junk on every release.
                    #
                    # Ordered AFTER the versioned-sha check above, not
                    # before: this glob also matches every real
                    # ``…-slot-<tag>-<arch>.sha256``, so reaching it first
                    # would delete the provenance sidecar the line above
                    # exists to protect.
                    del "$tag" "$a"
                    ;;
                *)
                    : # unknown / future asset — leave untouched
                    ;;
            esac
        fi
    done

    if [ "$is_prerelease" != "true" ]; then
        idx=$((idx + 1))
        seen_final="true"
    fi
done

kept_releases="${#RELEASES[@]}"
echo "→ Done. Scanned ${kept_releases} releases; ${deleted} assets $([ "$DRY_RUN" = "true" ] && echo 'would be ' )pruned. All releases, tags, notes, and versioned .sha256 sidecars retained."
