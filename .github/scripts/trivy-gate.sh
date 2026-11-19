#!/usr/bin/env bash
# trivy-gate.sh — turn a Trivy image report into a publish/refuse verdict.
#
#   usage: .github/scripts/trivy-gate.sh <trivy-report.json> <image-ref>
#
# The report is what `trivy image --format json` wrote for <image-ref>,
# scanned with `--severity HIGH,CRITICAL --ignore-unfixed` — so every
# finding in it is one Trivy believes has a fix. This script asks the
# one question Trivy cannot: is that fix INSTALLABLE from the package
# index the image builds against, right now?
#
# Trivy's "fixed" comes from the distro's security database. Alpine's
# secdb is updated when the fix is COMMITTED to aports; the built .apk
# reaches dl-cdn hours later (the builders and the CDN sync are separate
# steps). In that window a finding is "fixed" to Trivy and unfixable to
# `apk upgrade` — no Dockerfile change can clear it, and a gate that
# fails on it just blocks the nightly until the mirrors catch up.
# nightly-20260905 died exactly this way: util-linux 2.42.3 landed in
# aports at 00:08Z, the frontend image's fresh `apk upgrade` at 10:45Z
# picked up every other fix on the mirror but libuuid stayed at
# 2.42.1-r0 (7 HIGH), and the package appeared on the CDN at 13:53Z.
#
# Each finding is sorted into one of three outcomes:
#
#   FAIL   the index offers a version >= the fixed one. A rebuild would
#          cure this (stale layer cache, missing `apk upgrade`, a floor
#          that needs bumping) — the image must not ship. Exit 1.
#   DEFER  the index offers nothing newer, or something newer that is
#          still below the fixed version. Announced, not published.
#          Nothing a rebuild can do until the mirrors catch up, so it
#          is treated the way `--ignore-unfixed` already treats the
#          rest: reported (a workflow warning + step summary), not
#          blocking. The next build — whose package layer is rebuilt
#          against the current index — picks the fix up. Exit 0.
#   FAIL   the image's package manager is not one this script can ask
#          (apk and apt today), the probe itself failed, or the finding
#          is a language package (a new PyPI/npm release is always
#          installable). Availability is unknown, so the outcome is what
#          it was before this script existed: refuse. Exit 1.
#
# Debian/Ubuntu images are asked the same question a different way, and
# two details there are load-bearing:
#
#   Silence means the OPPOSITE thing to the two probes. apk's
#   `--simulate` reports only what it WOULD upgrade, so a package missing
#   from its output means "nothing newer exists"; `apt-cache policy`
#   answers for every package it is asked about, so a package missing
#   from ITS output means the index could not resolve the name at all —
#   unknown availability, which is a FAIL, not a DEFER. Reading the
#   second like the first turns a fail-closed branch into a fail-open one.
#
#   The probe has to prove the index was LOADED, not merely that
#   `apt-get update` returned. It returns 0 with every mirror
#   unreachable, and `apt-cache policy` then answers from the local dpkg
#   status file — Candidate == installed, which is non-empty, plausible,
#   and reads as "the fix is not published yet" for every finding at
#   once. See the probe for what is asserted instead.
#
# A missing, empty or unparsable report is a hard failure: an image
# nothing scanned is never a pass.
#
# Requires jq and docker (the image must be present locally, and the probe
# needs network access to the distro's mirrors). If trivy is
# on PATH the familiar table is printed first (`trivy convert`); otherwise
# a compact one is rendered from the JSON.
set -euo pipefail

usage() {
  echo "usage: $0 <trivy-report.json> <image-ref>" >&2
  exit 2
}
[ $# -eq 2 ] || usage
report=$1
image=$2

fail() {
  echo "::error::$*"
  exit 1
}

[ -s "$report" ] \
  || fail "trivy report '$report' is missing or empty — refusing to pass an unscanned image"
jq -e . "$report" >/dev/null 2>&1 \
  || fail "trivy report '$report' is not valid JSON"

# ── The report, for humans ──────────────────────────────────────────────
if command -v trivy >/dev/null 2>&1; then
  trivy convert --quiet --format table "$report" || true
else
  jq -r '
    .Results[]? as $r
    | ($r.Vulnerabilities // [])[]
    | "\($r.Target)\t\(.PkgName)\t\(.VulnerabilityID)\t\(.Severity)\t\(.InstalledVersion) -> \(.FixedVersion // "-")"
  ' "$report" | column -t -s $'\t' || true
fi
echo

# ── Findings: class, pkg, installed, fixed, id, severity ────────────────
# FixedVersion can list several versions ("1.2-r0, 1.3-r0"); the first
# is the lowest one that clears the CVE, which is the one to test for.
# An absent one is emitted as "-" — `read` collapses adjacent tabs, so an
# empty field would shift every column after it.
findings=$(jq -r '
  .Results[]? as $r
  | ($r.Vulnerabilities // [])[]
  | [ $r.Class, .PkgName, .InstalledVersion,
      ((.FixedVersion // "") | split(",") | (.[0] // "") | gsub("^\\s+|\\s+$"; "")
        | if . == "" then "-" else . end),
      .VulnerabilityID, .Severity ]
  | @tsv' "$report")

os_family=$(jq -r '.Metadata.OS.Family // ""' "$report")
os_name=$(jq -r '.Metadata.OS.Name // ""' "$report")

echo "── trivy-gate: ${image} (${os_family:-unknown os} ${os_name})"
if [ -z "$findings" ]; then
  echo "✓ no HIGH/CRITICAL findings with a fix"
  exit 0
fi

# ── What can the image's own package index install today? ──────────────
# Kept as "pkg<TAB>version" lines (no bash-4 associative arrays, so this
# also runs under macOS's bash 3). `--user 0` throughout because runtime
# images drop privileges and neither package manager resolves as non-root.
available=""
upgradable=""
probe_ok=0

case "$os_family" in
  alpine)
    # One `apk upgrade --simulate` against the live index yields, for
    # every upgradable package, the version `apk upgrade` WOULD install —
    # the exact thing the Dockerfile's `apk upgrade` line can reach.
    # `--no-cache` fetches a fresh index.
    if sim=$(docker run --rm --user 0 --entrypoint sh "$image" \
               -c 'apk upgrade --simulate --no-cache 2>/dev/null'); then
      probe_ok=1
      available=$(printf '%s\n' "$sim" \
        | sed -nE 's/^\([0-9]+\/[0-9]+\) Upgrading ([^ ]+) \(([^ ]+) -> ([^)]+)\)$/\1\t\3/p')
    else
      echo "::warning::could not run 'apk upgrade --simulate' in ${image}; availability unknown"
    fi
    ;;
  debian | ubuntu)
    # Two answers, because they are different questions and the gap
    # between them is a real state:
    #
    #   `apt-cache policy` CANDIDATE — the newest version the index can
    #     install at all. This is availability, and so the FAIL/DEFER
    #     decision.
    #   `apt-get -s upgrade` — what plain `apt-get upgrade`, the line the
    #     shipped Dockerfiles actually run, would install. apt holds a
    #     package back when upgrading it would pull in a new dependency
    #     or remove something, so this can be lower than the candidate.
    #
    # Deciding on the candidate alone (the first cut) makes a held-back
    # fix a FAIL whose stated remedy — rebuild the package layer — does
    # nothing, i.e. a permanently red nightly with a wrong instruction.
    # Deciding on the simulate alone makes it a DEFER that never clears,
    # on a fix an explicit install could have taken today. So the verdict
    # comes from the candidate and the REASON from both.
    #
    # Only the packages actually flagged are asked about, so the probe
    # stays one docker run regardless of image size. Shipped Dockerfiles
    # end with `rm -rf /var/lib/apt/lists/*`, hence the `apt-get update`.
    #
    # Names are filtered to Debian's own policy character class before
    # being interpolated into the shell command. A name outside it is not
    # sanitised, it is DROPPED — so it is then absent from `available`
    # and the loop below fails it as unverifiable, which is the direction
    # that cannot publish something on the strength of an unparsed name.
    pkgs=$(printf '%s\n' "$findings" \
      | awk -F '\t' '$1 == "os-pkgs" && $2 ~ /^[a-z0-9][a-z0-9+.-]*$/ { print $2 }' \
      | sort -u | tr '\n' ' ')
    if [ -z "$pkgs" ]; then
      # Nothing to ask about: every finding is a language package, which
      # the verdict loop answers without the index. Probing anyway would
      # emit a warning naming apt as the problem when apt is not involved.
      probe_ok=1
    elif pol=$(docker run --rm --user 0 --entrypoint sh "$image" -c "
           # THE PROBE MUST FAIL CLOSED, and neither obvious spelling of
           # that does. \`apt-get update\` exits 0 when every mirror is
           # unreachable (verified: --network none on debian:13-slim,
           # rc=0, empty lists) — and \`apt-cache policy\` then answers
           # from /var/lib/dpkg/status, reporting Candidate == INSTALLED.
           # That is non-empty and plausible, so every finding would
           # compare below its fix and DEFER: an offline runner would
           # publish an image on CRITICALs whose fixes were on the
           # mirrors the whole time. Error-Mode=any turns a fetch failure
           # into a non-zero exit, and the grep then proves an index was
           # actually LOADED — with none, the only package file listed is
           # the local dpkg status.
           apt-get update -qq -o APT::Update::Error-Mode=any >/dev/null 2>&1 || exit 1
           apt-cache policy 2>/dev/null \
             | grep -qE '^ *[0-9]+ (https?|ftp|file|cdrom):' || exit 1
           echo '@@SIMULATE@@'
           apt-get -s upgrade 2>/dev/null
           echo '@@POLICY@@'
           apt-cache policy ${pkgs} 2>/dev/null"); then
      probe_ok=1
      # "Inst <pkg> [<installed>] (<new> <origin> [<arch>])"
      upgradable=$(printf '%s\n' "$pol" \
        | sed -n '/^@@SIMULATE@@$/,/^@@POLICY@@$/p' \
        | sed -nE 's/^Inst ([^ ]+) \[[^]]*\] \(([^ ]+) .*/\1\t\2/p')
      # "pkgname:" at column 0, then an indented "Candidate: <version>".
      # A package apt cannot resolve produces neither, so it is absent
      # from `available` and the loop below fails it as unverifiable.
      available=$(printf '%s\n' "$pol" | sed -n '/^@@POLICY@@$/,$p' | awk '
        /^[^[:space:]]/          { pkg = $1; sub(/:$/, "", pkg); next }
        /^[[:space:]]+Candidate:/ { if (pkg != "" && $2 != "(none)") print pkg "\t" $2; pkg = "" }')
    else
      echo "::warning::could not query the apt index in ${image}; availability unknown"
    fi
    ;;
  redhat | centos | rocky | almalinux)
    # #3913 — the Red Hat UBI variants. ``microdnf repoquery --available``
    # lists what the image's own repositories (the UBI ones) can install, as
    # ``name-[epoch:]version-release.arch``. Red Hat publishes an advisory and
    # its packages together, so a gap between the two is rare, but the same
    # rule applies as for apk and apt: a fix the index offers is a FAIL (a
    # rebuild cures it), one it does not yet offer is a DEFER.
    #
    # Fails closed like the others: ``--refresh`` forces a metadata fetch, and
    # an offline probe exits non-zero (an empty answer would otherwise read as
    # "nothing newer, so DEFER" for every finding at once). Names are filtered
    # to rpm's own character class before they reach the shell; a name outside
    # it is dropped and then fails as unverifiable, never published.
    pkgs=$(printf '%s\n' "$findings" \
      | awk -F '\t' '$1 == "os-pkgs" && $2 ~ /^[A-Za-z0-9][A-Za-z0-9+._-]*$/ { print $2 }' \
      | sort -u | tr '\n' ' ')
    if [ -z "$pkgs" ]; then
      probe_ok=1
    elif pol=$(docker run --rm --user 0 --entrypoint sh "$image" -c "
           microdnf repoquery --refresh --available ${pkgs} 2>/dev/null"); then
      if [ -n "$pol" ]; then
        probe_ok=1
        # name-[E:]V-R.arch -> "name<TAB>E:V-R", epoch spelled out (0 when
        # absent) so one comparator handles every row; the newest per name wins.
        available=$(printf '%s\n' "$pol" | sed -nE '
          s/\.(x86_64|aarch64|noarch|i686|ppc64le|s390x)$//
          s/^(.+)-(([0-9]+):)?([^-]+)-([^-]+)$/\1\t\3\t\4-\5/p' \
          | awk -F '\t' '{ e = ($2 == "" ? "0" : $2); print $1 "\t" e ":" $3 }' \
          | sort -t "$(printf '\t')" -k1,1 -k2,2V | awk -F '\t' '{ last[$1] = $2 } END { for (p in last) print p "\t" last[p] }')
      else
        echo "::warning::'microdnf repoquery' printed nothing in ${image}; availability unknown"
      fi
    else
      echo "::warning::could not query the rpm index in ${image}; availability unknown"
    fi
    ;;
  *)
    echo "::warning::no package-index probe for '${os_family:-unknown}'; availability unknown"
    ;;
esac

# Newest version the index can install for $1, empty if it offered none.
offered_for() {
  printf '%s\n' "$available" | awk -F '\t' -v p="$1" '$1 == p { print $2; exit }'
}

# Version a plain upgrade would install for $1 — apt only, and empty when
# apt would hold the package back. The apk probe is already a simulated
# upgrade, so there is nothing to hold back there and this stays empty.
upgrade_offers() {
  printf '%s\n' "$upgradable" | awk -F '\t' -v p="$1" '$1 == p { print $2; exit }'
}

# The distro's OWN comparator, so "-r1 vs -r0", "+deb13u2", "~deb13u1",
# "_p1" and friends are judged the way the package manager judges them.
# Prints one of < = > per line of "A B" on stdin.
version_compare() {
  case "$os_family" in
    alpine)
      docker run --rm -i --user 0 --entrypoint sh "$image" -c '
        while read -r a b; do apk version -t "$a" "$b"; done'
      ;;
    debian | ubuntu)
      docker run --rm -i --user 0 --entrypoint sh "$image" -c '
        while read -r a b; do
          if dpkg --compare-versions "$a" gt "$b"; then echo ">"
          elif dpkg --compare-versions "$a" eq "$b"; then echo "="
          else echo "<"; fi
        done'
      ;;
    redhat | centos | rocky | almalinux)
      # rpm's own vercmp (a Lua function in ``rpm --eval``). It compares plain
      # version strings, so both sides carry an explicit epoch first: a fixed
      # version Trivy prints without one means epoch 0.
      docker run --rm -i --user 0 --entrypoint sh "$image" -c '
        norm() { case "$1" in *:*) printf "%s" "$1" ;; *) printf "0:%s" "$1" ;; esac; }
        while read -r a b; do
          a=$(norm "$a"); b=$(norm "$b")
          case $(rpm --eval "%{lua:print(rpm.vercmp(\"$a\", \"$b\"))}") in
            1) echo ">" ;; 0) echo "=" ;; *) echo "<" ;;
          esac
        done'
      ;;
  esac
}

fails=0
defers=0
summary=()
while IFS=$'\t' read -r class pkg installed fixed id sev; do
  [ -n "$pkg" ] || continue
  [ "$fixed" != "-" ] || fixed=""
  where="${pkg} ${id} (${sev}): installed ${installed}, fixed ${fixed:-?}"
  verdict=""
  reason=""
  if [ "$class" != "os-pkgs" ]; then
    verdict=FAIL
    reason="language package — a newer release is always installable; update the pin"
  elif [ "$probe_ok" -ne 1 ]; then
    verdict=FAIL
    reason="could not query the ${os_family:-unknown} package index; treating as installable"
  elif [ -z "$fixed" ]; then
    # Should not happen under --ignore-unfixed; if it does, the finding
    # is unfixed and the scan policy already says those do not block.
    verdict=DEFER
    reason="no fixed version known"
  elif offered=$(offered_for "$pkg") && [ -z "$offered" ]; then
    # Silence means different things to the two probes — see the header.
    if [ "$os_family" = "alpine" ]; then
      verdict=DEFER
      reason="the index offers nothing newer than ${installed} — fix announced, not yet published"
    else
      verdict=FAIL
      reason="the index does not list ${pkg}; treating as installable"
    fi
  else
    cmp=$(printf '%s %s\n' "$offered" "$fixed" | version_compare) || cmp=""
    case "$cmp" in
      '>' | '=')
        verdict=FAIL
        # Distinguish "a rebuild takes this" from "a rebuild cannot": on
        # apt a fix needing a new dependency is held back by plain
        # `apt-get upgrade` forever, and telling the operator to rebuild
        # would be an instruction that provably does nothing.
        reason="the index offers ${offered} — rebuild the package layer"
        if [ "$os_family" = "debian" ] || [ "$os_family" = "ubuntu" ]; then
          by_upgrade=$(upgrade_offers "$pkg")
          held=yes
          if [ -n "$by_upgrade" ]; then
            cmp_up=$(printf '%s %s\n' "$by_upgrade" "$fixed" | version_compare) || cmp_up=""
            case "$cmp_up" in
              '>' | '=') held=no ;;
            esac
          fi
          if [ "$held" = yes ]; then
            reason="the index offers ${offered} but \`apt-get upgrade\` holds ${pkg} back${by_upgrade:+ at ${by_upgrade}} — needs an explicit install or dist-upgrade, not a rebuild"
          fi
        fi
        ;;
      '<')
        verdict=DEFER
        reason="the index offers ${offered}, still below the fix — announced, not yet published"
        ;;
      *)
        verdict=FAIL
        reason="could not compare ${offered} with ${fixed} (got '${cmp}'); treating as installable"
        ;;
    esac
  fi

  case "$verdict" in
    FAIL)
      fails=$((fails + 1))
      echo "✗ FAIL  ${where} — ${reason}"
      echo "::error title=${image} ${id}::${where} — ${reason}"
      ;;
    DEFER)
      defers=$((defers + 1))
      echo "⏳ DEFER ${where} — ${reason}"
      echo "::warning title=${image} ${id} deferred::${where} — ${reason}"
      ;;
  esac
  summary+=("| ${verdict} | \`${pkg}\` | ${id} | ${sev} | ${installed} | ${fixed:-?} | ${reason} |")
done <<< "$findings"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Trivy gate — \`${image}\`"
    echo
    echo "| Verdict | Package | CVE | Severity | Installed | Fixed | Why |"
    echo "|---|---|---|---|---|---|---|"
    printf '%s\n' "${summary[@]}"
    echo
    echo "FAIL blocks the push. DEFER = the fix is in the distro's security database but not yet on the package mirrors; it is reported like an unfixed finding and picked up by the next build."
  } >> "$GITHUB_STEP_SUMMARY"
fi

echo
if [ "$fails" -gt 0 ]; then
  echo "✗ ${fails} finding(s) have an installable fix — refusing to publish ${image}"
  exit 1
fi
echo "✓ ${image}: ${defers} finding(s) deferred (fix announced, not yet on the mirrors); nothing a rebuild could cure"
exit 0
