#!/usr/bin/env bash
# trivy-scan.sh — build each shipped image and scan it with Trivy (`make trivy`).
#
#   usage: scripts/trivy-scan.sh <dockerfile:context:name>...
#
#   IMAGE=<name>       scan only that image (it must be one of the specs)
#   TRIVY_CACHE=<dir>  vulnerability-DB cache, mounted into the scanner
#   TRIVY_LOG_DIR=<d>  where each image's build and scan logs go (default /tmp)
#
# Each image ends in exactly one of four outcomes, and only two of them are
# verdicts about the image:
#
#   clean          Trivy ran and exited 0.
#   FINDINGS       Trivy exited 1 AND its report lists a finding.
#   SCAN FAILED    anything else: Docker could not run the scanner (125 — a
#                  refused mount, a pull failure, the daemon down), or Trivy
#                  exited 1 with no finding in the report, which is how it
#                  reports its own errors (a DB download failure is exit 1).
#   BUILD FAILED   the image never built, so there was nothing to scan.
#
# This used to treat every non-zero exit as FINDINGS (#1272), so a refused
# cache mount printed "✗ Trivy found HIGH/CRITICAL vulnerabilities" with no
# finding under it, for images that scanned clean. A check whose failure looks
# like a verdict teaches people to skip it, and the next real finding goes
# with it. The two failure outcomes print the tail of their log instead.
#
# Exit status: 0 all clean, 1 at least one image has findings, 2 no findings
# but at least one image could not be verified (including an IMAGE= that
# matched nothing — scanning nothing is not "clean").

set -uo pipefail

only="${IMAGE:-}"
cache="${TRIVY_CACHE:?TRIVY_CACHE must be set}"
logdir="${TRIVY_LOG_DIR:-/tmp}"

if ! mkdir -p "$cache" "$logdir"; then
  echo "✗ cannot create the Trivy cache ($cache) or log dir ($logdir)." >&2
  exit 2
fi

# Trivy's table report: a "Total: N (HIGH: …, CRITICAL: …)" line per scanned
# target, where targets with nothing to report say "Total: 0". A finding is a
# non-zero total or an advisory id in the table.
has_findings() {
  grep -qE '^Total: [1-9]|(CVE|GHSA)-[0-9]' "$1"
}

tail_log() {
  echo "     ── last lines of $1 ──"
  tail -n 12 "$1" | sed 's/^/     /'
}

scanned=0
findings=0
unverified=0

for spec in "$@"; do
  df="${spec%%:*}"
  name="${spec##*:}"
  ctx="${spec#*:}"
  ctx="${ctx%:*}"
  if [ -n "$only" ] && [ "$only" != "$name" ]; then
    continue
  fi
  scanned=$((scanned + 1))
  build_log="$logdir/trivy-$name-build.txt"
  scan_log="$logdir/trivy-$name.txt"

  printf "→ %-14s building… " "$name"
  if ! docker build -q -f "$df" -t "spatiumddi-trivy-$name:scan" "$ctx" >"$build_log" 2>&1; then
    printf "BUILD FAILED\n"
    tail_log "$build_log"
    unverified=$((unverified + 1))
    continue
  fi

  printf "scanning… "
  rc=0
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$cache":/root/.cache/ \
    aquasec/trivy:latest image \
    --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --scanners vuln -q \
    "spatiumddi-trivy-$name:scan" >"$scan_log" 2>&1 || rc=$?

  if [ "$rc" -eq 0 ]; then
    printf "clean\n"
  elif [ "$rc" -eq 1 ] && has_findings "$scan_log"; then
    printf "FINDINGS\n"
    grep -E "CVE-|GHSA-|Total:" "$scan_log" | head -8 | sed 's/^/     /'
    findings=$((findings + 1))
  else
    printf "SCAN FAILED (exit %s)\n" "$rc"
    tail_log "$scan_log"
    unverified=$((unverified + 1))
  fi
done

echo ""
if [ "$scanned" -eq 0 ]; then
  echo "✗ IMAGE=$only matched no image — nothing was scanned."
  exit 2
fi
if [ "$findings" -ne 0 ]; then
  echo "✗ Trivy found HIGH/CRITICAL vulnerabilities in $findings image(s) — fix before pushing."
  if [ "$unverified" -ne 0 ]; then
    echo "✗ $unverified more image(s) could not be scanned — see the log tails above."
  fi
  exit 1
fi
if [ "$unverified" -ne 0 ]; then
  echo "✗ $unverified image(s) could not be scanned — no verdict for them. This is"
  echo "  a Docker or Trivy failure, not a vulnerability; see the log tails above."
  exit 2
fi
echo "✓ Trivy clean (HIGH/CRITICAL, ignore-unfixed) — safe to push."
