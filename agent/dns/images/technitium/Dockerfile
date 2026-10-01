# syntax=docker/dockerfile:1.7
# SpatiumDDI Technitium DNS Server container — DnsServerApp + spatium-dns-agent.
# Multi-arch: linux/amd64, linux/arm64 (non-negotiable #11).
#
# Unlike bind9/powerdns (Alpine + an apk-packaged daemon binary), Technitium
# ships no Alpine package and no binary release assets at all (its GitHub
# releases carry release NOTES only — verified empirically, zero attached
# assets). The only reproducible, versioned, multi-arch artifact Technitium
# publishes is its own official Docker image
# (``docker.io/technitium/dns-server``, Ubuntu 24.04 + .NET 10 aspnet
# runtime). So this image builds FROM that upstream image and layers the
# agent on top, rather than trying to fetch+extract a build artifact that
# doesn't exist. This means the image is glibc/Ubuntu-based, not Alpine —
# an intentional, documented deviation from the other two DNS images.
#
# Pin the exact upstream tag (not :latest) for reproducible builds — bump
# deliberately, the same way the pdns/bind package versions are pinned.
#
# Pinned by DIGEST as well as tag. Unlike bind9/powerdns — whose bases are
# distro images from a first-party registry and whose daemons come from
# apk with its own signature chain — this runtime is a third-party Docker
# Hub account's image, and it lands in the appliance ISO's baked image set
# on every install. A tag is mutable: a retag upstream would silently
# change what ships in a release without any diff here. The digest is the
# image INDEX (multi-arch manifest list), so buildx still selects
# amd64/arm64 per platform (non-negotiable #11).
#
# To bump: set the new tag, then
#   docker buildx imagetools inspect technitium/dns-server:<tag> \
#     --format '{{.Manifest.Digest}}'
# and paste the result below. Both must move together — a mismatched pair
# fails the pull outright rather than silently preferring one.
ARG TECHNITIUM_VERSION=15.4.0
ARG TECHNITIUM_DIGEST=sha256:df7d90ef0f7b6fff6916d291a7022cd902290cc31c3141d4158b6c375a641b41
ARG PYTHON_VERSION=3.12

# Builder matches the RUNTIME's libc family (glibc/Debian), not Alpine —
# spatium_dns_agent depends on `cryptography`, which ships compiled wheels;
# building on Alpine would resolve musllinux wheels that don't load on the
# Ubuntu-based Technitium runtime.
FROM python:${PYTHON_VERSION}-slim-bookworm AS agent-build
WORKDIR /src
COPY agent/dns/pyproject.toml /src/pyproject.toml
COPY agent/dns/spatium_dns_agent /src/spatium_dns_agent
RUN pip install --prefix=/install --no-cache-dir .

FROM technitium/dns-server:${TECHNITIUM_VERSION}@${TECHNITIUM_DIGEST} AS runtime

# `dig` already ships in the upstream image (dnsutils, installed for
# troubleshooting) — reused here for the HEALTHCHECK. Add python3 for the
# agent + su-exec-equivalent (gosu — Debian/Ubuntu's su-exec) to drop
# privileges, and libcap2-bin for setcap.
#
# `aspnetcore-runtime-10.0` (which pulls in `dotnet-runtime-10.0`) is
# installed explicitly to pick up Ubuntu's patched runtime — the upstream
# `technitium/dns-server:15.4.0` image ships .NET 10.0.9 (installed via
# Microsoft's own binary layout under /usr/share/dotnet, not tracked by
# apt), which carries five HIGH CVEs (CVE-2026-47302/50524/50528/50651/
# 57108, fixed in 10.0.10 — caught by `make trivy IMAGE=technitium`).
# Ubuntu's noble-updates/security repo already ships the fixed 10.0.10
# package (confirmed — no need for the Microsoft apt repo the base image
# registers for libmsquic). `dotnet` resolves the highest installed
# runtime satisfying an app's version range at launch, so installing
# apt's copy alongside the vendored one is sufficient — verified via
# `dotnet --list-runtimes` before/after. Bump this alongside
# TECHNITIUM_VERSION and re-run `make trivy IMAGE=technitium`.
#
# `apt-get upgrade` runs BEFORE the install for the same reason every
# Alpine image in this repo runs `apk upgrade`: the upstream base is
# pinned by digest, so nothing else in this file can ever patch the
# packages it shipped with. `APT_SNAPSHOT` is what lets the upgrade
# actually execute — BuildKit keys a layer on its RUN text, so a
# `type=gha` cache serves this whole layer, package set included, from
# whenever it was first built until that text changes. Same knob as
# `APK_SNAPSHOT` in the Alpine images. See #1088, where the api image
# having neither published 34 HIGH/CRITICAL findings whose fixes had
# been on the mirrors for days.
#
# WHICH BUILDS HONOUR IT, because it is not "CI" as a whole:
#   nightly.yml   passes the date tag — the layer rebuilds once a night.
#   release.yml   uses no layer cache at all, so it always rebuilds.
#   build-dns-images.yml (the PR-time Trivy lane) passes NOTHING and
#     caches on `type=gha`, so what it scans can be an old package set.
#     Arming it needs more than a build-arg: that lane runs Trivy with a
#     bare `exit-code: 1` and no trivy-gate.sh, so a fix announced ahead
#     of its mirror would hard-fail every PR with nothing a rebuild could
#     do — the failure the gate exists to prevent. Both halves together,
#     or neither.
# Local builds default to `dev`.
ARG APT_SNAPSHOT=dev
RUN echo "apt snapshot ${APT_SNAPSHOT}" >/dev/null \
 && apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
      python3 gosu libcap2-bin tini aspnetcore-runtime-10.0 \
 && apt-get clean -y \
 && rm -rf /var/lib/apt/lists/* \
    # The apt package replaces /usr/bin/dotnet's target with its own host
    # at /usr/lib/dotnet/dotnet (confirmed: `dotnet --list-runtimes`
    # post-install shows ONLY 10.0.10, from /usr/lib/dotnet/shared/... —
    # the vendored copy at /usr/share/dotnet is no longer reachable through
    # the active dotnet binary at all, not merely superseded in a version
    # search). Remove it outright: leaving the orphaned 10.0.9 files on
    # disk serves no purpose (they're dead weight, ~200MB) and is exactly
    # what Trivy's .NET scanner keys on (it reads shared-framework
    # directories directly, not `dotnet --list-runtimes`) — so the CVEs it
    # flags stay flagged even though nothing loads those files. Verified
    # DnsServerApp.dll starts fine post-removal.
 && rm -rf /usr/share/dotnet \
    # The upstream image runs `dotnet DnsServerApp.dll` as root (no
    # unprivileged user is created upstream). Grant CAP_NET_BIND_SERVICE to
    # the shared dotnet host binary so the unprivileged `spatium` user this
    # image adds can still bind :53 — this container runs nothing else, so
    # scoping the capability to `dotnet` system-wide is acceptable here.
 && setcap cap_net_bind_service=+ep "$(readlink -f "$(command -v dotnet)")" \
 && groupadd -g 102 spatium \
 && useradd -u 101 -g spatium -M -s /usr/sbin/nologin spatium \
 && mkdir -p /var/lib/spatium-dns-agent /etc/dns /var/log/technitium \
 && chown -R spatium:spatium /var/lib/spatium-dns-agent /etc/dns /var/log/technitium

COPY --from=agent-build /install /usr/local
COPY agent/dns/images/technitium/entrypoint.sh /usr/local/bin/spatium-dns-entrypoint
RUN chmod +x /usr/local/bin/spatium-dns-entrypoint

# Override the upstream ENTRYPOINT/CMD entirely — the agent launches
# DnsServerApp.dll itself as a supervised subprocess (same pattern as the
# PowerDNS driver launching pdns_server directly), so this image never
# hits the base image's own entrypoint. tini as PID 1, matching bind9/
# powerdns, so signals + the dotnet child process reap correctly.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/spatium-dns-entrypoint"]
CMD []

ARG PYTHON_VERSION
ENV AGENT_DRIVER=technitium \
    AGENT_STATE_DIR=/var/lib/spatium-dns-agent \
    PYTHONPATH=/usr/local/lib/python${PYTHON_VERSION}/site-packages \
    LOG_LEVEL=INFO

# #1037 — prove PYTHONPATH matches THIS image's interpreter, at build time.
# Unlike the Alpine agents, PYTHON_VERSION here has to match TWO things: the
# `python:${PYTHON_VERSION}-slim-bookworm` builder above (which resolves the
# compiled `cryptography` wheel) and the python3 inside the upstream
# `technitium/dns-server` image, which is whatever Ubuntu release it is built
# on. Today both are 3.12 — by coincidence, not by construction. The next
# TECHNITIUM_DIGEST bump onto a newer Ubuntu silently breaks the pair: the
# wheels stay cp312, the interpreter does not, and the agent dies at runtime
# with no build-time signal (#672's shape on the one image #1037 first missed).
#
# The version EQUALITY check is the load-bearing half, and an import alone is
# not enough here — verified: building with `--build-arg PYTHON_VERSION=3.13`
# moves the builder AND PYTHONPATH together, so the import still succeeds even
# though the runtime interpreter is 3.12. (It succeeds because `cryptography`
# and `pydantic-core` ship abi3 wheels, which load across 3.x — so the import
# cannot see the skew that a pure-cp3XX dependency would trip over.) Compare
# the interpreter to the arg directly instead.
RUN set -eu; \
    have="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"; \
    if [ "$have" != "${PYTHON_VERSION}" ]; then \
        echo "PYTHON_VERSION=${PYTHON_VERSION} but this image ships python $have." >&2; \
        echo "The technitium base moved Python: bump PYTHON_VERSION (and versions.json)." >&2; \
        exit 1; \
    fi; \
    python3 -c "import spatium_dns_agent, cryptography"

VOLUME ["/var/lib/spatium-dns-agent", "/etc/dns", "/var/log/technitium"]
EXPOSE 53/udp 53/tcp

# Unlike bind9/powerdns, Technitium REFUSES CHAOS-class queries entirely
# (confirmed empirically — "id.server CH TXT" / "version.bind CH TXT" both
# come back REFUSED, not answered) so the usual id.server liveness probe
# doesn't apply here. Query the RFC 6761 reserved "invalid." TLD instead —
# Technitium answers it locally and instantly (NXDOMAIN, no recursion
# attempted) regardless of any configured zone state, which is exactly the
# "is the daemon actually listening and answering on :53" signal a
# healthcheck needs.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD dig @127.0.0.1 -p 53 healthcheck.invalid A +timeout=2 +tries=1 || exit 1

# #1182 — the version the agent reports: the release tag from release.yml,
# the nightly stamp from nightly.yml. A build that passes nothing reports
# "dev". Last, so a new version only rebuilds this layer.
ARG APP_VERSION=dev
ENV SPATIUM_AGENT_VERSION=${APP_VERSION}
