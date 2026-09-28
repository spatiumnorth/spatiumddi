# syntax=docker/dockerfile:1.7
# SpatiumDDI PowerDNS-Authoritative container — pdns_server + spatium-dns-agent.
# Issue #127, Phase 1 — LMDB backend, no external DB dependency.
# Multi-arch: linux/amd64, linux/arm64 (non-negotiable #11)
#
# ⚠️ alpine:3.24 ships pdns 5.0.7 (3.23 shipped 5.0.5; 3.22 shipped 4.9.5) —
# READ THIS BEFORE TOUCHING THE BASE OR THE ENTRYPOINT (issue #638).
#
# PowerDNS 5.0 performs an AUTOMATIC, SILENT, IRREVERSIBLE LMDB schema
# upgrade (v5 → v6) on the first open of the database. A read is enough to
# trigger it, and there is no opt-out (the documented
# ``lmdb-schema-version=5`` escape hatch is an upstream docs bug: setting it
# makes pdns refuse to boot outright). Once 5.0 has opened the LMDB, pdns 4.9
# can no longer read it at all:
#     Error: Somehow, we are not at schema version 5. Giving up
#
# Our LMDB is persisted in every deployment shape (compose named volume /
# appliance hostPath / chart PVC), and the appliance A/B slot rollback swaps
# the ROOTFS while /var — where the database lives — is the shared persistent
# partition. So an upgrade-then-rollback would leave pdns 4.9 crash-looping on
# a schema-6 database: DNS down, with the rollback unable to recover it.
#
# This image is only safe on a pdns-5 base because of the LMDB guard
# installed below: the entrypoint snapshots the database whenever the pdns
# MAJOR version changed since the last start, BEFORE the agent spawns
# pdns_server, and fails closed if it cannot.
#
# The 3.23 → 3.24 move (#1037) is 5.0.5 → 5.0.7 — a PATCH within pdns 5, so
# the schema is already v6, no upgrade is triggered and the guard correctly
# takes no snapshot. The 4.9 → 5.0 crossing is the one that matters, and it
# already happened on the 3.22 → 3.23 move.
#
# Rolling back means redeploying the older image AND
# running ``spatium-pdns-lmdb-guard restore latest`` — see lmdb-guard.sh and
# docs/deployment/DNS_AGENT.md. Do not bypass the guard call in entrypoint.sh.
ARG PYTHON_VERSION=3.14

FROM alpine:3.24 AS agent-build
RUN apk add --no-cache python3 py3-pip py3-wheel
WORKDIR /src
COPY agent/dns/pyproject.toml /src/pyproject.toml
COPY agent/dns/spatium_dns_agent /src/spatium_dns_agent
RUN python3 -m pip install --prefix=/install --no-cache-dir --break-system-packages .

FROM alpine:3.24 AS runtime
# pdns + the LMDB backend; bind-tools only for `dig` so the smoke test
# in agent-e2e.yml works against the PowerDNS pod the same way it
# does against the BIND pod. ``libcap`` brings in ``setcap`` so we
# can grant ``pdns_server`` CAP_NET_BIND_SERVICE — without it, the
# unprivileged ``spatium`` user can't bind port 53 (the daemon starts
# but silently fails on the privileged-port bind).
#
# ``apk upgrade --no-cache`` runs BEFORE ``apk add`` so the package
# database is fresh and any previously-baked layer gets re-resolved
# against the current alpine 3.24 index. GitHub Actions Docker layer
# cache (the ``cache-from: type=gha`` on the build workflow) is
# otherwise happy to serve a 30-day-old ``apk add`` layer that Trivy
# will then flag.
#
# ``apk upgrade`` alone is NOT enough: if the whole RUN layer is a cache
# hit, neither the upgrade nor the add executes. Only a change to the
# command STRING busts it, so security-relevant floors are written as
# explicit lower bounds — they pin the fixed version AND guarantee the
# rebuild. Bump the bound when a new CVE lands.
#
# * ``bind-tools`` ``>=9.20.29-r0`` — 7 HIGH CVEs fixed in that release
#   (#1218; see the bind9 image's Dockerfile for the list).
# * ``pdns`` ``>=5.0.7-r0`` — no CVE; a floor so the version is a
#   ``versions.json`` component (#1240) the weekly upstream check can see. Only ``dig`` is
#   wanted here, but pdns also drags ``bind-libs`` transitively for the
#   DNS-name parser, and both come from the same source package.
# * ``libcrypto3`` / ``libssl3`` ``>=3.5.7-r0`` — CVE-2026-45447 (HIGH,
#   OpenSSL). The 3.24 base already satisfies it; the bound is kept
#   because it still busts a pre-3.24 cache layer.
# ``APK_SNAPSHOT`` is what makes that upgrade actually run in CI. BuildKit
# keys a layer on its RUN text, so a ``type=gha`` cache serves this whole
# layer — package set included — from whenever it was first built, until
# the text changes. The nightly passes its date tag so the layer is
# rebuilt once a night against the current index; local builds default
# to ``dev``. Full story: agent/supervisor/images/supervisor/Dockerfile.
ARG APK_SNAPSHOT=dev
RUN echo "apk snapshot ${APK_SNAPSHOT}" >/dev/null \
 && apk upgrade --no-cache \
 && apk add --no-cache \
      'pdns>=5.0.7-r0' pdns-backend-lmdb \
      'bind-tools>=9.20.29-r0' \
      tini su-exec \
      python3 py3-pip \
      libcap \
      ca-certificates tzdata \
      'libcrypto3>=3.5.7-r0' 'libssl3>=3.5.7-r0' \
 && setcap cap_net_bind_service=+ep /usr/sbin/pdns_server \
    # uid/gid PINNED (#50). The dnsdist front container reads the DoT/DoH
    # listener key this image writes at mode 0600 through a shared volume,
    # so the two must agree on the uid. Both landed on 101:102 by accident
    # of package ordering; pinning makes a future package that creates a
    # system user fail the BUILD loudly instead of silently shifting the
    # uid and breaking TLS at runtime (dnsdist --check-config never opens
    # the PEM, so the failure would only surface as a fatal daemon start).
    # Also matches the on-disk ownership of existing state volumes.
 && addgroup -S -g 102 spatium \
 && adduser -S -u 101 -G spatium spatium \
 && mkdir -p /var/lib/spatium-dns-agent /var/lib/powerdns /var/run/pdns \
 && chown -R spatium:spatium /var/lib/spatium-dns-agent /var/lib/powerdns /var/run/pdns \
 && { \
      echo "alpine_release=$(cat /etc/alpine-release)"; \
      apk info -v 2>/dev/null \
        | grep -E '^(pdns|pdns-backend-lmdb)-' \
        | sort -u \
        | sed 's/^\([a-z0-9-]*\)-\([0-9].*\)$/\1=\2/'; \
    } > /etc/spatiumddi-versions

COPY --from=agent-build /install /usr/local
COPY agent/dns/images/powerdns/entrypoint.sh /usr/local/bin/spatium-dns-entrypoint
# #638 — the LMDB schema guard. Installed as a first-class command (not an
# entrypoint-internal helper) because the operator needs to run ``list`` /
# ``restore`` by hand from a shell in a node whose DNS is currently down.
COPY agent/dns/images/powerdns/lmdb-guard.sh /usr/local/bin/spatium-pdns-lmdb-guard
RUN chmod +x /usr/local/bin/spatium-dns-entrypoint /usr/local/bin/spatium-pdns-lmdb-guard

ARG PYTHON_VERSION
ENV AGENT_DRIVER=powerdns \
    AGENT_STATE_DIR=/var/lib/spatium-dns-agent \
    PYTHONPATH=/usr/local/lib/python${PYTHON_VERSION}/site-packages \
    LOG_LEVEL=INFO

# #1037 — prove PYTHONPATH matches THIS image's interpreter, at build time.
# The agent is installed into /usr/local/lib/python<X.Y>/site-packages by the
# build stage and is found only because PYTHONPATH names that exact directory.
# When the Alpine base moves the bundled Python (3.23 shipped 3.12, 3.24 ships
# 3.14) a stale PYTHONPATH yields an image that builds clean and then
# CrashLoopBackOffs with ModuleNotFoundError — what #672 hit, and the reason
# the base stayed pinned for a year. One import turns that into a build
# failure, here, instead of a pod failure in the field.
RUN python3 -c "import spatium_dns_agent"


VOLUME ["/var/lib/spatium-dns-agent", "/var/lib/powerdns"]
EXPOSE 53/udp 53/tcp

# Authoritative servers respond to a CHAOS-class query for "id.server"
# (the analogue of BIND's "version.bind"). Use that as the liveness
# probe so the check is independent of any zone state.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD dig @127.0.0.1 -p 53 id.server CH TXT +short +timeout=2 || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/spatium-dns-entrypoint"]
