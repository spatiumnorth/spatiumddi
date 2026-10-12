# syntax=docker/dockerfile:1.7
# SpatiumDDI Kea DHCP container — kea-dhcp4 + kea-dhcp6 + kea-ctrl-agent + spatium-dhcp-agent
# Multi-arch: linux/amd64, linux/arm64 (non-negotiable #11)
ARG PYTHON_VERSION=3.14

FROM alpine:3.24 AS agent-build
RUN apk add --no-cache python3 py3-pip py3-wheel
WORKDIR /src
COPY agent/dhcp/pyproject.toml /src/pyproject.toml
COPY agent/dhcp/spatium_dhcp_agent /src/spatium_dhcp_agent
COPY agent/dhcp/README.md /src/README.md
RUN python3 -m pip install --prefix=/install --no-cache-dir --break-system-packages .

FROM alpine:3.24 AS runtime
# libpcap is pulled in for scapy's BPF socket support, used by the
# optional Phase 2 device-fingerprinting sniffer (DHCP_FINGERPRINT_ENABLED=1).
# scapy itself is pure-python so the install works on amd64 + arm64
# without compilation. The container also needs CAP_NET_RAW at run-time
# for the sniffer to bind the socket — see docs/deployment/DOCKER.md.
#
# ``libcap`` brings in ``setcap`` so we can grant ``kea-dhcp4`` /
# ``kea-dhcp6`` the CAP_NET_BIND_SERVICE + CAP_NET_RAW file capabilities.
# NET_BIND_SERVICE: bind UDP/67 (DHCPv4) + UDP/547 (DHCPv6) as the
# unprivileged ``spatium`` user the entrypoint drops to. NET_RAW: open
# the AF_PACKET/LPF raw socket for ``dhcp-socket-type: raw`` (the
# #365/#366 default — required to hear directly-attached broadcast
# DISCOVERs); without it kea-dhcp4 fails with "Failed to create raw LPF
# socket" on the real NIC and serves no leases (#383). Crucially:
# container-level ``cap_add`` / ``securityContext.capabilities.add:
# [NET_RAW]`` only sets the bounding set — it's DROPPED when the
# entrypoint ``su-exec``s to the non-root user, so the capability has to
# live on the binary as a file cap to survive the privilege drop. Same
# fix as named + pdns_server in the DNS image family.
#
# ``setpriv`` (util-linux) is added for the python agent's launch: the
# opt-in scapy rogue-DHCP probe + fingerprint sniffer need CAP_NET_RAW,
# but a python interpreter can't carry a file cap, so the entrypoint
# raises NET_RAW into the *ambient* set via setpriv (survives the
# setuid + execve into ``spatium``). See entrypoint.sh (#383).
#
# ``kea>=3.0.3-r0`` (issue #637) — alpine 3.24 ships Kea 3.0.3, ISC's first
# LTS. The explicit ``>=`` lower-bound is what makes the major EXPLICIT: the
# old ``>=2.6.5-r0`` bound was *satisfied* by 3.0.3-r0, so flipping the base
# tag alone would have silently pulled a major version bump. 3.0.3 (not
# 3.0.0-3.0.2) is also the CVE floor — it carries the CVE-2026-3608 fix
# (deeply-nested-JSON stack overflow, reachable on every control endpoint and
# explicitly noted upstream to bypass the HA command filters) plus the
# 3.0.0/3.0.2 crafted-packet crash fixes. The bound additionally busts the
# BuildKit ``cache-from`` layer so a stale ``apk add`` layer can't serve a
# vulnerable version. ``kea-dhcp6`` is named explicitly (the ``kea``
# meta-package pulls it in too) so it is obvious the v6 daemon is part of the
# always-on dual-stack image.
#
# ⚠️ KEA 3.0 PATH RESTRICTIONS — DO NOT "TIDY" THE PATHS BELOW.
# Kea 3.0 (CVE-2025-32801/2/3) refuses to start if hook libraries, unix
# control sockets, lease files or log files live outside its COMPILED-IN
# default directories. Enforcement is a literal string compare of the config
# path's parent — there is no realpath(), so even ``/var/run/kea`` vs
# ``/run/kea`` fails. Alpine builds Kea with ``-Dprefix=/usr
# -Dlocalstatedir=/var -Drunstatedir=/run``, making the enforced defaults:
#     hooks   → /usr/lib/kea/hooks   (render_kea.py: HA + lease_cmds ``library``)
#     socket  → /run/kea             (KEA_CONTROL_SOCKET; dir must be mode 0750)
#     leases  → /var/lib/kea         (KEA_LEASE_FILE)
#     logs    → /var/log/kea         (render_kea.py ``output_options``)
# Those happen to be exactly our existing layout, which is why the 2.6 → 3.0
# jump needed no config changes at all. Move any of them and kea-dhcp4 will
# refuse to start (or log an unrecoverable error if already running). Verify
# with ``kea-dhcp4 -W`` ("Hooks directory") and ``kea-dhcp4 -T <conf>``.
#
# ``kea-ctrl-agent`` is deliberately NOT installed (#637). Kea 3.0 deprecates
# it, and nothing in SpatiumDDI ever spoke to it: the agent drives kea-dhcp4 /
# kea-dhcp6 over their unix control sockets (spatium_dhcp_agent/kea_ctrl.py —
# config-reload, status-get, statistic-get-all) and the backend
# KeaDriver.apply_config is a no-op. It was dead weight whose supervise loop
# could take the whole container down via the entrypoint's ``wait -n``.
#
# ``apk upgrade --no-cache`` runs BEFORE ``apk add`` so the package
# database is fresh and any previously-baked layer carrying an older
# libpq version (CVE-2026-6638 fixed in 17.10-r0 — pulled in
# transitively by kea-admin's optional psql backend wiring) gets
# re-resolved against the current alpine 3.24 index. GitHub Actions
# Docker layer cache (``cache-from: type=gha``) is otherwise happy
# to serve a 30-day-old ``apk add`` layer that Trivy will then flag.
#
# The old explicit ``libcrypto3>=3.5.7-r0`` / ``libssl3>=3.5.7-r0`` bounds
# (CVE-2026-45447) are gone: the alpine 3.24 base already ships openssl
# 3.5.7-r0, so they were redundant. ``apk upgrade`` above keeps them current.
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
      'kea>=3.0.3-r0' kea-dhcp4 kea-dhcp6 kea-admin \
      kea-hook-lease-cmds kea-hook-ha \
      tini su-exec setpriv \
      python3 py3-pip libpcap \
      libcap \
      radvd \
      ca-certificates tzdata \
 && setcap cap_net_bind_service,cap_net_raw=+ep /usr/sbin/kea-dhcp4 \
 && setcap cap_net_bind_service,cap_net_raw=+ep /usr/sbin/kea-dhcp6 \
 # radvd (issue #524) — opt-in IPv6 Router Advertisement daemon, started
 # by the entrypoint only when RADVD_MANAGED=1. Needs CAP_NET_RAW to open
 # the ICMPv6 raw socket + CAP_NET_ADMIN to send RAs; as a file cap so it
 # survives the su-exec drop to the unprivileged spatium user.
 && setcap cap_net_raw,cap_net_admin=+ep /usr/sbin/radvd \
 && addgroup -S spatium \
 && adduser -S -G spatium spatium \
 && mkdir -p /var/lib/spatium-dhcp-agent /var/lib/kea /run/kea /etc/kea /var/log/kea \
      /etc/radvd /run/radvd \
 && chown -R spatium:spatium /var/lib/spatium-dhcp-agent /var/lib/kea /run/kea /etc/kea /var/log/kea \
      /etc/radvd /run/radvd \
 && { \
      echo "alpine_release=$(cat /etc/alpine-release)"; \
      apk info -v 2>/dev/null \
        | grep -E '^kea(-[a-z]+)?-' \
        | sort -u \
        | sed 's/^\([a-z0-9-]*\)-\([0-9].*\)$/\1=\2/'; \
    } > /etc/spatiumddi-versions

COPY --from=agent-build /install /usr/local
COPY agent/dhcp/images/kea/kea-dhcp4.conf /etc/kea/kea-dhcp4.conf
COPY agent/dhcp/images/kea/kea-dhcp6.conf /etc/kea/kea-dhcp6.conf
COPY agent/dhcp/images/kea/entrypoint.sh /usr/local/bin/spatium-dhcp-entrypoint
RUN chmod +x /usr/local/bin/spatium-dhcp-entrypoint \
 && chown spatium:spatium \
      /etc/kea/kea-dhcp4.conf /etc/kea/kea-dhcp6.conf

ARG PYTHON_VERSION
ENV CACHE_DIR=/var/lib/spatium-dhcp-agent \
    KEA_CONFIG_PATH=/etc/kea/kea-dhcp4.conf \
    KEA_CONTROL_SOCKET=/run/kea/kea4-ctrl-socket \
    KEA_LEASE_FILE=/var/lib/kea/kea-leases4.csv \
    KEA_CONFIG_PATH_V6=/etc/kea/kea-dhcp6.conf \
    KEA_CONTROL_SOCKET_V6=/run/kea/kea6-ctrl-socket \
    PYTHONPATH=/usr/local/lib/python${PYTHON_VERSION}/site-packages \
    LOG_LEVEL=INFO \
    RADVD_MANAGED=0 \
    RADVD_CONFIG_PATH=/etc/radvd/radvd.conf \
    RADVD_PIDFILE=/run/radvd/radvd.pid \
    RADVD_DEFAULT_IFACE=eth0

# #1037 — prove PYTHONPATH matches THIS image's interpreter, at build time.
# The agent is installed into /usr/local/lib/python<X.Y>/site-packages by the
# build stage and is found only because PYTHONPATH names that exact directory.
# When the Alpine base moves the bundled Python (3.23 shipped 3.12, 3.24 ships
# 3.14) a stale PYTHONPATH yields an image that builds clean and then
# CrashLoopBackOffs with ModuleNotFoundError — what #672 hit, and the reason
# the base stayed pinned for a year. One import turns that into a build
# failure, here, instead of a pod failure in the field.
RUN python3 -c "import spatium_dhcp_agent"


VOLUME ["/var/lib/spatium-dhcp-agent", "/var/lib/kea"]
# DHCPv4 server
EXPOSE 67/udp
# DHCPv6 server (always-on dual-stack — kea-dhcp6 binds 547 once started)
EXPOSE 547/udp
# Kea HA hook peer-to-peer HTTP listener (CmdHttpListener bound to the
# this-server peer URL). When HA is inactive the port is unused.
#
# This is now the ONLY TCP port the image exposes: kea-ctrl-agent (:8544) was
# removed in #637 — see the package-install comment above. The HA hook owns
# 8000 exclusively, so the old "don't collide with 8544" constraint is moot.
# Note Kea 3.0 also flips the HA listener's ``restrict-commands`` default to
# true, so this port now answers only HA-internal commands regardless.
EXPOSE 8000/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD test -S /run/kea/kea4-ctrl-socket || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/spatium-dhcp-entrypoint"]

# #1182 — the version the agent reports: the release tag from release.yml,
# the nightly stamp from nightly.yml. A build that passes nothing reports
# "dev". Last, so a new version only rebuilds this layer.
ARG APP_VERSION=dev
ENV SPATIUM_AGENT_VERSION=${APP_VERSION}
