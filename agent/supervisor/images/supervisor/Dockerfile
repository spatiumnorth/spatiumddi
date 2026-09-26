# syntax=docker/dockerfile:1.7
# SpatiumDDI Supervisor — host-side controller for Application-role appliances.
# Multi-arch: linux/amd64, linux/arm64 (non-negotiable #11).
#
# Phase A1 ships a near-empty supervisor — the box exists, builds
# clean, and logs an idle heartbeat. Real work lands in Waves A2 → D.
# See agent/supervisor/README.md.
ARG PYTHON_VERSION=3.14

FROM alpine:3.24 AS build
RUN apk add --no-cache python3 py3-pip py3-wheel
WORKDIR /src
COPY agent/supervisor/pyproject.toml /src/pyproject.toml
COPY agent/supervisor/spatium_supervisor /src/spatium_supervisor
COPY agent/supervisor/README.md /src/README.md
RUN python3 -m pip install --prefix=/install --no-cache-dir --break-system-packages .

FROM alpine:3.24 AS runtime
# Issue #183 Phase 7 — k3s-only appliance. ``docker-cli`` +
# ``docker-cli-compose`` are gone; the supervisor's k3s lifecycle
# module talks to the local kubeapi via stdlib http.client (no
# ``kubernetes`` Python client needed — see k8s_api.py). The
# supervisor pod uses in-cluster ServiceAccount auth, so it doesn't
# need a kubeconfig file either.
#
# ``nftables`` stays — the supervisor renders nft drop-ins under
# ``/etc/nftables.d/`` and exec()s ``nft -f`` to apply (firewall
# allowlist for the kubeapi-direct CIDRs, role-driven ports).
# dashboard-and-remote-nettools — reachability-tool binaries for the
# agent-perspective network tools (ping / traceroute / dig). The
# supervisor's nettool poll thread runs these against the appliance's
# local vantage when an operator dispatches a tool from the Tools page.
#   * iputils    — provides the REAL iputils ``ping``. The argv builder
#                  uses iputils flags (``-n`` numeric, ``-w`` deadline);
#                  BusyBox's built-in ping lacks ``-n`` and treats
#                  ``-w`` differently, so iputils MUST override it.
#   * traceroute — standalone traceroute (BusyBox's lacks the flags).
#   * bind-tools — provides ``dig`` (Alpine's BIND utils package).
# port-test + tls-cert are pure-Python (asyncio sockets + ssl +
# cryptography) and need no binary. mtr + whois are intentionally NOT
# installed — they stay server-only (mtr needs CAP_NET_RAW + is covered
# by ping/traceroute; whois hits off-prem infra with no per-vantage
# meaning), so the control plane never dispatches them to an appliance.
# ``apk upgrade --no-cache`` runs BEFORE ``apk add`` so the base image's
# packages (openssl / libcrypto3 / libssl3, …) are pulled forward to their
# fixed versions — keeps the Trivy HIGH/CRITICAL gate clean. Same pattern as
# the DNS/DHCP agent images (agent/{dns,dhcp}/images/*/Dockerfile).
#
# ``APK_SNAPSHOT`` exists to make that actually happen in CI. BuildKit keys
# a layer on its RUN command text, so ``--no-cache`` (which only tells apk
# not to keep its own index) does nothing to stop the whole layer being
# restored from the ``type=gha`` cache — the image then keeps shipping
# whatever package set the layer was FIRST built with, indefinitely.
# That is how this image was still shipping bind 9.20.23-r0 days after
# Alpine published the 9.20.26-r0 fix, failing the PR Trivy gate on a
# change that had nothing to do with it. The workflow passes the current
# ISO year-week, so the package layer rebuilds weekly — matching the
# cadence of trivy-scheduled.yml, and bounding how long a published fix
# can sit unapplied. Everything above this line still caches normally.
ARG APK_SNAPSHOT=dev
RUN echo "apk snapshot ${APK_SNAPSHOT}" >/dev/null \
 && apk upgrade --no-cache \
 && apk add --no-cache \
      tini su-exec \
      python3 py3-pip \
      nftables libcap \
      ca-certificates tzdata \
      iputils traceroute bind-tools \
 && addgroup -S spatium \
 && adduser -S -G spatium spatium \
 && mkdir -p /var/lib/spatium-supervisor \
 && chown -R spatium:spatium /var/lib/spatium-supervisor \
 && setcap cap_net_admin+eip /usr/sbin/nft \
 && setcap cap_net_raw+ep /usr/bin/traceroute
# dashboard-and-remote-nettools — traceroute needs a raw socket but
# Alpine ships it NON-setuid, so the unprivileged ``spatium`` user the
# entrypoint drops to can't open one without a file cap. ``ping`` is
# already setuid-root in the iputils package so it needs no setcap.
# The pod runs privileged (supervisor.yaml securityContext) so
# CAP_NET_RAW is in the bounding set; the file cap promotes it into the
# non-root process's effective set. Same pattern as the nft setcap
# above + the api image's setcap on nmap.
# ``libcap`` ships ``setcap``; the file cap on /usr/sbin/nft lets the
# unprivileged ``spatium`` user (issue #170 design) actually exercise
# the CAP_NET_ADMIN the compose entry requests. Without the file
# cap, compose's ``cap_add: NET_ADMIN`` only adds the cap to the
# container's bounding set — a non-root process still needs file
# caps to use it. Same shape as the api image's setcap on nmap.

COPY --from=build /install /usr/local
COPY agent/supervisor/images/supervisor/entrypoint.sh /usr/local/bin/spatium-supervisor-entrypoint
RUN chmod +x /usr/local/bin/spatium-supervisor-entrypoint

ARG PYTHON_VERSION
ENV STATE_DIR=/var/lib/spatium-supervisor \
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
RUN python3 -c "import spatium_supervisor"


VOLUME ["/var/lib/spatium-supervisor"]

# Process health = the python entry is still pid-of-supervisor.
# Real health (cert valid, control plane reachable, role applied)
# is a Wave A2+ concern.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD pgrep -f spatium-supervisor >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/spatium-supervisor-entrypoint"]

# #1183 — the version the supervisor reports: the release tag from
# release.yml, the nightly stamp from nightly.yml, the dev stamp from
# ``make build-supervisor``. A build that passes nothing reports "dev".
# Last, so a new version only rebuilds this layer.
ARG APP_VERSION=dev
ENV SPATIUM_SUPERVISOR_VERSION=${APP_VERSION}
