# syntax=docker/dockerfile:1.7
# SpatiumDDI BIND9 DNS container — BIND9 + spatium-dns-agent
# Multi-arch: linux/amd64, linux/arm64 (non-negotiable #11)
ARG PYTHON_VERSION=3.14

FROM alpine:3.24 AS agent-build
RUN apk add --no-cache python3 py3-pip py3-wheel
WORKDIR /src
COPY agent/dns/pyproject.toml /src/pyproject.toml
COPY agent/dns/spatium_dns_agent /src/spatium_dns_agent
RUN python3 -m pip install --prefix=/install --no-cache-dir --break-system-packages .

FROM alpine:3.24 AS runtime
# ``libcap`` brings in ``setcap`` so we can grant ``named`` the
# CAP_NET_BIND_SERVICE file capability — without it, the unprivileged
# ``spatium`` user the entrypoint drops to can't bind port 53 (named
# starts but only ends up listening on the stats-channel port >1024,
# silently failing on real DNS traffic). Alpine's ``bind`` package
# does NOT set this cap automatically, unlike ``iputils-ping`` etc.
#
# ``apk upgrade --no-cache`` runs BEFORE ``apk add`` so the package
# database is fresh and any previously-baked layer carrying an older
# bind / bind-libs version gets re-resolved against the current alpine
# 3.24 index. GitHub Actions Docker layer cache (the ``cache-from:
# type=gha`` on the build workflow) is otherwise perfectly happy to
# serve a 30-day-old ``apk add`` layer that Trivy will then flag.
#
# ``apk upgrade`` alone is NOT enough, and this is the part that keeps
# biting: if the whole RUN layer is a cache hit, neither the upgrade nor
# the add executes at all. Only a change to the command STRING busts it.
# So security-relevant floors are written as explicit lower bounds —
# they pin the fixed version AND, by changing the string, guarantee the
# layer is rebuilt. When a new CVE lands, bump the bound here.
#
# * ``bind`` / ``bind-tools`` ``>=9.20.29-r0`` — CVE-2026-19666, -19667,
#   -76163, -77692, -80274, -81563, -81736 (7 HIGH remote DoS, all fixed
#   in 9.20.29-r0; #1218). The release 2026.09.04-1 shipped 9.20.26.
#   The previous floor, 9.20.26-r0, covered CVE-2026-11331, -11605,
#   -11622, -11721, -12617, -13204, -13321, caught by CI on PR #716 after
#   the image had been building from a cached layer carrying 9.20.23-r0.
#   The floor is also a ``versions.json`` component (``bind``, #1240), so
#   the weekly upstream check reports when Alpine ships a newer build.
# * ``libcrypto3`` / ``libssl3`` ``>=3.5.7-r0`` — CVE-2026-45447 (HIGH,
#   OpenSSL). The 3.24 base already satisfies this one; the bound is
#   kept because it still busts a pre-3.24 cache layer.
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
      'bind>=9.20.29-r0' 'bind-tools>=9.20.29-r0' \
      tini su-exec \
      python3 py3-pip \
      libcap \
      ca-certificates tzdata \
      'libcrypto3>=3.5.7-r0' 'libssl3>=3.5.7-r0' \
 && setcap cap_net_bind_service=+ep /usr/sbin/named \
 && addgroup -S spatium \
 && adduser -S -G spatium spatium \
 && mkdir -p /var/lib/spatium-dns-agent /var/cache/bind /var/run/named /var/log/named \
 && chown -R spatium:spatium /var/lib/spatium-dns-agent /var/cache/bind /var/run/named /var/log/named \
 && { \
      echo "alpine_release=$(cat /etc/alpine-release)"; \
      apk info -v 2>/dev/null \
        | grep -E '^(bind|bind-tools|bind-libs)-' \
        | sort -u \
        | sed 's/^\([a-z0-9-]*\)-\([0-9].*\)$/\1=\2/'; \
    } > /etc/spatiumddi-versions

COPY --from=agent-build /install /usr/local
COPY agent/dns/images/bind9/entrypoint.sh /usr/local/bin/spatium-dns-entrypoint
RUN chmod +x /usr/local/bin/spatium-dns-entrypoint

ARG PYTHON_VERSION
ENV AGENT_DRIVER=bind9 \
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


VOLUME ["/var/lib/spatium-dns-agent", "/var/cache/bind"]
EXPOSE 53/udp 53/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD dig @127.0.0.1 -p 53 . NS +short +timeout=2 || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/spatium-dns-entrypoint"]

# #1182 — the version the agent reports: the release tag from release.yml,
# the nightly stamp from nightly.yml. A build that passes nothing reports
# "dev". Last, so a new version only rebuilds this layer.
ARG APP_VERSION=dev
ENV SPATIUM_AGENT_VERSION=${APP_VERSION}
