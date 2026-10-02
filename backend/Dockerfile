# ── Stage 1: build dependencies ───────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System dev deps for compiled Python packages: asyncpg (libpq), python3-saml
# (libxml2 + xmlsec).
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy only the dependency manifest first so this layer is cached independently
# of source code changes.
COPY pyproject.toml .

# Create a minimal stub package so hatchling can resolve metadata without
# needing the full source tree, then install runtime deps only.
RUN mkdir -p app && touch app/__init__.py && \
    pip install --no-cache-dir --prefix=/install .


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    NMAP_PRIVILEGED=1
    # NMAP_PRIVILEGED=1 — Debian's nmap does an early getuid()==0 check
    # for SYN scans + ``-O`` OS detection and bails before consulting the
    # process's actual capabilities. This env var (or ``--privileged``)
    # tells nmap to trust that it has the necessary raw-socket privilege
    # via Linux capabilities (granted by the setcap-on-nmap line below).
    # Without it operators get "TCP/IP fingerprinting requires root
    # privileges" even though CAP_NET_RAW is in the process's effective
    # set. The cap itself is still required — env var alone doesn't help.

WORKDIR /app

# Runtime system deps: libpq5 for asyncpg, libxmlsec1 for python3-saml,
# iputils-ping for the DNS pool ICMP health-check (the binary ships
# with cap_net_raw+ep on Debian, so it works as the non-root app user).
# traceroute + mtr-tiny + dnsutils (dig) + whois back the built-in
# network-tools surface (#58); they're invoked via the server-perspective
# nettools runner. mtr-tiny needs CAP_NET_RAW for ICMP probes — the api
# container doesn't grant it, so mtr falls back to UDP probes (still a
# usable report). ping reuses the existing cap_net_raw+ep iputils binary.
# libcap2-bin gives us setcap so we can grant nmap CAP_NET_RAW —
# without it ``nmap -O`` (and any SYN scan) bails with
# "TCP/IP fingerprinting requires root privileges" when invoked by
# the non-root app user. The cap is in Docker's default bounding set
# so this works without needing cap_add at the compose / k8s layer.
# libnfs14 backs the ``nfs`` backup destination (#971). Runtime shared
# library only — the driver binds it through ctypes, so there is no
# ``libnfs-dev`` and no compile step in the builder stage. Dynamic
# linking is also what keeps the LGPL-2.1 obligation to the simple case;
# see docs/THIRD_PARTY.md and the root NOTICE.
# Add the official PostgreSQL apt repo so we can pin
# ``postgresql-client-16`` (Debian trixie's default repos only carry
# client-17). We need the client major to match the postgres SERVER
# version we ship in compose/k8s — pg_dump 17 emits
# ``SET transaction_timeout = 0;`` and ``\restrict`` directives that
# a postgres-16 server rejects on replay. When we eventually bump
# the postgres image to 17, bump this pin in lockstep.
#
# ``apt-get upgrade`` runs BEFORE the installs so the base image's own
# packages — perl-base, gzip, libpcre2, libsqlite3, libssh2, everything
# ``python:3.12-slim`` brought with it — are patched against the current
# Debian index rather than frozen at whatever the base image was baked
# with. Without it those packages can only ever be fixed by upstream
# rebuilding python:3.12-slim, which is not a schedule we control: the
# nightly of 2026-09-14 refused to publish the api image on 34 HIGH /
# CRITICAL findings (7 CVEs across perl, 2 libpcre2, 2 libsqlite3, 1
# gzip, 1 libssh2) whose fixes had been sitting on deb.debian.org the
# whole time. Every Alpine image in this repo has run ``apk upgrade``
# for exactly this reason; the two Debian-family ones did not.
#
# ``APT_SNAPSHOT`` is what makes that upgrade actually run in CI, and it
# is not optional decoration. BuildKit keys a layer on its RUN text, so
# the ``type=gha`` cache the nightly uses serves this whole layer —
# package set included — from whenever it was first built, until the
# text changes. That is why the same nightly also reported ``perl`` at
# 5.40.1-6 when the index had offered 5.40.1-6+deb13u1 for days: the
# layer had not executed in weeks. The nightly passes its date tag so
# the layer is rebuilt once a night against the current index
# (everything above it still caches); local builds default to ``dev``.
# Same knob, same reasoning as ``APK_SNAPSHOT`` in the Alpine images —
# see agent/supervisor/images/supervisor/Dockerfile for the full story.
ARG APT_SNAPSHOT=dev
RUN echo "apt snapshot ${APT_SNAPSHOT}" >/dev/null \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
    ca-certificates wget gnupg \
    && install -d /usr/share/postgresql-common/pgdg \
    && wget -qO /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(. /etc/os-release && echo $VERSION_CODENAME)-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libxml2 \
    libxmlsec1-openssl \
    nmap \
    tcpdump \
    iputils-ping \
    traceroute \
    mtr-tiny \
    dnsutils \
    whois \
    libcap2-bin \
    postgresql-client-16 \
    libnfs14 \
    && setcap cap_net_raw,cap_net_bind_service+eip /usr/bin/nmap \
    # issue #59 — grant tcpdump CAP_NET_RAW so the non-root app user can
    # capture (server vantage). cap_net_admin is NOT granted; we run
    # non-promiscuous by default so cap_net_raw alone suffices. Assert the
    # cap landed so a wrong binary path fails the build instead of
    # silently relying on a privileged container.
    && setcap cap_net_raw+eip /usr/bin/tcpdump \
    && getcap /usr/bin/tcpdump | grep -q cap_net_raw \
    && rm -rf /var/lib/apt/lists/*

# Non-root user. Pre-create + chown the on-volume paths so the
# matching named volumes inherit app-user ownership on first attach.
# Docker only propagates the underlying directory's mode/owner to a
# fresh volume when the path exists on the image; without these
# mkdirs the api / worker hit EACCES on the first write attempt.
#
#   /var/lib/spatiumddi/backups      — issue #117 (backup archive volume)
#   /var/lib/spatiumddi/certs        — issue #134 Phase 4b.2 (appliance TLS
#                                      cert volume, shared with the frontend
#                                      nginx container at /etc/nginx/certs)
#   /var/lib/spatiumddi/slot-images  — #170 follow-up (air-gap appliance
#                                      slot-image upload storage)
#   /var/lib/spatiumddi/pcaps        — issue #59 (packet-capture .pcap
#                                      artifacts; shared api+worker volume)
#
# The user is created BEFORE the COPYs so we can use BuildKit's
# ``--chown=app:app`` flag and avoid a trailing ``chown -R /app``
# pass — that rewrite would materialise a duplicate copy of every
# file in a new layer (~550 MB doubled). Setting ownership at COPY
# time keeps the source layer authoritative.
#
# The base image's pip is removed (#1392): nothing at runtime runs it, and
# it is not a Debian package, so ``apt-get upgrade`` can never patch it and
# every scan at default severity reports its CVEs. A production image also
# has no business carrying a package installer. The ``dev`` stage below puts
# it back with ``ensurepip``.
RUN python -m pip uninstall -y --root-user-action=ignore pip \
    && useradd --no-create-home --shell /bin/false app \
    && mkdir -p /var/lib/spatiumddi/backups /var/lib/spatiumddi/certs /var/lib/spatiumddi/slot-images /var/lib/spatiumddi/pcaps \
    && chmod 0700 /var/lib/spatiumddi/pcaps \
    && chown app:app /app \
    && chown -R app:app /var/lib/spatiumddi

COPY --from=builder /install /usr/local
COPY --chown=app:app . .

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/live')"

# --no-proxy-headers: uvicorn must NOT rewrite request.client /
# request.url.scheme from forwarding headers itself. It used to, with
# --forwarded-allow-ips=* (#626), which let any caller that reached the
# api directly choose its own address (#1221). The app's
# TrustedProxyMiddleware (app/core/request_meta.py) needs the real TCP
# peer, and applies X-Real-IP / X-Forwarded-Proto only when that peer is
# in TRUSTED_PROXY_CIDRS, so audit rows still record the end user's IP
# behind nginx rather than the nginx container's.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-proxy-headers"]


# ── Stage 3: dev (used by docker-compose.dev.yml) ─────────────────────────────
# Adds the ``[dev]`` extras (pytest + pytest-asyncio + pytest-xdist +
# pytest-cov + pytest-split) on top of the runtime stage so ``make test`` can run pytest
# inside the api container without bloating the production image. The dev
# compose's ``build.target: dev`` selects this stage.
#
# ⚠️  This is the LAST stage, so ``docker build`` with no ``--target`` lands
# HERE, not on ``runtime``. Nothing in this file can prevent that — every
# ship path must pin the stage explicitly, and all of them do:
# ``.github/workflows/release.yml`` (``target: runtime``), the appliance bake
# in ``Makefile`` (``--target runtime``), and ``trivy-scheduled.yml``. That
# was not always true: until #732 release.yml had no ``target:``, so every
# published api image shipped the test tooling below. If you append a stage
# after this one, you inherit the same trap.
#
# We install as root (the runtime stage's USER app would block site-packages
# writes), then switch back to ``app`` so the runtime CMD stays unchanged.
FROM runtime AS dev
USER root
# The runtime stage removed pip (#1392); ``--default-pip`` restores the plain
# ``pip`` command too, which ``make ci-backend-lint`` execs into this image.
RUN python -m ensurepip --default-pip \
    && python -m pip install --no-cache-dir --root-user-action=ignore \
        "pytest>=8.3.0" \
        "pytest-asyncio>=0.24.0" \
        "pytest-cov>=6.0.0" \
        "pytest-split>=0.9.0" \
        "pytest-xdist>=3.6.0"
USER app
