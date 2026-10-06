# syntax=docker/dockerfile:1.7
# SpatiumDDI BGP Looking Glass collector container — receive-only GoBGP +
# spatium-lg-agent. Multi-arch: linux/amd64, linux/arm64 (non-negotiable #11)
#
# RECEIVE-ONLY SAFETY INVARIANT — see spatium_lg_agent/gobgp.py's module
# docstring for the full writeup + empirical verification notes. This
# image runs gobgpd purely as a passive collector: the rendered config's
# global default-export-policy is always "reject-route" and no
# export-policy-list is ever populated, so the daemon can receive routes
# from every configured peer but can never advertise one back.
ARG PYTHON_VERSION=3.14
ARG GOBGP_VERSION=4.10.0

FROM alpine:3.24 AS agent-build
RUN apk add --no-cache python3 py3-pip py3-wheel
WORKDIR /src
COPY agent/looking-glass/pyproject.toml /src/pyproject.toml
COPY agent/looking-glass/spatium_lg_agent /src/spatium_lg_agent
COPY agent/looking-glass/README.md /src/README.md
RUN python3 -m pip install --prefix=/install --no-cache-dir --break-system-packages .

# ── GoBGP binaries — built from source ──────────────────────────────────
# GoBGP ships no apk/apt package, and its prebuilt release binaries are
# compiled with whatever Go toolchain upstream had at release time — so the
# embedded ``stdlib`` carries every Go CVE disclosed AFTER that build (Trivy
# scans the Go version baked into the binary and fails HIGH/CRITICAL). We
# therefore build gobgp/gobgpd from the pinned source tag with the CURRENT Go
# toolchain, which keeps the embedded stdlib on the latest patch (CVE-clean)
# independent of GoBGP's own release cadence. gobgp/gobgpd are pure-Go, so
# CGO_ENABLED=0 yields fully static binaries that drop straight into the
# Alpine (musl) runtime with no shims.
#
# ``--platform=$BUILDPLATFORM`` + GOOS/GOARCH from the buildx TARGET* args
# cross-compiles with the native toolchain (fast, no QEMU) for both
# linux/amd64 + linux/arm64. Bump GOBGP_VERSION (a git tag from
# https://github.com/osrg/gobgp/tags) + the golang base image together; the
# repo's committed go.sum verifies every module checksum during the build.
#
# The Go toolchain version is a SECURITY pin, not just a build detail: Go links
# its standard library statically into the binary, so a stdlib CVE ships inside
# ``gobgpd`` itself and Trivy flags it against the ``gobinary`` target — there is
# no separate package to patch and no ``apk upgrade`` that can fix it. The only
# remedy is to rebuild with a fixed toolchain.
#
# The 1.26.4 → 1.26.5 bump cleared CVE-2026-39822 (HIGH — ``os.Root`` symlink
# following allows directory traversal). Keep this at the latest 1.26.x.
#
# Stated in the PAST tense on purpose: Dependabot bumps the ``FROM`` line but
# cannot touch this comment, so any wording that names the CURRENT pin goes
# stale on the very next bump — which is exactly what happened at 1.26.6.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS gobgp-build
ARG GOBGP_VERSION
ARG TARGETOS
ARG TARGETARCH
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --depth 1 --branch "v${GOBGP_VERSION}" https://github.com/osrg/gobgp .
# Bump vulnerable transitive deps above the versions gobgp pins so Trivy
# (HIGH/CRITICAL) stays green. The CVEs such overrides clear: golang.org/x/net below
# 0.55 carries several HIGH (html XSS, IDNA punycode privilege escalation,
# HTTP/2 DoS); x/text below 0.39 carries CVE-2026-56852 (norm.Iter infinite
# loop); grpc-go below 1.82.1 carries GHSA-hrxh-6v49-42gf (xDS RBAC +
# HTTP/2), 1.83.0 carries CVE-2026-84304 (HIGH, fixed in 1.83.1) and
# 1.83.1 carries CVE-2026-84445 (HIGH, xDS server DoS, fixed in 1.83.2).
#
# That last one was caught by CI on #1037, not locally: touching a
# Dockerfile is what makes CI scan the image, so the PR inherits every
# CVE published since the last time anything touched it. A local
# `make trivy` against a stale DB reported clean an hour earlier.
#
# These three are NOT independent, and `go get` REFUSES a mismatched set
# rather than resolving it — so raising one drags the others and the build
# says exactly which. Bumping grpc alone to clear CVE-2026-84445 took two
# more rounds: grpc 1.83.2 wanted x/net 0.58.0, then both wanted x/text
# 0.41.0. That is a feature — the failure is loud and at build time — but
# budget for it, and re-run `make trivy IMAGE=looking-glass` after, since
# the versions you end up on are not the ones you set out to pin.
#
# EVERY ONE OF THESE MUST BE AN UPGRADE, NEVER A DOWNGRADE. ``go get pkg@vX``
# sets exactly that version, so once GoBGP's own go.mod moves past one of
# these the line silently pulls the dependency BACKWARDS — reintroducing the
# CVE it was added to clear, while the build stays green and the comment
# still says it is a fix. Check upstream's go.mod on every GOBGP_VERSION bump
# and drop or raise each pin. Deliberately written without naming the pinned
# GoBGP version: a comment naming the pinned release goes stale on
# the next bump and then asserts something false (#975 found it had).
#
# At v4.10.0 upstream pins x/net v0.58.0 (indirect), x/text v0.41.0 and
# grpc v1.83.2 — exactly the versions the overrides used to force — so
# there are no `go get` override lines right now: the build takes
# upstream's go.mod as-is. Reinstate an override only when upstream
# lags a CVE fix again, and only as a strict upgrade per the rule above.
#
# Dependabot does not see these: they are `go get` arguments in a Dockerfile,
# not a tracked manifest, which is why they live in versions.json's orbit and
# why `make trivy IMAGE=looking-glass` is what surfaces the next one.
ENV CGO_ENABLED=0
RUN GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH}" \
      go build -trimpath -ldflags="-s -w" -o /out/gobgpd ./cmd/gobgpd \
 && GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH}" \
      go build -trimpath -ldflags="-s -w" -o /out/gobgp ./cmd/gobgp

FROM alpine:3.24 AS runtime
# Re-declared (no value) so the global GOBGP_VERSION pin is in scope in
# this stage — without it the /etc/spatiumddi-versions write below
# expands it to empty and the image reports `gobgp=`.
ARG GOBGP_VERSION
# ``libcap`` brings in ``setcap`` so gobgpd can bind BGP's privileged
# TCP/179 as the unprivileged ``spatium`` user (same pattern as
# kea-dhcp4/6 + named/pdns_server in the DHCP/DNS images — a
# container-level ``cap_add``/``securityContext.capabilities.add`` only
# sets the bounding set, which su-exec's setuid drops on the privilege
# drop; the capability has to live on the binary as a file cap to
# survive it).
#
# ``apk upgrade --no-cache`` runs BEFORE ``apk add`` so the package
# database is fresh and any previously-baked layer carrying an older
# libssl/libcrypto (or other base) version gets re-resolved against the
# current alpine 3.22 index rather than serving a stale GitHub Actions
# layer cache that Trivy would then flag.
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
      tini su-exec \
      python3 py3-pip \
      libcap \
      ca-certificates tzdata \
 && addgroup -S spatium \
 && adduser -S -G spatium spatium \
 && mkdir -p /var/lib/spatium-lg-agent /etc/gobgp \
 && chown -R spatium:spatium /var/lib/spatium-lg-agent /etc/gobgp

COPY --from=agent-build /install /usr/local
COPY --from=gobgp-build /out/gobgp /usr/local/bin/gobgp
COPY --from=gobgp-build /out/gobgpd /usr/local/bin/gobgpd
RUN setcap cap_net_bind_service=+ep /usr/local/bin/gobgpd
COPY agent/looking-glass/images/gobgp/gobgpd-idle.json /etc/gobgp/gobgpd.json
COPY agent/looking-glass/images/gobgp/entrypoint.sh /usr/local/bin/spatium-lg-entrypoint
RUN chmod +x /usr/local/bin/spatium-lg-entrypoint \
 && chown spatium:spatium /etc/gobgp/gobgpd.json \
 && { \
      echo "alpine_release=$(cat /etc/alpine-release)"; \
      echo "gobgp=${GOBGP_VERSION}"; \
    } > /etc/spatiumddi-versions

ARG PYTHON_VERSION
ENV AGENT_STATE_DIR=/var/lib/spatium-lg-agent \
    GOBGPD_CONFIG_PATH=/etc/gobgp/gobgpd.json \
    GOBGPD_BIN=/usr/local/bin/gobgpd \
    GOBGP_BIN=/usr/local/bin/gobgp \
    GOBGP_GRPC_HOST=127.0.0.1 \
    GOBGP_GRPC_PORT=50051 \
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
RUN python3 -c "import spatium_lg_agent"


VOLUME ["/var/lib/spatium-lg-agent"]
# BGP (receive-only — see spatium_lg_agent/gobgp.py's module docstring)
EXPOSE 179/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD /usr/local/bin/gobgp -u 127.0.0.1 -p 50051 -j neighbor >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/spatium-lg-entrypoint"]

# #1182 — the version the agent reports: the release tag from release.yml,
# the nightly stamp from nightly.yml. A build that passes nothing reports
# "dev". Last, so a new version only rebuilds this layer.
ARG APP_VERSION=dev
ENV SPATIUM_AGENT_VERSION=${APP_VERSION}
