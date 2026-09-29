# syntax=docker/dockerfile:1.7
# SpatiumDDI dnsdist front for PowerDNS Authoritative (issue #146 Phase 2).
# PowerDNS auth has no Response-Rate-Limiting equivalent, so dnsdist sits on
# :53 (in its OWN container/netns) and forwards to the pdns backend over the
# network at ${DNSDIST_BACKEND} (default dns-powerdns:53) — pdns never moves
# port. The entrypoint builds the base config from env and appends the
# operator's rate-limit rules, which the PowerDNS agent renders into a shared
# read-only volume; it rebuilds + restarts dnsdist whenever the rules change.
# Multi-arch: linux/amd64, linux/arm64 (non-negotiable #11).
FROM alpine:3.24 AS runtime

# apk upgrade before add so the layer cache can't serve a stale index that
# Trivy would then flag (mirrors the powerdns image rationale).
# ``APK_SNAPSHOT`` is what makes that upgrade actually run in CI. BuildKit
# keys a layer on its RUN text, so a ``type=gha`` cache serves this whole
# layer — package set included — from whenever it was first built, until
# the text changes. The nightly passes its date tag so the layer is
# rebuilt once a night against the current index; local builds default
# to ``dev``. Full story: agent/supervisor/images/supervisor/Dockerfile.
ARG APK_SNAPSHOT=dev
RUN echo "apk snapshot ${APK_SNAPSHOT}" >/dev/null \
    && apk upgrade --no-cache \
    && apk add --no-cache 'dnsdist>=2.0.8-r0' libcap bash tini \
    # uid/gid PINNED (#50) — must match the powerdns image, whose agent
    # writes the DoT/DoH listener key at mode 0600 into the volume this
    # container mounts read-only. See the matching note there.
    && addgroup -S -g 102 spatium \
    && adduser -S -u 101 -G spatium -h /var/lib/dnsdist spatium \
    # dnsdist binds :53 as the unprivileged spatium user.
    && setcap cap_net_bind_service=+ep /usr/sbin/dnsdist 2>/dev/null \
       || setcap cap_net_bind_service=+ep /usr/bin/dnsdist

COPY agent/dns/images/dnsdist/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# DNSDIST_BACKEND: the pdns backend address (set per deployment, e.g.
# dns-powerdns:53 on compose). DNSDIST_RULES_FILE: the agent-rendered rules,
# mounted read-only from the shared PowerDNS agent state volume.
ENV DNSDIST_BACKEND=dns-powerdns:53 \
    DNSDIST_RULES_FILE=/agent-state/dnsdist-rules.conf
USER spatium
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
