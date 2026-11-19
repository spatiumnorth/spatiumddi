#!/bin/sh
# Container entrypoint — delegates to the Python supervisor.
# tini is PID 1 (provided by ENTRYPOINT in the Dockerfile).
#
# Issue #183 Phase 7 simplification — the appliance is k3s-only; the
# pre-Phase-7 docker.sock gid-juggling is gone (no docker, no socket,
# no supplementary group dance). The supervisor runs as an in-cluster
# pod with a ServiceAccount + auto-mounted token; cap_net_admin for
# nftables comes from the Pod's securityContext.
#
# Two paths still need write access:
#
# * /var/lib/spatium-supervisor → identity key + cert + session token
#   + role-compose.env + role-switch-state. Chowned below.
# * /etc/nftables.d → spatium-role.nft drop-in (the only file the
#   supervisor manages there). Chown the *directory* only; existing
#   host-managed SNMP / NTP drop-ins keep their canonical ownership.
#
# Phase 7 also sources /etc/spatiumddi-host/.env so configuration the
# operator's spatium-install wizard wrote (CONTROL_PLANE_URL,
# BOOTSTRAP_PAIRING_CODE, AGENT_GROUP, …) lands in the supervisor's
# environment without a separate Secret / ConfigMap.

set -eu

mkdir -p /var/lib/spatium-supervisor
chown -R spatium:spatium /var/lib/spatium-supervisor || true

if [ -d /etc/nftables.d ]; then
    # Issue #239 — only the supervisor (spatium user) writes here.
    # 0750 keeps the group's read+traverse capability for operators
    # who run ``ls /etc/nftables.d/`` under the spatium group from
    # the host, but strips group-write. Pre-#239 used 0775 which let
    # anyone in the spatium group drop arbitrary ``.nft`` files into
    # the host firewall config dir.
    chown spatium:spatium /etc/nftables.d || true
    chmod 0750 /etc/nftables.d || true
fi

# Read the host's /etc/spatiumddi/.env (mounted at
# /etc/spatiumddi-host/.env in the pod via hostPath) and export only
# strict ``KEY=VALUE`` lines into the supervisor's environment.
# Best-effort — a fresh appliance before spatium-install completion
# has no file here yet.
#
# This MUST stay above the su-exec below: the file is 0600 root
# (GHSA-h2j9-qrg7-grfw — it holds the database password, SECRET_KEY and
# the agent PSKs), so only this root half of the entrypoint can read it.
#
# Issue #238 — the pre-fix ``set -a; . "$HOST_ENV"; set +a`` shell-
# sourced the file verbatim, executing every command-substitution
# / arithmetic-expansion inside it. A foothold that could write a
# single line like ``EVIL=$(rm -rf /var/lib/spatium-supervisor)`` to
# the operator-managed host file got immediate code execution
# inside the supervisor pod. The new loop reads the file with
# ``read -r`` (no backslash interpretation), validates each KEY
# matches the POSIX env-var-name pattern, strips at most one layer
# of surrounding quotes from the value, and ``export``s the pair
# without shell-interpretation of the value.
HOST_ENV=/etc/spatiumddi-host/.env
if [ -r "$HOST_ENV" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip blanks + comments.
        case "$line" in
            ''|'#'*) continue ;;
        esac
        # Tolerate a leading ``export `` prefix the way the dot-source
        # would. Strip it before splitting.
        case "$line" in
            'export '*) line=${line#export } ;;
        esac
        # Must contain a ``=``. Skip otherwise.
        case "$line" in
            *=*) ;;
            *) continue ;;
        esac
        key=${line%%=*}
        val=${line#*=}
        # Validate KEY shape — POSIX env-var name pattern. We use
        # ``case`` rather than a regex tool so the entrypoint stays
        # busybox-compatible.
        case "$key" in
            [A-Za-z_]) ;;                      # single-char name
            [A-Za-z_]*[!A-Za-z0-9_]*) continue ;;  # has bad char anywhere
            [A-Za-z_]*) ;;                     # multi-char, all good
            *) continue ;;
        esac
        # Strip one layer of surrounding ``"..."`` or ``'...'``.
        case "$val" in
            \"*\") val=${val#\"}; val=${val%\"} ;;
            \'*\') val=${val#\'}; val=${val%\'} ;;
        esac
        export "$key=$val"
    done < "$HOST_ENV"
fi

# Drop privileges to the unprivileged spatium user. ``su-exec spatium``
# (no ``:group`` suffix) calls initgroups() so the user's supplementary
# group set comes through. Phase 7: no docker group. The one extra group
# that matters is ``spatium-host`` (2770, baked in the Dockerfile): the
# host's release-state trigger directory is 1770 root:2770 and its k3s
# kubeconfig 0640 root:2770 (GHSA-h2j9-qrg7-grfw), so dropping the
# ``:group``-less form here would cut the supervisor off from both.
exec su-exec spatium /usr/local/bin/spatium-supervisor
