#!/bin/sh
# Container entrypoint — delegates to the Python supervisor. tini is PID 1.
set -eu

: "${CONTROL_PLANE_URL:?CONTROL_PLANE_URL is required}"
: "${DNS_AGENT_KEY:?DNS_AGENT_KEY is required (issue #246: pairing-code exchange was removed in #170 Wave A3 — paste the long hex key directly; Application appliances receive it via the supervisor's role-compose.env automatically)}"

# Ensure state dir is writable by the agent user. /var/log/named is
# the rendered query-log destination; named runs unprivileged as
# spatium (see start_daemon — no `-u` flag), so the directory needs
# to be owned by that user before the daemon can open the file. The
# log file itself is created by named on first query.
# /var/cache/bind/keys is the DNSSEC key-directory (issue #49): BIND9
# auto-generates + rotates the inline-signing private keys there, so it
# must exist and be writable by the unprivileged named (spatium) user.
#
# Started as root (Docker Compose, the appliance, a plain Kubernetes pod) this
# chowns and then drops to ``spatium`` with su-exec. Started as any other uid
# (#3852 — OpenShift's restricted SCC assigns a random one, in group 0) there
# is nobody to chown to and nothing to drop: the image makes these paths group-0
# writable and the volumes arrive group-writable through fsGroup, so just run
# as the uid we were given. chown / su-exec would only fail with EPERM.
mkdir -p /var/lib/spatium-dns-agent /var/cache/bind/keys /var/log/named
if [ "$(id -u)" = "0" ]; then
    chown -R spatium:spatium /var/lib/spatium-dns-agent /var/log/named /var/cache/bind || true
fi

# Agent-controlled rndc credentials. The alpine bind package's
# /etc/bind/rndc.key lives in a directory `spatium` can't traverse,
# and BIND9's auto-generated controls channel uses an in-memory key
# that doesn't match the on-disk file (causing "bad auth" failures
# when rndc tries to authenticate). Solve both by generating our own
# rndc keypair under the agent's state dir on first boot — the agent's
# named.conf renderer adds a matching `controls { }` block keyed off
# the same name, so BIND9 and rndc agree by construction.
if [ ! -f /var/lib/spatium-dns-agent/rndc.key ]; then
    rndc-confgen -a -k spatium-rndc -A hmac-sha256 \
        -c /var/lib/spatium-dns-agent/rndc.key 2>/dev/null || true
fi
if [ -f /var/lib/spatium-dns-agent/rndc.key ]; then
    cat > /var/lib/spatium-dns-agent/rndc.conf <<'EOF'
options {
    default-server 127.0.0.1;
    default-key    "spatium-rndc";
};
include "/var/lib/spatium-dns-agent/rndc.key";
EOF
    if [ "$(id -u)" = "0" ]; then
        chown spatium:spatium \
            /var/lib/spatium-dns-agent/rndc.key \
            /var/lib/spatium-dns-agent/rndc.conf || true
    fi
    chmod 600 \
        /var/lib/spatium-dns-agent/rndc.key \
        /var/lib/spatium-dns-agent/rndc.conf || true
fi

# Supervise: agent process manages named lifecycle
if [ "$(id -u)" = "0" ]; then
    exec su-exec spatium:spatium /usr/local/bin/spatium-dns-agent
fi
exec /usr/local/bin/spatium-dns-agent
