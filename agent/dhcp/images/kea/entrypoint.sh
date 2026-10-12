#!/bin/sh
# Container entrypoint — starts kea-dhcp4, kea-dhcp6, and the
# spatium-dhcp-agent. tini (PID 1) reaps zombies and forwards signals.
#
# kea-ctrl-agent was removed in #637. Kea 3.0 deprecates it (it logs
# CTRL_AGENT_IS_DEPRECATED on every start), and SpatiumDDI never used it:
# the agent talks to kea-dhcp4 / kea-dhcp6 directly over their unix control
# sockets (spatium_dhcp_agent/kea_ctrl.py — config-reload,
# status-get, statistic-get-all). Supervising a daemon nothing calls was a
# liability, not a feature: its crash-loop give-up path would be seen by the
# child-exit poll below and take the whole container down with it.
#
# kea-dhcp6 runs always-on alongside kea-dhcp4 (dual-stack): it boots
# from a minimal idle config (``interfaces: []`` + empty ``subnet6``)
# that binds nothing, so it is safe on hosts with no IPv6. Once the
# control plane ships a v6 scope, the agent's sync loop rewrites
# kea-dhcp6.conf and reloads the v6 control socket — the daemon is
# already running and just picks up the new subnets.
#
# Each Kea daemon runs under a supervise-loop so a transient crash
# (bind race against Docker/k8s networking during restart, partner
# flap, etc.) doesn't leave the container in an agent-alive /
# Kea-dead zombie state. The supervise loop:
#
#   - scrubs any stale ``*.pid`` file before each launch, because Kea
#     only removes its own PID on GRACEFUL exit — SIGKILL or hard
#     crashes leave the PID file on the tmpfs, and ``createPIDFile``
#     refuses to start with ``DHCP4_ALREADY_RUNNING``;
#   - installs SIGTERM/SIGINT traps that forward to the in-flight
#     daemon AND flip a "stopping" flag so the outer loop doesn't
#     retry during container shutdown;
#   - crash-counts only fast exits (<30s uptime) so we don't
#     eventually give up on a long-running daemon that happens to
#     die after weeks of uptime.
set -eu

: "${SPATIUM_API_URL:?SPATIUM_API_URL is required}"
: "${SPATIUM_AGENT_KEY:?SPATIUM_AGENT_KEY is required (issue #246: pairing-code exchange was removed in #170 Wave A3 — paste the long hex key directly; Application appliances receive it via the supervisor's role-compose.env automatically)}"

# Ensure state + runtime dirs are writable by the agent user.
mkdir -p /var/lib/spatium-dhcp-agent /var/lib/kea /run/kea /var/log/kea
chown -R spatium:spatium /var/lib/spatium-dhcp-agent /var/lib/kea /run/kea /var/log/kea || true
# Kea requires the control-socket parent dir to be exactly mode 0750.
# Kea 3.0 hardened this: the socket path itself must also sit under the
# compiled-in default dir (/run/kea on Alpine) or the daemon refuses to
# start outright — see the path-restriction note in the Dockerfile (#637).
chmod 0750 /run/kea

KEA_CFG="${KEA_CONFIG_PATH:-/etc/kea/kea-dhcp4.conf}"
KEA_CFG6="${KEA_CONFIG_PATH_V6:-/etc/kea/kea-dhcp6.conf}"
KEA_PID_FILE="/run/kea/kea-dhcp4.kea-dhcp4.pid"
KEA6_PID_FILE="/run/kea/kea-dhcp6.kea-dhcp6.pid"

# Top-level cleanup — scrub any leftover PID files from a prior
# container incarnation BEFORE either supervisor starts. Belt and
# suspenders: the per-iteration rm below catches in-container
# crashes, this handles the docker-compose-restart case where the
# entire container came back up with the tmpfs state intact.
rm -f "$KEA_PID_FILE" "$KEA6_PID_FILE" 2>/dev/null || true

supervise_kea() {
    STOPPING=0
    KEA_CHILD=
    # Forward SIGTERM to the live daemon AND flip the stop flag so
    # the outer loop doesn't try to restart during container
    # shutdown. ``exit 0`` here ensures the subshell goes away
    # cleanly so the parent's child-exit poll sees it.
    # shellcheck disable=SC2064
    trap 'STOPPING=1; [ -n "$KEA_CHILD" ] && kill -TERM "$KEA_CHILD" 2>/dev/null; exit 0' TERM INT
    fails=0
    while [ "$STOPPING" -eq 0 ]; do
        rm -f "$KEA_PID_FILE" 2>/dev/null || true
        start_ts=$(date +%s)
        su-exec spatium:spatium kea-dhcp4 -c "$KEA_CFG" &
        KEA_CHILD=$!
        wait "$KEA_CHILD" || true
        code=$?
        KEA_CHILD=
        [ "$STOPPING" -eq 1 ] && break
        end_ts=$(date +%s)
        runtime=$((end_ts - start_ts))
        if [ "$runtime" -ge 30 ]; then
            fails=0
        else
            fails=$((fails + 1))
        fi
        if [ "$fails" -ge 5 ]; then
            echo "kea-dhcp4 crash-looping (5x in <30s), giving up code=$code" >&2
            return "$code"
        fi
        echo "kea-dhcp4 exited code=$code after ${runtime}s, restarting (attempt $fails/5)" >&2
        sleep 2
    done
    return 0
}

supervise_kea6() {
    STOPPING=0
    KEA6_CHILD=
    # shellcheck disable=SC2064
    trap 'STOPPING=1; [ -n "$KEA6_CHILD" ] && kill -TERM "$KEA6_CHILD" 2>/dev/null; exit 0' TERM INT
    fails=0
    while [ "$STOPPING" -eq 0 ]; do
        rm -f "$KEA6_PID_FILE" 2>/dev/null || true
        start_ts=$(date +%s)
        su-exec spatium:spatium kea-dhcp6 -c "$KEA_CFG6" &
        KEA6_CHILD=$!
        wait "$KEA6_CHILD" || true
        code=$?
        KEA6_CHILD=
        [ "$STOPPING" -eq 1 ] && break
        end_ts=$(date +%s)
        runtime=$((end_ts - start_ts))
        if [ "$runtime" -ge 30 ]; then
            fails=0
        else
            fails=$((fails + 1))
        fi
        if [ "$fails" -ge 5 ]; then
            echo "kea-dhcp6 crash-looping (5x in <30s), giving up code=$code" >&2
            return "$code"
        fi
        echo "kea-dhcp6 exited code=$code after ${runtime}s, restarting (attempt $fails/5)" >&2
        sleep 2
    done
    return 0
}


# radvd (issue #524) — opt-in IPv6 Router Advertisement daemon. Only
# runs when RADVD_MANAGED=1. The python agent renders the control-plane's
# radvd.conf to $RADVD_CONFIG_PATH on each bundle apply; this loop waits
# for that file to appear (radvd refuses to boot without an interface
# stanza), then runs radvd in the foreground with a pidfile the agent
# SIGHUPs to reload on later config changes. radvd carries the
# net_raw+net_admin file caps so it works after the su-exec privilege drop.
supervise_radvd() {
    STOPPING=0
    RADVD_CHILD=
    # shellcheck disable=SC2064
    trap 'STOPPING=1; [ -n "$RADVD_CHILD" ] && kill -TERM "$RADVD_CHILD" 2>/dev/null; exit 0' TERM INT
    RADVD_CFG="${RADVD_CONFIG_PATH:-/etc/radvd/radvd.conf}"
    RADVD_PID="${RADVD_PIDFILE:-/run/radvd/radvd.pid}"
    while [ "$STOPPING" -eq 0 ]; do
        if [ ! -s "$RADVD_CFG" ]; then
            sleep 3
            continue
        fi
        rm -f "$RADVD_PID" 2>/dev/null || true
        su-exec spatium:spatium radvd -C "$RADVD_CFG" -p "$RADVD_PID" -n &
        RADVD_CHILD=$!
        wait "$RADVD_CHILD" || true
        RADVD_CHILD=
        [ "$STOPPING" -eq 1 ] && break
        echo "radvd exited, restarting in 3s" >&2
        sleep 3
    done
    return 0
}

supervise_kea &
KEA_PID=$!

supervise_kea6 &
KEA6_PID=$!


# radvd only when opted in — best-effort, not part of the container
# liveness wait (a radvd flap must not take the DHCP server down).
RADVD_PID=
if [ "${RADVD_MANAGED:-0}" = "1" ]; then
    supervise_radvd &
    RADVD_PID=$!
fi

# Forward container SIGTERM to all supervisor subshells and the
# agent. The supervisors' own traps handle the in-flight daemon.
_term() {
    # NEVER expand an unset pid to 0. `kill -TERM 0` signals the CALLER'S
    # ENTIRE PROCESS GROUP, and `trap _term TERM INT` below means that
    # re-enters this function — unbounded recursion until the shell dies of
    # stack exhaustion. The old `"${RADVD_PID:-0}"` did exactly that on every
    # default install, because radvd is only started when RADVD_MANAGED=1 and
    # the image default is 0, so RADVD_PID is empty.
    #
    # Latent until #1043: the only paths that reached _term were a clean
    # SIGTERM (where the shell is already going away) and a `wait` return that
    # the broken `wait -n` made unreachable. Making the crash path work is what
    # exposed it — measured, the container exited 139 (SIGSEGV) after ~4000
    # recursive _term calls instead of the child's status, and kea was never
    # shut down.
    for _tp in "$KEA_PID" "$KEA6_PID" "$RADVD_PID" "$AGENT_PID"; do
        [ -n "$_tp" ] || continue
        kill -TERM "$_tp" 2>/dev/null || true
    done
    return 0
}
trap _term TERM INT

# The python agent runs the opt-in scapy rogue-DHCP probe (#370) +
# passive fingerprint sniffer, which need CAP_NET_RAW to open
# AF_PACKET sockets. ``su-exec``'s setuid clears the container's
# NET_RAW on the 0→non-root privilege drop, and a python interpreter
# can't carry a file capability the way kea-dhcp4/6 do — so use
# ``setpriv`` to raise NET_RAW into the *ambient* set, which survives
# setuid + execve into the unprivileged ``spatium`` user (#383).
setpriv --reuid spatium --regid spatium --init-groups \
        --inh-caps +net_raw --ambient-caps +net_raw \
        spatium-dhcp-agent &
AGENT_PID=$!

# `set +e` from here to the end (#1036). This script runs under `set -eu`,
# and everything below exists to CAPTURE a non-zero status and then clean up —
# which is exactly what `-e` prevents. Reproduced against busybox ash: with a
# supervised child exiting 3, the `||` list returns 3, `-e` killed the script
# on that line, and `EXIT_CODE=$?`, `_term` and `exit` were ALL skipped. So a
# kea or agent CRASH — the case this supervision block exists for — tore the
# container down without terminating its siblings, while a clean SIGTERM
# (which returns 0 here) ran the cleanup perfectly. The failure path was the
# only one that skipped it.
set +e

# Exit as soon as the FIRST of the three children does (#1043).
#
# This was `wait -n "$KEA_PID" "$KEA6_PID" "$AGENT_PID" || wait …`, whose
# comment claimed busybox ash "accepts it too as of 1.30+". It accepts the
# FLAG and ignores the SEMANTICS. Measured on busybox 1.37 (alpine 3.24, the
# image's own base): with one child exiting at 0.2 s and another alive for
# 5 s, `wait -n` returned after the full 5 s — it waited for ALL of them.
#
# That is not a cosmetic difference. `supervise_kea` and `supervise_kea6` are
# restart loops that never exit on their own, so when the AGENT died the wait
# simply never returned: the container kept running with kea serving a frozen
# config and no agent in it, `kubectl get pod` reported 1/1 Running with an
# unchanged restart count, and every DHCP change made through the API was
# accepted, rendered, and silently never delivered. The trigger on the
# ddi-pg walk was #1042's post-upgrade 401 — the agent's documented
# "exit so supervisor restarts the container (→ re-bootstrap)" path — but ANY
# unhandled agent crash lands the same way. The DNS image is immune only
# because it `exec`s its agent, so the agent IS the container.
#
# `kill -0` is the portable test: ash reaps a background child on SIGCHLD
# while we sit in `sleep`, so the pid is gone from the table within a tick of
# its exit, and `wait` on an already-reaped job still yields its remembered
# status. Verified on busybox 1.37 in both directions.
#
# ALL THREE are watched, including kea-dhcp6, and that is a deliberate
# behaviour change worth knowing about: because the broken `wait -n` never
# returned, a kea-dhcp6 supervise loop that gave up (5 crashes in <30 s) used
# to be TOLERATED — v4 kept serving and the dead v6 daemon was invisible. It
# is fatal now. That restores the original intent — all three were named in
# the `wait -n` list, and radvd is deliberately excluded from it precisely
# because "a radvd flap must not take the DHCP server down" — and it matches
# this whole change's thesis: a container that restarts is visible and
# recoverable, a silently dead daemon is neither. A v6 misconfiguration now
# CrashLoopBackOffs the pod rather than quietly serving v4 only, which is the
# trade being made on purpose.
EXIT_CODE=0
while :; do
    for _pid in "$KEA_PID" "$KEA6_PID" "$AGENT_PID"; do
        kill -0 "$_pid" 2>/dev/null && continue
        wait "$_pid"
        EXIT_CODE=$?
        case "$_pid" in
            "$AGENT_PID") _who="spatium-dhcp-agent" ;;
            "$KEA_PID")   _who="kea-dhcp4 supervisor" ;;
            *)            _who="kea-dhcp6 supervisor" ;;
        esac
        echo "entrypoint: $_who (pid $_pid) exited with $EXIT_CODE —" \
             "shutting the container down so it restarts" >&2
        break 2
    done
    sleep 1
done
_term
wait
exit "$EXIT_CODE"
