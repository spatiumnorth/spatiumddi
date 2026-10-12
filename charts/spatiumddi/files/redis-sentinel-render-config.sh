#!/bin/sh
# render-config: write this pod's redis.conf and sentinel.conf into the data
# volume from the ConfigMap's templates (#272 Phase 3, #590, #1442).
#
# The role comes from Sentinel, not from the ordinal (#1442). Sentinel moves
# the master on its own, so after any failover it can sit on any pod. Writing
# a fixed topology here (redis-0 the master, every other pod its replica) on
# every start brought a re-created master pod back as a replica of redis-0
# while redis-0 was still ITS replica: no master, every failover aborted
# no-good-slave, the api and the workers down for good. So this pod first asks
# the sentinels it can reach which pod is the master:
#   - another pod -> start as its replica;
#   - this pod    -> start as master: nobody was promoted while it was gone,
#                    the sentinels still monitor it, and it holds the newest
#                    data;
#   - no answer   -> the whole set is starting cold: the ordinal rule, redis-0
#                    the master, the one state every pod can reach on its own.
# Peers are asked through their stable FQDNs for the master's address and its
# config epoch, and the highest epoch wins: a peer whose sentinel restarted a
# moment ago, and has not yet heard from the others, cannot outvote one that
# saw the failover. The same master goes into sentinel.conf, so this pod's
# sentinel starts out monitoring the master the others monitor.
#
# The question is retried for up to REDIS_DISCOVERY_SECONDS (60 s). Cluster DNS
# can be down for a moment exactly when a node comes back (CoreDNS moves with
# the node), and falling back to the ordinal rule on one failed lookup would
# re-create the cycle above. A cold start pays that wait once; a single
# replica asks nobody.
set -eu

TMPL_DIR="${TMPL_DIR:-/tmpl}"
DATA_DIR="${DATA_DIR:-/data}"
DOMAIN="${REDIS_CLUSTER_DOMAIN:-cluster.local}"
WAIT="${REDIS_DISCOVERY_SECONDS:-60}"
# From the ConfigMap rather than the pod's env, so a promote that grows the set
# re-renders it without rolling the pods that are already running.
REPLICAS="$(cat "$TMPL_DIR/replicas" 2>/dev/null || echo 1)"

# #590 — a pod's stable identity. ${HOSTNAME} is <sts>-<ordinal>, which the
# headless Service resolves for the pod's whole lifetime, unlike the pod IP
# that changes on every reschedule. Only dots and dashes: no sed escaping.
pod_fqdn() {
    printf '%s.%s.%s.svc.%s' "$1" "$REDIS_HEADLESS" "$REDIS_NAMESPACE" "$DOMAIN"
}
POD_FQDN="$(pod_fqdn "$HOSTNAME")"
ORDINAL_MASTER="$(pod_fqdn "${REDIS_STS}-0")"

# One peer sentinel's answer, as "<config epoch> <master address>", or nothing.
ask() {
    T=""
    if command -v timeout >/dev/null 2>&1; then T="timeout 5"; fi
    host="$($T redis-cli -h "$1" -p 26379 SENTINEL get-master-addr-by-name \
        "$REDIS_MASTER_SET" 2>/dev/null | head -n 1 || true)"
    case "$host" in
        "" | *[!A-Za-z0-9.:-]*) return 0 ;;
    esac
    epoch="$($T redis-cli -h "$1" -p 26379 SENTINEL MASTER "$REDIS_MASTER_SET" \
        2>/dev/null | awk 'prev == "config-epoch" { print; exit } { prev = $0 }' || true)"
    case "$epoch" in
        "" | *[!0-9]*) epoch=0 ;;
    esac
    printf '%s %s\n' "$epoch" "$host"
}

# The master the peers agree on (the highest config epoch), or "".
discover() {
    i=0
    while [ "$i" -lt "$REPLICAS" ]; do
        peer="${REDIS_STS}-${i}"
        if [ "$peer" != "$HOSTNAME" ]; then
            ask "$(pod_fqdn "$peer")"
        fi
        i=$((i + 1))
    done | sort -nr | awk 'NR == 1 { print $2 }'
}

MASTER=""
HOW="a single replica"
if [ "$REPLICAS" -gt 1 ]; then
    deadline=$(($(date +%s) + WAIT))
    while :; do
        MASTER="$(discover)"
        if [ -n "$MASTER" ] || [ "$(date +%s)" -ge "$deadline" ]; then
            break
        fi
        sleep 2
    done
    if [ -n "$MASTER" ]; then
        HOW="the sentinels name it"
    else
        HOW="no sentinel answered within ${WAIT}s, so the ordinal rule"
    fi
fi
if [ -z "$MASTER" ]; then
    MASTER="$ORDINAL_MASTER"
fi

PW="${REDIS_PASSWORD:-}"
# Escape sed-replacement metacharacters (\ & and the / delimiter) so a
# password containing them renders a valid auth line instead of a broken one.
# The auto-generated chart secret is alnum, but a non-appliance operator may
# BYO a password with special chars.
ESC=$(printf '%s' "$PW" | sed -e 's/[\\/&]/\\&/g')
sed -e "s/__PASSWORD__/${ESC}/g" -e "s/__POD_FQDN__/${POD_FQDN}/g" \
    "$TMPL_DIR/redis.conf.tmpl" > "$DATA_DIR/redis.conf"
sed -e "s/__PASSWORD__/${ESC}/g" -e "s/__POD_FQDN__/${POD_FQDN}/g" \
    -e "s/__MASTER_HOST__/${MASTER}/g" \
    "$TMPL_DIR/sentinel.conf.tmpl" > "$DATA_DIR/sentinel.conf"
if [ "$MASTER" = "$POD_FQDN" ]; then
    echo "render-config: ${HOSTNAME} starts as master (${HOW})"
else
    echo "replicaof ${MASTER} 6379" >> "$DATA_DIR/redis.conf"
    echo "render-config: ${HOSTNAME} starts as a replica of ${MASTER} (${HOW})"
fi
