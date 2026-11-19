#!/usr/bin/env bash
# spatium-warroom.sh — §6.6 terminal `live status` fallback for the 24h perf run.
#
# One-screen, 5s-refresh war-room for SSH-from-the-couch monitoring. Run FROM THE
# MONITORING BOX (off-box) — never on the appliance under test. Deps: curl jq
# redis-cli psql kubectl. Mirrors the panels the Grafana board shows, but in a
# single terminal so you can watch a soak over a flaky link.
#
# Native field names are PINNED against surfaces.py — anything that reads a native
# JSON payload uses the exact key surfaces.py maps. The deep-DB section (locks /
# deadlocks / idle-in-txn) goes DIRECT to psql, the only path that exposes it
# (§5.4 / §6.6). Domain counts also come from psql (the §8.2.4 ledger).
#
# Placeholders you MUST set during provisioning are clearly marked PLACEHOLDER and
# default to env vars so you can export them once:
#   API_BASE        e.g. https://10.20.0.10/api   (manifest target.api_base)
#   ADMIN_TOKEN     superadmin bearer token        (env SPDDI_PERF_ADMIN_TOKEN)
#   PSQL_DSN        direct CNPG DSN (pg_monitor)    (env SPDDI_PERF_PSQL_DSN)
#   REDIS_CLI_ARGS  e.g. "-h 10.20.0.10 -a $REDISPASS"  (PLACEHOLDER — redis host/pass)
#   NAMESPACE       k8s namespace (default spatium) (for kubectl pod lookups)
#   CNPG_PRIMARY    CNPG primary pod name           (PLACEHOLDER — kubectl get pods)
#   REDIS_POD       redis/sentinel pod name         (PLACEHOLDER)
#
# Field names below are kept in lockstep with surfaces.py SHELL_EXPORTS; regenerate
# the reference with:  python3 perf/warroom/surfaces.py --dump-shell

set -uo pipefail

REFRESH="${REFRESH:-5}"
API_BASE="${API_BASE:-${SPDDI_PERF_API_BASE:-https://CHANGE-ME/api}}"   # PLACEHOLDER
ADMIN_TOKEN="${ADMIN_TOKEN:-${SPDDI_PERF_ADMIN_TOKEN:-}}"
PSQL_DSN="${PSQL_DSN:-${SPDDI_PERF_PSQL_DSN:-}}"
REDIS_CLI_ARGS="${REDIS_CLI_ARGS:-}"                                    # PLACEHOLDER e.g. "-h HOST -a PASS"
NAMESPACE="${NAMESPACE:-spatium}"
CNPG_PRIMARY="${CNPG_PRIMARY:-}"                                        # PLACEHOLDER pod name
REDIS_POD="${REDIS_POD:-}"                                              # PLACEHOLDER pod name
CURL_OPTS=(-fsS --max-time 8 -k)   # -k: self-signed appliance cert (off-box monitor)

# Celery queues (the Redis LLEN keys) — keep in sync with surfaces.CELERY_QUEUES.
CELERY_QUEUES=(ipam dns dhcp default)

# Derive /api/v1 + host-root from API_BASE the same way surfaces.api_v1_base does.
api_v1() {
  local b="${API_BASE%/}"
  case "$b" in
    */api/v1) printf '%s' "$b" ;;
    */api)    printf '%s/v1' "$b" ;;
    *)        printf '%s/api/v1' "$b" ;;
  esac
}
host_root() {
  # scheme://host  (strip path) — /health/* is mounted at root, not under /api/v1.
  printf '%s' "$API_BASE" | sed -E 's#^(https?://[^/]+).*#\1#'
}
V1="$(api_v1)"
ROOT="$(host_root)"

# ── colour helpers ────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_B=$'\033[34m'; C_DIM=$'\033[2m'; C_0=$'\033[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_DIM=""; C_0=""
fi
hr() { printf '%s\n' "────────────────────────────────────────────────────────────────────────"; }

# Authenticated GET against /api/v1. Returns body on stdout, empty on failure.
api_get() {  # $1 = path under /api/v1
  [[ -z "$ADMIN_TOKEN" ]] && { echo ""; return; }
  curl "${CURL_OPTS[@]}" -H "Authorization: Bearer ${ADMIN_TOKEN}" "${V1}$1" 2>/dev/null || echo ""
}
# GET against host-root (for /health/platform). Sends the admin token when
# set: since #2935 an anonymous caller gets the rollup status only, without
# the components[] list the platform panel draws.
root_get() {
  if [[ -n "$ADMIN_TOKEN" ]]; then
    curl "${CURL_OPTS[@]}" -H "Authorization: Bearer ${ADMIN_TOKEN}" "${ROOT}$1" 2>/dev/null || echo ""
  else
    curl "${CURL_OPTS[@]}" "${ROOT}$1" 2>/dev/null || echo ""
  fi
}

# redis-cli wrapper — prefers kubectl exec when REDIS_POD set, else direct args.
rcli() {  # passes args straight to redis-cli
  if [[ -n "$REDIS_POD" ]]; then
    kubectl -n "$NAMESPACE" exec "$REDIS_POD" -- redis-cli "$@" 2>/dev/null
  else
    # shellcheck disable=SC2086
    redis-cli $REDIS_CLI_ARGS "$@" 2>/dev/null
  fi
}
# psql wrapper — tuples-only, the ONLY path for locks/deadlocks/domain-counts.
pq() {  # $1 = SQL
  [[ -z "$PSQL_DSN" ]] && { echo ""; return; }
  psql "$PSQL_DSN" -At -F '|' -c "$1" 2>/dev/null || echo ""
}

dot() { case "$1" in ok|warn) printf '%s●%s' "$C_G" "$C_0" ;; *) printf '%s●%s' "$C_R" "$C_0" ;; esac; }

# ── panels ──────────────────────────────────────────────────────────────────

panel_platform() {
  # /health/platform → components[] {name,status}. status ok|warn = up. (surfaces.HEALTH_*)
  local j; j="$(root_get /health/platform)"
  printf '%sPLATFORM%s  ' "$C_B" "$C_0"
  if [[ -z "$j" ]]; then printf '%s(unreachable)%s\n' "$C_R" "$C_0"; return; fi
  # surfaces.HEALTH_COMPONENT_MAP keys: api postgres redis celery-workers celery-beat
  for comp in api postgres redis celery-workers celery-beat; do
    local st; st="$(echo "$j" | jq -r --arg n "$comp" '.components[]?|select(.name==$n)|.status' 2>/dev/null)"
    printf '%s %s  ' "$(dot "${st:-down}")" "$comp"
  done
  local rollup; rollup="$(echo "$j" | jq -r '.status // "?"')"
  printf '  rollup=%s' "$rollup"
  [[ "$(echo "$j" | jq -r '.maintenance_mode // false')" == "true" ]] && printf '  %sMAINTENANCE%s' "$C_Y" "$C_0"
  printf '\n'
}

panel_postgres() {
  # /admin/postgres/overview fields (surfaces.PG_FIELD_*):
  #   .active_connections .max_connections .cache_hit_ratio .wal_bytes
  #   .db_size_bytes .longest_transaction.age_seconds
  local j; j="$(api_get /admin/postgres/overview)"
  printf '%sPOSTGRES%s ' "$C_B" "$C_0"
  if [[ -z "$j" ]]; then printf '%s(no token/unreachable)%s\n' "$C_R" "$C_0"; else
    local ac mc ch sz lt
    ac="$(echo "$j" | jq -r '.active_connections // 0')"
    mc="$(echo "$j" | jq -r '.max_connections // 0')"
    ch="$(echo "$j" | jq -r '(.cache_hit_ratio // 0)*100|floor')"
    sz="$(echo "$j" | jq -r '.db_size_bytes // 0')"
    lt="$(echo "$j" | jq -r '.longest_transaction.age_seconds // 0|floor')"
    local chc="$C_G"; [[ "$ch" -lt 95 ]] && chc="$C_Y"; [[ "$ch" -lt 90 ]] && chc="$C_R"
    printf 'conns=%s/%s  cache=%s%s%%%s  longest_txn=%ss  size=%sMB\n' \
      "$ac" "$mc" "$chc" "$ch" "$C_0" "$lt" "$((sz/1024/1024))"
  fi
  # by-state (surfaces.PG_CONNS_*): /admin/postgres/connections .rows[] {state,count}
  local cj; cj="$(api_get /admin/postgres/connections)"
  if [[ -n "$cj" ]]; then
    printf '%s         by-state:%s ' "$C_DIM" "$C_0"
    echo "$cj" | jq -r '.rows[]? | "\(.state)=\(.count)"' 2>/dev/null | tr '\n' ' '
    printf '\n'
  fi
}

panel_hot_table() {
  # Hottest focus table dead/live + last-autovacuum — DIRECT psql (authoritative).
  # Mirrors psql_probe FOCUS_TABLES; sorted by dead_tup desc, top 3.
  local out
  out="$(pq "SELECT relname, n_dead_tup, n_live_tup,
                   COALESCE(EXTRACT(EPOCH FROM (now()-last_autovacuum))::int,-1)
            FROM pg_stat_user_tables
            WHERE relname = ANY(ARRAY['dhcp_lease','ip_address','dhcp_lease_history',
                  'dns_record','dns_record_op','dns_zone','dns_query_log_entry',
                  'dhcp_log_entry','audit_log','dns_server_zone_state'])
            ORDER BY n_dead_tup DESC LIMIT 3")"
  printf '%sHOT TABLES%s (dead/live · last-autovac)\n' "$C_B" "$C_0"
  if [[ -z "$out" ]]; then printf '  %s(no psql DSN)%s\n' "$C_R" "$C_0"; return; fi
  while IFS='|' read -r t dead live av; do
    [[ -z "$t" ]] && continue
    local avs="${av}s"; [[ "$av" == "-1" ]] && avs="never"
    printf '  %-22s %s/%s  %s\n' "$t" "$dead" "$live" "$avs"
  done <<< "$out"
}

panel_locks() {
  # locks_waiting / deadlocks / idle_in_txn — DIRECT psql, the ONLY path (§6.6).
  local waiting deadlocks iit
  waiting="$(pq "SELECT count(*) FROM pg_locks WHERE granted=false")"
  deadlocks="$(pq "SELECT deadlocks FROM pg_stat_database WHERE datname=current_database()")"
  iit="$(pq "SELECT count(*) FROM pg_stat_activity WHERE state='idle in transaction'")"
  printf '%sLOCKS%s ' "$C_B" "$C_0"
  if [[ -z "$PSQL_DSN" ]]; then printf '%s(no psql DSN)%s\n' "$C_R" "$C_0"; return; fi
  local wc="$C_G"; [[ "${waiting:-0}" -gt 0 ]] && wc="$C_R"
  local dc="$C_G"; [[ "${deadlocks:-0}" -gt 0 ]] && dc="$C_R"
  local ic="$C_G"; [[ "${iit:-0}" -gt 20 ]] && ic="$C_R"; [[ "${iit:-0}" -gt 10 && "${iit:-0}" -le 20 ]] && ic="$C_Y"
  printf 'waiting=%s%s%s  deadlocks=%s%s%s  idle_in_txn=%s%s%s\n' \
    "$wc" "${waiting:-?}" "$C_0" "$dc" "${deadlocks:-?}" "$C_0" "$ic" "${iit:-?}" "$C_0"
}

panel_redis() {
  # /admin/redis/overview fields (surfaces.REDIS_FIELD_*):
  #   .used_memory_bytes .maxmemory_bytes .instantaneous_ops_per_sec
  #   .keyspace_hits .keyspace_misses    (evicted_keys NOT in native — read via redis-cli)
  local j; j="$(api_get /admin/redis/overview)"
  printf '%sREDIS%s ' "$C_B" "$C_0"
  if [[ -n "$j" && "$(echo "$j" | jq -r '.available // true')" != "false" ]]; then
    local used max ops
    used="$(echo "$j" | jq -r '.used_memory_bytes // 0')"
    max="$(echo "$j" | jq -r '.maxmemory_bytes // 0')"
    ops="$(echo "$j" | jq -r '.instantaneous_ops_per_sec // 0')"
    local pct=0; [[ "${max:-0}" -gt 0 ]] && pct=$(( used*100/max ))
    local mc="$C_G"; [[ "$pct" -gt 80 ]] && mc="$C_Y"; [[ "$pct" -gt 90 ]] && mc="$C_R"
    printf 'mem=%s%sMB/%sMB (%s%%)%s ops/s=%s ' \
      "$mc" "$((used/1024/1024))" "$((max/1024/1024))" "$pct" "$C_0" "$ops"
  else
    printf '%s(no token/unavailable)%s ' "$C_R" "$C_0"
  fi
  # evicted_keys — native surface doesn't re-expose it; read INFO direct via redis-cli.
  local ev; ev="$(rcli INFO stats | tr -d '\r' | awk -F: '/^evicted_keys:/{print $2}')"
  local evc="$C_G"; [[ "${ev:-0}" -gt 0 ]] && evc="$C_R"
  printf 'evicted=%s%s%s\n' "$evc" "${ev:-?}" "$C_0"
  # Celery queue LLENs (the 4 queues; no native endpoint — §2.4).
  printf '%s      queues:%s ' "$C_DIM" "$C_0"
  for q in "${CELERY_QUEUES[@]}"; do
    local n; n="$(rcli LLEN "$q")"
    printf '%s=%s ' "$q" "${n:-?}"
  done
  printf '\n'
}

panel_funnel() {
  # Last-60s native timeseries latest bucket. surfaces.METRICS_{DNS,DHCP}_PATH.
  # DHCP DORA funnel: discover→offer→request→ack→nak. DNS: queries/noerror/nxdomain/servfail.
  local dh dn
  dh="$(api_get '/metrics/dhcp/timeseries?window=1h')"
  dn="$(api_get '/metrics/dns/timeseries?window=1h')"
  printf '%sKEA 60s%s  ' "$C_B" "$C_0"
  if [[ -n "$dh" ]]; then
    echo "$dh" | jq -r '(.points|last) as $p | if $p then
      "disc=\($p.discover) offer=\($p.offer) req=\($p.request) ack=\($p.ack) nak=\($p.nak)"
      else "(no buckets)" end' 2>/dev/null | tr -d '\n'
  else printf '%s(no token)%s' "$C_R" "$C_0"; fi
  printf '\n%sBIND 60s%s ' "$C_B" "$C_0"
  if [[ -n "$dn" ]]; then
    echo "$dn" | jq -r '(.points|last) as $p | if $p then
      "q=\($p.queries_total) noerr=\($p.noerror) nx=\($p.nxdomain) servfail=\($p.servfail)"
      else "(no buckets)" end' 2>/dev/null | tr -d '\n'
  else printf '%s(no token)%s' "$C_R" "$C_0"; fi
  printf '\n'
}

panel_counts() {
  # §8.2.4 domain-truth ledger — DIRECT psql (matches psql_probe domain_counts shape).
  printf '%sCOUNTS%s (propagation completeness + unbounded checks)\n' "$C_B" "$C_0"
  if [[ -z "$PSQL_DSN" ]]; then printf '  %s(no psql DSN)%s\n' "$C_R" "$C_0"; return; fi
  local row
  row="$(pq "SELECT
      (SELECT count(*) FROM dhcp_lease WHERE state='active'),
      (SELECT count(*) FROM ip_address WHERE auto_from_lease),
      (SELECT count(*) FROM dns_record WHERE deleted_at IS NULL),
      (SELECT count(*) FROM dns_record_op WHERE state='pending'),
      (SELECT count(*) FROM dns_record_op),
      (SELECT count(*) FROM dhcp_lease_history),
      (SELECT count(*) FROM audit_log)")"
  IFS='|' read -r al mir rec pend optot hist aud <<< "$row"
  printf '  active_leases=%s  ipam_mirror=%s  dns_records=%s\n' "${al:-?}" "${mir:-?}" "${rec:-?}"
  printf '  record_op_pending=%s  record_op_total=%s%s%s  lease_history=%s  audit_rows=%s\n' \
    "${pend:-?}" "$C_Y" "${optot:-?}" "$C_0" "${hist:-?}" "${aud:-?}"
}

render() {
  clear 2>/dev/null || true
  printf '%s SpatiumDDI war-room %s  %s  refresh=%ss  target=%s\n' \
    "$C_B" "$C_0" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$REFRESH" "$ROOT"
  hr
  panel_platform
  hr
  panel_postgres
  panel_locks
  hr
  panel_hot_table
  hr
  panel_redis
  hr
  panel_funnel
  hr
  panel_counts
  hr
  printf '%sCtrl-C to exit · placeholders: API_BASE/ADMIN_TOKEN/PSQL_DSN/REDIS_CLI_ARGS or REDIS_POD/CNPG_PRIMARY%s\n' "$C_DIM" "$C_0"
}

# ── preflight ─────────────────────────────────────────────────────────────────
for dep in curl jq; do command -v "$dep" >/dev/null 2>&1 || { echo "missing dep: $dep" >&2; exit 1; }; done
command -v redis-cli >/dev/null 2>&1 || echo "warn: redis-cli not found — queue/eviction panels degrade" >&2
command -v psql      >/dev/null 2>&1 || echo "warn: psql not found — locks/counts panels degrade" >&2
[[ "$API_BASE" == *CHANGE-ME* ]] && echo "warn: API_BASE is a placeholder — set API_BASE or SPDDI_PERF_API_BASE" >&2

if [[ "${1:-}" == "--once" ]]; then render; exit 0; fi
trap 'printf "\n"; exit 0' INT TERM
while true; do render; sleep "$REFRESH"; done
