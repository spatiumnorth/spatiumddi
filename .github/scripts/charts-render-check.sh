#!/usr/bin/env bash
#
# Lint, render and schema-check the Helm charts (#966, #983).
#
# Until this existed nothing on a PR parsed the charts at all: the one
# PR-time helm job (agent-e2e) is path-filtered to charts/spatiumddi/** and
# installs only the umbrella chart, so charts/spatiumddi-appliance/ was first
# read by helm during ``release.yml``'s ``helm package`` — a template that
# failed to render broke the release, not the PR that introduced it. And no
# job ran ``helm lint`` for either chart.
#
# Three gates per render, each catching what the previous cannot:
#
#   helm lint        — template syntax, values schema, chart metadata.
#   helm template    — the render itself, with the role / feature toggles
#                      flipped ON, because a template that only renders at
#                      defaults has not been rendered (every appliance role
#                      is ``enabled: false`` by default).
#   kubeconform      — the rendered objects against the Kubernetes API
#                      schemas, -strict so an unknown field (a key indented
#                      under the wrong parent, the classic helm mistake) is
#                      an error rather than something the apiserver would
#                      silently drop. CRDs (the CNPG ``Cluster``) resolve
#                      through the datreeio CRDs-catalog.
#   no-besteffort    — every render: each serving container must carry a
#                      CPU + memory request or limit (#965). A ``with`` guard
#                      that tests the wrong values path renders no
#                      ``resources:`` block and passes the three gates above.
#   pod-posture      — every render: each pod template carries a seccomp
#                      profile, every init container declares resources
#                      (#3208), and (where the render opts in) a
#                      PriorityClass (#983). Same failure mode as the line
#                      above — a workload added without either one runs
#                      perfectly well, just unprotected and unranked.
#   toggle-coverage  — every ``.Values.x.enabled`` / ``.kind`` a template is
#                      gated on must be flipped by at least one render, so a
#                      new gate cannot silently fall out of the matrix.
#   no-external-kea-ha — every render, plus the raw ``k8s/dhcp`` manifests: no
#                      NodePort / LoadBalancer Service in front of a DHCP agent
#                      publishes TCP 8000, Kea's unauthenticated HA listener.
#   dhcp-readiness   — every render, plus a dedicated pass over the umbrella
#                      posture render and the raw manifests: no DHCP agent
#                      readiness probe gates on that same HA listener
#                      (#1589) — a standalone Kea server never binds it, so
#                      the pod would never become Ready.
#   dns-agent-service — every render: a DNS agent LoadBalancer Service keeps
#                      the client address (``externalTrafficPolicy: Local``,
#                      #1548), plus one dedicated render asserting the
#                      ``server.service`` fields (VIP, source ranges, IP
#                      family policy, annotations) reach the Service, and
#                      negative controls for encrypted-transport ports a
#                      flavor cannot serve (#1553).
#   slot-image-mirror — every render: the mirror runs the api's image and
#                      imports the whole application, so its memory and CPU
#                      limits must each be at least the api's (#1174). Below
#                      the api it is OOMKilled before it serves a byte, and
#                      helm, kubeconform and the posture gates all pass it.
#   rollout-strategy — every render: a Deployment with required pod
#                      anti-affinity must retire an old pod first, or its
#                      rollout wedges once replicas == nodes (#590); plus a
#                      dedicated pass asserting the appliance's api / worker /
#                      frontend retire first at one replica too, where the
#                      blocking term rides on the OUTGOING pods (#1541).
#   hpa-replicas     — every render, plus --require passes, a control and
#                      negative controls: a workload an autoscaler scales
#                      renders no ``spec.replicas`` (#3111), while the
#                      appliance's api (autoscaler off) keeps its count. Helm
#                      4 applies server-side, so a rendered count made helm an
#                      owner of the field the autoscaler writes, and every
#                      ``helm upgrade`` failed on it once the autoscaler had
#                      scaled.
#   footprint        — dedicated pass over the default render, an opt-in
#                      render and negative controls: the api autoscaler aims at
#                      least at one api pod's measured use and scales on CPU
#                      alone unless memory is asked for, and the api's request
#                      and the api and worker limits hold what they were
#                      measured to use (#3110). At 80 % of the old 256Mi
#                      request one idle api process sat above the memory
#                      target, and every default install ran 10 replicas.
#   template-stable  — dedicated pass over the appliance renders at one replica
#                      and at three: the frontend's pod template must be the
#                      same in both (#2450). The first promotion only raises
#                      its replicas, and on the appliance a template change
#                      rolls the seed's one frontend pod, which holds the
#                      node's ports 80 and 443, before its replacement can
#                      start: the seed refuses connections mid-promotion.
#   shared-env       — dedicated umbrella render: api, worker and beat all carry
#                      every variable in ``sharedEnv``, and APPLIANCE_VERSION
#                      from ``applianceVersion`` (#2176); api and worker carry
#                      the slot-image mirror URL / secret, beat and the mirror
#                      itself do not (#1826).
#                      The appliance's APPLIANCE_MODE reached only the api, so
#                      the worker that runs alert evaluation saw it unset.
#   dns-startup-probe — every render, plus a --require pass over the umbrella
#                      and appliance DNS renders and a negative control: a DNS
#                      container whose liveness probe checks :53 carries a
#                      startup probe of at least 30 min (#2223), or a cold
#                      start at scale is killed before the daemon listens.
#   cnpg-recovery    — every render, plus --require passes and negative
#                      controls: each CNPG Cluster sets max_slot_wal_keep_size
#                      and bounds pg_wal at half its volume (#2317), one with
#                      replicas updates its primary by switchover while a
#                      single instance renders no method at all (#2831),
#                      every Cluster bounds its smart shutdown, one instance
#                      included (#2878), and the supervisor's namespace Role
#                      grants what its re-clone of a stuck instance needs,
#                      pods/log get + pods patch (#2132).
#   cnpg-node-local  — dedicated umbrella render with the appliance's CNPG
#                      values, a --require pass over it and over the HA render,
#                      and negative controls: the appliance's instance pods take
#                      the API server from their own node (``status.hostIP``,
#                      port 6443) and the umbrella default sets neither
#                      variable (#3021). A primary whose API connection landed
#                      on a lost node was restarted by its own liveness probe.
#   bind9 memory     — the appliance dns-bind9 container takes its memory from
#                      ``dnsBind9.memory`` (sized from node RAM by the
#                      supervisor, #2223) and an explicit memory in
#                      ``dnsBind9.resources`` wins over it.
#
# Runs anywhere helm + kubeconform + python3 (with PyYAML) are on PATH; the
# CI job and ``make charts-lint`` both call it. Rendered manifests are left
# in $OUT for inspection.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${OUT:-$(mktemp -d)}"
K8S_VERSION="${K8S_VERSION:-1.36.0}"
# Group/kind/version-templated so any CRD in the catalog resolves; the one
# we render today is postgresql.cnpg.io/Cluster.
CRD_SCHEMAS='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'

UMBRELLA="$ROOT/charts/spatiumddi"
APPLIANCE="$ROOT/charts/spatiumddi-appliance"
METALLB="$ROOT/charts/spatiumddi-metallb"

for tool in helm kubeconform python3; do
    command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done

failures=0

lint() { # chart [helm --set args...]
    local chart="$1"; shift
    echo "── helm lint $(basename "$chart") $*"
    helm lint --strict "$chart" "$@" || failures=$((failures + 1))
}

# kubeconform caches fetched schemas only in memory, per invocation; six
# invocations would fetch every kind's schema six times from GitHub raw. A
# disk cache makes renders 2-6 free, and CI persists it across runs.
KUBECONFORM_CACHE="${KUBECONFORM_CACHE:-$OUT/.schema-cache}"
mkdir -p "$KUBECONFORM_CACHE"

# Extra flags handed to chart-pod-posture.py, set per render group below.
# Word-split on purpose (simple flags only).
POSTURE_ARGS=""

render() { # name chart [helm --set args...]
    local name="$1" chart="$2"; shift 2
    local file="$OUT/$name.yaml"
    echo "── helm template $name ($(basename "$chart")) $*"
    if ! helm template "$name" "$chart" --kube-version "$K8S_VERSION" "$@" > "$file"; then
        failures=$((failures + 1)); return
    fi
    echo "   $(grep -c '^kind:' "$file") objects → $file"
    # CustomResourceDefinition is skipped: the only CRDs rendered are the
    # CNPG operator's, vendored from upstream via the subchart — not ours to
    # validate, and the upstream schema set carries no strict variant for
    # the kind. Every CR *instance* (the ``Cluster``) is still checked.
    kubeconform -strict -summary \
        -kubernetes-version "$K8S_VERSION" \
        -schema-location default \
        -schema-location "$CRD_SCHEMAS" \
        -skip CustomResourceDefinition \
        -cache "$KUBECONFORM_CACHE" \
        "$file" || failures=$((failures + 1))
    python3 "$ROOT/.github/scripts/chart-no-besteffort.py" "$file" || failures=$((failures + 1))
    # #1042 — a generated credential Secret must carry resource-policy: keep,
    # checked on the RENDER so a value typo or a false condition cannot hide it.
    python3 "$ROOT/.github/scripts/chart-credential-secrets-kept.py" "$file" \
        || failures=$((failures + 1))
    # shellcheck disable=SC2086  # POSTURE_ARGS is a deliberate flag list
    python3 "$ROOT/.github/scripts/chart-pod-posture.py" $POSTURE_ARGS "$file" \
        || failures=$((failures + 1))
    python3 "$ROOT/.github/scripts/chart-no-external-kea-ha.py" "$file" \
        || failures=$((failures + 1))
    # #1589 — no DHCP agent readiness probe may gate on the Kea HA
    # listener (TCP 8000): a standalone server never binds it.
    python3 "$ROOT/.github/scripts/chart-dhcp-readiness.py" "$file" \
        || failures=$((failures + 1))
    # #1550 — MetalLB VIP Services must not allocate NodePorts.
    python3 "$ROOT/.github/scripts/chart-vip-nodeports.py" "$file" \
        || failures=$((failures + 1))
    # #1548 — a DNS agent LoadBalancer Service must keep the client
    # address (externalTrafficPolicy: Local); see the script's docstring.
    python3 "$ROOT/.github/scripts/chart-dns-agent-service.py" "$file" \
        || failures=$((failures + 1))
    # #1725 — a BIND9 agent container must carry a memory limit.
    python3 "$ROOT/.github/scripts/chart-dns-memory-limit.py" "$file" \
        || failures=$((failures + 1))
    # #2223 — a DNS container's liveness probe must wait for a startup probe.
    python3 "$ROOT/.github/scripts/chart-dns-startup-probe.py" "$file" \
        || failures=$((failures + 1))
    # #1510 — no two Services may ask MetalLB for the same address; only the
    # one created first would get it.
    python3 "$ROOT/.github/scripts/chart-lb-address-single-owner.py" "$file" \
        || failures=$((failures + 1))
    # A MetalLB VIP must keep the client's source address (the DNS VIP's
    # rate limits, query logs and RPZ hits are all per client). The DHCP
    # relay VIP is exempt: Kea answers the relay at giaddr, so the packet's
    # source address is never used.
    python3 "$ROOT/.github/scripts/chart-vip-client-ip.py" --allow dhcp-kea-relay "$file" \
        || failures=$((failures + 1))
    python3 "$ROOT/.github/scripts/chart-slot-image-mirror.py" "$file" \
        || failures=$((failures + 1))
    # #2955 — the api / worker / beat pools must fit max_connections.
    python3 "$ROOT/.github/scripts/chart-postgres-connections.py" "$file" \
        || failures=$((failures + 1))
    # #2317 / #2132 — CNPG WAL bounded at half its volume; the supervisor may
    # re-clone a stuck instance.
    python3 "$ROOT/.github/scripts/chart-cnpg-recovery.py" "$file" \
        || failures=$((failures + 1))
    # #590 / #1541 — required anti-affinity with a surge-first rollout
    # wedges once replicas == nodes.
    python3 "$ROOT/.github/scripts/chart-rollout-strategy.py" "$file" \
        || failures=$((failures + 1))
    # #3111 — an autoscaled workload must leave spec.replicas to the
    # autoscaler, or helm upgrade fails on it under server-side apply.
    python3 "$ROOT/.github/scripts/chart-hpa-replicas.py" "$file" \
        || failures=$((failures + 1))
}

coverage() { # chart [every --set arg from every render of that chart...]
    local chart="$1"; shift
    echo "── toggle coverage $(basename "$chart")"
    python3 "$ROOT/.github/scripts/chart-toggle-coverage.py" "$chart" "$@" || failures=$((failures + 1))
}

# Subcharts. The umbrella has none today; the appliance vendors CNPG (#272)
# and this is the first time the dependency resolves before release.
helm dependency update "$UMBRELLA"
helm dependency update "$APPLIANCE"
helm dependency update "$METALLB"

# ── Umbrella chart ──────────────────────────────────────────────────────────
# Every template gate on: the agents, ingress, the slot-image mirror, HPA, the
# three RBAC toggles + service control + appliance host mounts, frontend TLS,
# Redis auth. ``chart-toggle-coverage.py`` fails this script if a template
# grows a gate that no set below flips.
UMBRELLA_ALL_ON=(
    --set dnsAgents.enabled=true
    --set dhcpAgents.enabled=true
    --set ingress.enabled=true
    --set slotImageMirror.enabled=true
    --set api.autoscaling.enabled=true
    --set api.serviceAccount.enabled=true
    --set worker.serviceAccount.enabled=true
    --set api.serviceControl.enabled=true
    --set api.serviceControlRBAC.enabled=true
    --set api.upgradeOrchestratorRBAC.enabled=true
    --set api.applianceHostMounts.enabled=true
    --set frontend.tls.enabled=true
    --set redis.auth.enabled=true
)
# The HA topology docs/deployment/KUBERNETES.md points operators at: a
# CloudNativePG ``Cluster`` CR (the one CRD instance either chart renders —
# the datreeio schema location exists for it) + Redis Sentinel, with CNPG
# backups on.
UMBRELLA_HA=(
    --set postgresql.kind=cnpg
    --set postgresql.cnpg.backup.enabled=true
    --set postgresql.cnpg.caPublisher.enabled=true
    --set redis.kind=sentinel
)
# #2873 — HA topology with Redis auth ON: the Sentinel config must require the
# password the clients send. Neither set above flips both together.
UMBRELLA_HA_AUTH=(
    "${UMBRELLA_HA[@]}"
    --set redis.auth.enabled=true
)
UMBRELLA_EXTERNAL=(
    --set postgresql.enabled=false --set externalDatabase.host=pg.example
    --set redis.enabled=false --set externalRedis.host=redis.example
)
# #983 — the appliance overlay's shape: both PriorityClass knobs set, and
# every optional workload on, so the posture gate sees each one wired. Agent
# StatefulSets only render when ``servers`` is non-empty, so the ``enabled``
# toggle alone leaves those two templates unrendered — name a server.
UMBRELLA_POSTURE=(
    "${UMBRELLA_ALL_ON[@]}"
    --set global.priorityClassName=spatium-control-plane
    --set global.servicePriorityClassName=spatium-service
    --set dnsAgents.servers[0].name=ns1
    --set dhcpAgents.servers[0].name=dhcp1
)

lint "$UMBRELLA"
lint "$UMBRELLA" "${UMBRELLA_ALL_ON[@]}"
lint "$UMBRELLA" "${UMBRELLA_HA[@]}"
lint "$UMBRELLA" "${UMBRELLA_HA_AUTH[@]}"
render umbrella-defaults "$UMBRELLA"
render umbrella-all-on "$UMBRELLA" "${UMBRELLA_ALL_ON[@]}"
render umbrella-ha "$UMBRELLA" "${UMBRELLA_HA[@]}"
render umbrella-ha-auth "$UMBRELLA" "${UMBRELLA_HA_AUTH[@]}"
# #2873 — the Sentinel set must carry requirepass + sentinel-pass in the same
# render whose clients are handed REDIS_SENTINEL_PASSWORD.
python3 - "$OUT/umbrella-ha-auth.yaml" <<'PYEOF' || failures=$((failures + 1))
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
tmpl = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("redis-sentinel-tmpl"))
conf = tmpl["data"]["sentinel.conf.tmpl"]
need = ["requirepass __PASSWORD__", "sentinel sentinel-pass __PASSWORD__", "sentinel auth-pass"]
missing = [n for n in need if n not in conf]
if missing:
    print("FAIL #2873: sentinel.conf.tmpl lacks", missing)
    sys.exit(1)
print("ok #2873: sentinel.conf.tmpl requires the password")
PYEOF
# Bring-your-own database + Redis: the shape k8s/ha/ installs use.
render umbrella-external-db "$UMBRELLA" "${UMBRELLA_EXTERNAL[@]}"
# #1174 — the shape the slot-image mirror actually runs in: an appliance
# whose control plane has more than one node, where the supervisor turns the
# mirror on and sizes the api from the node's RAM (``control_plane_resources``
# writes ``api.resources.limits.memory``: 2949Mi on an 8 GiB node). The mirror
# runs the api's image, so that sizing has to reach it as well.
render umbrella-appliance-mirror "$UMBRELLA" \
    --set slotImageMirror.enabled=true \
    --set api.resources.limits.memory=2949Mi
# #1541 — the appliance control plane's own values (``hard`` anti-affinity,
# which the supervisor writes on every install) at one replica and at three.
# #1805 — and the api Service's PreferSameNode, which firstboot renders and
# the supervisor writes on every install too; the umbrella default is "".
# One replica renders no anti-affinity of its own, but the pods a 3 → 1
# demote replaces still carry the 3-node required term, which keeps a
# surged pod off the only node for good — so api and worker must retire
# first at one replica as well as at three.
# #3111 — and the api autoscaler off, as firstboot renders it: the appliance's
# api count is its control-plane size (``api.replicas``), which helm sets.
APPLIANCE_CP_HARD=(
    --set api.podAntiAffinity=hard
    --set worker.podAntiAffinity=hard
    --set frontend.podAntiAffinity=hard
    --set frontend.hostNetwork=true
    --set api.service.trafficDistribution=PreferSameNode
    --set api.autoscaling.enabled=false
)
for n in 1 3; do
    render "umbrella-appliance-cp-$n" "$UMBRELLA" "${APPLIANCE_CP_HARD[@]}" \
        --set api.replicas=$n --set worker.replicas=$n --set frontend.replicas=$n
    echo "── rollout strategy at $n replica(s) (umbrella, #1541)"
    python3 "$ROOT/.github/scripts/chart-rollout-strategy.py" \
        --retire-first api --retire-first worker --retire-first frontend \
        "$OUT/umbrella-appliance-cp-$n.yaml" || failures=$((failures + 1))
done

# #1805 — the api Service's PreferSameNode is the appliance's, not the
# umbrella default's. The default render (a BYO-Kubernetes install) must omit
# the field, as before #1805. The appliance's values must carry it, at one
# replica and at three. A render below Kubernetes 1.34 must omit it even with
# the appliance's values, because the API server refuses the value there.
# --require on each, so none can pass by rendering no api Service at all.
echo "── api Service trafficDistribution: off by default, PreferSameNode on the appliance (umbrella, #1805)"
python3 "$ROOT/.github/scripts/chart-api-node-local.py" --require --absent \
    "$OUT/umbrella-defaults.yaml" || failures=$((failures + 1))
python3 "$ROOT/.github/scripts/chart-api-node-local.py" --require \
    "$OUT/umbrella-appliance-cp-1.yaml" "$OUT/umbrella-appliance-cp-3.yaml" \
    || failures=$((failures + 1))
if helm template umbrella-k8s-133 "$UMBRELLA" --kube-version 1.33.0 \
        "${APPLIANCE_CP_HARD[@]}" > "$OUT/umbrella-k8s-133.yaml"; then
    python3 "$ROOT/.github/scripts/chart-api-node-local.py" --require --absent \
        "$OUT/umbrella-k8s-133.yaml" || failures=$((failures + 1))
else
    echo "   FAIL: umbrella chart did not render at Kubernetes 1.33" >&2
    failures=$((failures + 1))
fi
# Negative controls: each guard must refuse the other's render, naming #1805,
# or the checks above could be passing on renders they cannot read.
echo "── negative controls: the #1805 guard must refuse each wrong render"
neg1805() { # label manifest [chart-api-node-local.py flags...]
    local label="$1" file="$2"; shift 2
    local out rc
    out="$(python3 "$ROOT/.github/scripts/chart-api-node-local.py" "$@" "$file" 2>&1)" \
        && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "#1805"; then
        echo "   ok: $label refused by the #1805 guard"
    else
        echo "   FAIL: expected the #1805 guard to refuse $label (rc=$rc)" >&2
        printf '%s\n' "$out" | tail -5 >&2
        failures=$((failures + 1))
    fi
}
neg1805 "the default render read as the appliance's" "$OUT/umbrella-defaults.yaml" --require
neg1805 "an appliance render read as the default" "$OUT/umbrella-appliance-cp-3.yaml" \
    --require --absent

# #3111 — the autoscaler alone sets the api's replica count. The default render
# (a BYO-Kubernetes install, autoscaler on) and the all-on render must leave
# ``spec.replicas`` off the api Deployment; the appliance's values turn the
# autoscaler off, and there helm keeps rendering ``api.replicas``, at one
# replica and at three. --require so no pass can succeed by rendering no
# autoscaler at all.
echo "── api replicas: the autoscaler's while it is on, api.replicas while it is off (umbrella, #3111)"
python3 "$ROOT/.github/scripts/chart-hpa-replicas.py" --require \
    "$OUT/umbrella-defaults.yaml" "$OUT/umbrella-all-on.yaml" || failures=$((failures + 1))
for n in 1 3; do
    python3 "$ROOT/.github/scripts/chart-hpa-replicas.py" --replicas "api=$n" \
        "$OUT/umbrella-appliance-cp-$n.yaml" || failures=$((failures + 1))
done
# Negative controls: the default render as it was before #3111 (``replicas: 2``
# beside the autoscaler) and an appliance api that lost its count must each be
# refused, naming #3111, or the passes above could be reading renders they
# cannot parse.
echo "── negative controls: the #3111 guard must refuse each wrong render"
api_replicas() { # source-render out-file set|drop
    python3 - "$@" <<'PYEOF'
import sys, yaml
src, dst, how = sys.argv[1:4]
docs = [d for d in yaml.safe_load_all(open(src)) if d]
for d in docs:
    if d.get("kind") == "Deployment" and d["metadata"]["labels"].get("app.kubernetes.io/component") == "api":
        if how == "set":
            d["spec"]["replicas"] = 2
        else:
            d["spec"].pop("replicas", None)
with open(dst, "w") as fh:
    yaml.safe_dump_all(docs, fh)
PYEOF
}
neg3111() { # label manifest [chart-hpa-replicas.py flags...]
    local label="$1" file="$2"; shift 2
    local out rc
    out="$(python3 "$ROOT/.github/scripts/chart-hpa-replicas.py" "$@" "$file" 2>&1)" \
        && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "#3111"; then
        echo "   ok: $label refused by the #3111 guard"
    else
        echo "   FAIL: expected the #3111 guard to refuse $label (rc=$rc)" >&2
        printf '%s\n' "$out" | tail -5 >&2
        failures=$((failures + 1))
    fi
}
api_replicas "$OUT/umbrella-defaults.yaml" "$OUT/neg-hpa-replicas-set.yaml" set
api_replicas "$OUT/umbrella-appliance-cp-3.yaml" "$OUT/neg-hpa-replicas-dropped.yaml" drop
neg3111 "an autoscaled api rendering replicas: 2" "$OUT/neg-hpa-replicas-set.yaml" --require
neg3111 "an appliance api without its count" "$OUT/neg-hpa-replicas-dropped.yaml" --replicas api=3

# #3110 — the chart's default sizing holds what the api and the worker were
# measured to use (docs/deployment/SIZING.md, Kubernetes): the api autoscaler
# aims at least at one api pod's use at rest and under light load, and by
# default scales on CPU alone (memory is opt-in); the api's memory request
# holds its working set; the api and worker limits leave the sizing guide's
# headroom. On the default render only: the appliance sizes the limits from
# the node's RAM. --require so the pass cannot succeed on a render with no api.
echo "── api and worker sizing hold their measured use (umbrella, #3110)"
python3 "$ROOT/.github/scripts/chart-control-plane-footprint.py" --require \
    --expect-metrics cpu "$OUT/umbrella-defaults.yaml" || failures=$((failures + 1))
# The opt-in memory metric renders, and at the 512Mi request 80 % aims above
# that use.
helm template hpa-memory "$UMBRELLA" --kube-version "$K8S_VERSION" \
    --set api.autoscaling.targetMemoryUtilizationPercentage=80 \
    | python3 "$ROOT/.github/scripts/chart-control-plane-footprint.py" --require \
        --expect-metrics cpu,memory - || failures=$((failures + 1))
# Negative controls: each value as the chart shipped it before #3110 must be
# refused by its own rule, or the passes above could be reading renders they
# cannot parse. Decided on the guard's message, not its exit status alone.
echo "── negative controls: the #3110 guard must refuse the pre-#3110 sizing"
neg3110() { # label expected-message [helm --set args...]
    local label="$1" expect="$2"; shift 2
    local out rc
    out="$(helm template neg "$UMBRELLA" --kube-version "$K8S_VERSION" "$@" \
        | python3 "$ROOT/.github/scripts/chart-control-plane-footprint.py" --require - 2>&1)" \
        && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qF "$expect"; then
        echo "   ok: $label refused by the #3110 guard"
    else
        echo "   FAIL: expected the #3110 guard to refuse $label (rc=$rc)" >&2
        printf '%s\n' "$out" | tail -5 >&2
        failures=$((failures + 1))
    fi
}
neg3110 "a memory target at 80 % of a 256Mi request" \
    "aims memory at 80 % of 256Mi = 205 MiB" \
    --set api.resources.requests.memory=256Mi \
    --set api.autoscaling.targetMemoryUtilizationPercentage=80
neg3110 "a 256Mi api memory request" "the api's memory request is 256Mi" \
    --set api.resources.requests.memory=256Mi
neg3110 "a CPU target at 70 % of 100m" "aims CPU at 70 % of 100m = 70m" \
    --set api.resources.requests.cpu=100m
neg3110 "a 512Mi api memory limit" "the api's memory limit is 512Mi" \
    --set api.resources.limits.memory=512Mi
neg3110 "a 1Gi worker memory limit" "the worker's memory limit is 1Gi" \
    --set worker.resources.limits.memory=1Gi

# #3021 — the CNPG instance pods reach the API server on their own node, which
# the appliance sets (firstboot's HelmChart and the supervisor's
# HelmChartConfig, ``postgresql.cnpg.nodeLocalApiServer.enabled``). The
# umbrella default (a BYO-Kubernetes install, whose nodes need not serve the
# API on their own address) keeps the kubernetes Service, as before #3021: the
# HA render above must set neither variable, the appliance's values both.
# --require on each, so neither can pass by rendering no Cluster at all.
UMBRELLA_APPLIANCE_CNPG=(
    "${UMBRELLA_HA[@]}"
    --set postgresql.cnpg.nodeLocalApiServer.enabled=true
)
render umbrella-appliance-cnpg "$UMBRELLA" "${UMBRELLA_APPLIANCE_CNPG[@]}"
echo "── CNPG instances: the kubernetes Service by default, the node's own API server on the appliance (umbrella, #3021)"
python3 "$ROOT/.github/scripts/chart-cnpg-node-local-api.py" --require --absent \
    "$OUT/umbrella-ha.yaml" || failures=$((failures + 1))
python3 "$ROOT/.github/scripts/chart-cnpg-node-local-api.py" --require \
    "$OUT/umbrella-appliance-cnpg.yaml" || failures=$((failures + 1))
echo "── negative controls: the #3021 guard must refuse each wrong render"
neg3021() { # label manifest [chart-cnpg-node-local-api.py flags...]
    local label="$1" file="$2"; shift 2
    local out rc
    out="$(python3 "$ROOT/.github/scripts/chart-cnpg-node-local-api.py" "$@" "$file" 2>&1)" \
        && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "#3021"; then
        echo "   ok: $label refused by the #3021 guard"
    else
        echo "   FAIL: expected the #3021 guard to refuse $label (rc=$rc)" >&2
        printf '%s\n' "$out" | tail -5 >&2
        failures=$((failures + 1))
    fi
}
neg3021 "the default render read as the appliance's" "$OUT/umbrella-ha.yaml" --require
neg3021 "an appliance render read as the default" "$OUT/umbrella-appliance-cnpg.yaml" \
    --require --absent
# #2450 — the first promotion takes the appliance's frontend from one replica
# to the node count, and the supervisor's overrides change nothing else in its
# values. Its pods bind hostPorts 80 and 443 and the old pod retires first, so
# a pod template that differs between one replica and three rolls the seed's
# only frontend pod mid-promotion, and the seed refuses connections on both
# ports until the replacement binds them. Rendered under the appliance's own
# release name (the renders above are named apart, which their labels carry);
# the values are the cp renders' and already validated there.
for n in 1 3; do
    helm template spatium-control "$UMBRELLA" --kube-version "$K8S_VERSION" \
        "${APPLIANCE_CP_HARD[@]}" \
        --set api.replicas=$n --set worker.replicas=$n --set frontend.replicas=$n \
        > "$OUT/umbrella-appliance-promote-$n.yaml" || failures=$((failures + 1))
done
echo "── frontend pod template at 1 and 3 replicas (umbrella, #2450)"
python3 "$ROOT/.github/scripts/chart-template-stable.py" --component frontend \
    "$OUT/umbrella-appliance-promote-1.yaml" "$OUT/umbrella-appliance-promote-3.yaml" \
    || failures=$((failures + 1))
# Negative control: a three-replica frontend whose template gained a field must
# be refused, or the guard above could be passing on renders it cannot read.
echo "── negative control: a frontend template that differs must fail"
if python3 "$ROOT/.github/scripts/chart-template-stable.py" --component frontend \
    "$OUT/umbrella-appliance-promote-1.yaml" \
    <(python3 - "$OUT/umbrella-appliance-promote-3.yaml" <<'PYEOF'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
for d in docs:
    if d.get("kind") == "Deployment" and d["metadata"]["labels"].get("app.kubernetes.io/component") == "frontend":
        meta = d["spec"]["template"]["metadata"]
        meta.setdefault("annotations", {})["example.com/changed"] = "1"
print(yaml.safe_dump_all(docs))
PYEOF
) >/dev/null 2>&1; then
    echo "   FAIL: chart-template-stable.py passed a frontend template that differs" >&2
    failures=$((failures + 1))
else
    echo "   ok: a frontend template that differs refused"
fi
# #1826 — the appliance's shared env, as firstboot writes it. Rendered with
# the mirror on so its URL / secret are in the set too.
render umbrella-shared-env "$UMBRELLA" \
    --set slotImageMirror.enabled=true \
    --set sharedEnv[0].name=APPLIANCE_MODE --set-string sharedEnv[0].value=true \
    --set sharedEnv[1].name=APPLIANCE_HOSTNAME --set sharedEnv[1].value=node1 \
    --set sharedEnv[2].name=APPLIANCE_HOST_IPS --set sharedEnv[2].value=10.0.0.1 \
    --set sharedEnv[3].name=INITIAL_NTP_SERVERS --set sharedEnv[3].value=ntp.example \
    --set-string applianceVersion=0.0.0-nightly-20261019+abcdef1
echo "── shared env (umbrella, #1826, #2176)"
python3 "$ROOT/.github/scripts/chart-shared-env.py" \
    --expect VERSION --expect SECRET_KEY --expect DATABASE_URL --expect REDIS_URL \
    --expect CELERY_BROKER_URL \
    --expect APPLIANCE_MODE --expect APPLIANCE_HOSTNAME --expect APPLIANCE_HOST_IPS \
    --expect INITIAL_NTP_SERVERS --expect APPLIANCE_VERSION \
    --expect-on api:SLOT_IMAGE_MIRROR_URL --expect-on api:SLOT_IMAGE_MIRROR_SECRET \
    --expect-on worker:SLOT_IMAGE_MIRROR_URL --expect-on worker:SLOT_IMAGE_MIRROR_SECRET \
    --absent beat:SLOT_IMAGE_MIRROR_SECRET \
    --absent slot-image-mirror:APPLIANCE_MODE \
    --absent slot-image-mirror:SLOT_IMAGE_MIRROR_URL \
    "$OUT/umbrella-shared-env.yaml" || failures=$((failures + 1))
# Negative control: a worker without the variable must be refused, or the
# guard above could be passing on a render it cannot read.
echo "── negative control: a worker missing a shared variable must fail"
if python3 "$ROOT/.github/scripts/chart-shared-env.py" --expect APPLIANCE_MODE \
    <(python3 - "$OUT/umbrella-shared-env.yaml" <<'PYEOF'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
for d in docs:
    if d.get("kind") == "Deployment" and d["metadata"]["labels"].get("app.kubernetes.io/component") == "worker":
        for c in d["spec"]["template"]["spec"]["containers"]:
            c["env"] = [e for e in c["env"] if e["name"] != "APPLIANCE_MODE"]
print(yaml.safe_dump_all(docs))
PYEOF
) >/dev/null 2>&1; then
    echo "   FAIL: chart-shared-env.py passed a worker without APPLIANCE_MODE" >&2
    failures=$((failures + 1))
else
    echo "   ok: worker without APPLIANCE_MODE refused"
fi
# #2955 — the derived max_connections holds the pools at several HPA shapes,
# on both Postgres kinds, and the derived memory limit holds those connections;
# a pinned too-small value must be refused.
echo "── Postgres connection budget (umbrella, #2955)"
for shape in "std::" "hpa30::--set api.autoscaling.maxReplicas=30" \
    "nohpa::--set api.autoscaling.enabled=false --set api.replicas=4" \
    "pool::--set api.databasePool.size=5 --set api.databasePool.maxOverflow=5 --set worker.concurrency=8"; do
    for kind in standalone cnpg; do
        # shellcheck disable=SC2086
        helm template pgc "$UMBRELLA" --kube-version "$K8S_VERSION" \
            --set postgresql.kind=$kind ${shape#*::} \
            | python3 "$ROOT/.github/scripts/chart-postgres-connections.py" --require --check-memory - \
            || { echo "   FAIL: ${shape%%::*}/$kind" >&2; failures=$((failures + 1)); }
    done
done
echo "── negative control: a pinned max_connections below the pools must fail"
# Decided on the guard's own message, not its exit status alone: a guard that
# crashed would exit non-zero too, and read as a refusal.
pgc_out=$(helm template pgc "$UMBRELLA" --kube-version "$K8S_VERSION" --set postgresql.maxConnections=100 \
    | python3 "$ROOT/.github/scripts/chart-postgres-connections.py" --require - 2>&1 || true)
if printf '%s' "$pgc_out" | grep -q "but max_connections is 100 (#2955)"; then
    echo "   ok: max_connections=100 refused"
else
    echo "   FAIL: chart-postgres-connections.py did not refuse max_connections=100: $pgc_out" >&2
    failures=$((failures + 1))
fi
echo "── negative control: a max_connections the memory limit cannot hold must fail"
# A pinned max_connections leaves the limit at the chart's 1Gi.
pgc_out=$(helm template pgc "$UMBRELLA" --kube-version "$K8S_VERSION" --set postgresql.maxConnections=369 \
    | python3 "$ROOT/.github/scripts/chart-postgres-connections.py" --require --check-memory - 2>&1 || true)
if printf '%s' "$pgc_out" | grep -q "the Postgres memory limit is 1024Mi"; then
    echo "   ok: 369 connections in 1Gi refused"
else
    echo "   FAIL: chart-postgres-connections.py did not refuse 369 connections in 1Gi: $pgc_out" >&2
    failures=$((failures + 1))
fi
POSTURE_ARGS="--require-priority"
render umbrella-posture "$UMBRELLA" "${UMBRELLA_POSTURE[@]}"
# ...and again on the HA topology. The CNPG ``Cluster`` and the Sentinel
# StatefulSet only exist in this shape, and the Cluster carries the posture on
# its OWN fields rather than on a pod template — so without this render a
# wrong values path in cnpg-cluster.yaml ships green with Postgres at
# priority 0, which is precisely what the gate exists to prevent.
render umbrella-posture-ha "$UMBRELLA" "${UMBRELLA_POSTURE[@]}" "${UMBRELLA_HA[@]}"
echo "── CNPG WAL budget (umbrella, #2317)"
python3 "$ROOT/.github/scripts/chart-cnpg-recovery.py" --require-cluster \
    "$OUT/umbrella-ha.yaml" "$OUT/umbrella-posture-ha.yaml" || failures=$((failures + 1))
# Negative controls: PostgreSQL's unbounded default, and a cap the volume
# cannot hold, must each be refused naming #2317, or the pass above could be
# reading a render it cannot parse.
echo "── negative controls: an unbounded or oversized slot WAL cap must fail"
neg2317() { # label [helm --set args...]
    local label="$1"; shift
    local out rc
    out="$(helm template neg "$UMBRELLA" --kube-version "$K8S_VERSION" \
        "${UMBRELLA_HA[@]}" "$@" \
        | python3 "$ROOT/.github/scripts/chart-cnpg-recovery.py" --require-cluster - 2>&1)" \
        && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "#2317"; then
        echo "   ok: $label refused by the #2317 guard"
    else
        echo "   FAIL: expected the #2317 guard to refuse $label (rc=$rc)" >&2
        printf '%s\n' "$out" | tail -5 >&2
        failures=$((failures + 1))
    fi
}
neg2317 "max_slot_wal_keep_size -1" \
    --set-string postgresql.cnpg.parameters.max_slot_wal_keep_size=-1
neg2317 "a 3GB cap on a 4Gi volume" --set postgresql.persistence.size=4Gi
# #2831: the same guard holds a replicated Cluster to primaryUpdateMethod
# switchover: CNPG's default restart deletes the primary's pod under its
# clients, and its smart shutdown refuses new connections for 180 s.
echo "── negative control: a replicated Cluster restarting its primary in place must fail"
out="$(helm template neg "$UMBRELLA" --kube-version "$K8S_VERSION" "${UMBRELLA_HA[@]}" \
    --set postgresql.cnpg.primaryUpdateMethod=restart \
    | python3 "$ROOT/.github/scripts/chart-cnpg-recovery.py" --require-cluster - 2>&1)" \
    && rc=0 || rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "#2831"; then
    echo "   ok: primaryUpdateMethod restart on three instances refused by the #2831 guard"
else
    echo "   FAIL: expected the #2831 guard to refuse primaryUpdateMethod restart (rc=$rc)" >&2
    printf '%s\n' "$out" | tail -5 >&2
    failures=$((failures + 1))
fi
# One instance has no replica to switch over to: the chart leaves the field
# out there, so a single node keeps CNPG's in-place restart exactly as before.
echo "── one CNPG instance renders no primaryUpdateMethod (#2831)"
if helm template one "$UMBRELLA" --kube-version "$K8S_VERSION" "${UMBRELLA_HA[@]}" \
    --set postgresql.cnpg.instances=1 | grep -q 'primaryUpdateMethod'; then
    echo "   FAIL: a one-instance Cluster rendered primaryUpdateMethod" >&2
    failures=$((failures + 1))
else
    echo "   ok: a one-instance Cluster leaves CNPG's default"
fi
# #2878: one instance is restarted in place by any rolling update (a demote to
# one node moves the Postgres limit, #2156), and its smart shutdown refuses
# every new connection until smartShutdownTimeout runs out: CNPG's default is
# 180 s. The guard must refuse that, and a one-instance render must carry the
# chart's bound.
echo "── negative control: a smart shutdown left at CNPG's 180 s must fail (#2878)"
out="$(helm template neg "$UMBRELLA" --kube-version "$K8S_VERSION" "${UMBRELLA_HA[@]}" \
    --set postgresql.cnpg.instances=1 --set postgresql.cnpg.smartShutdownTimeout=180 \
    | python3 "$ROOT/.github/scripts/chart-cnpg-recovery.py" --require-cluster - 2>&1)" \
    && rc=0 || rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "#2878"; then
    echo "   ok: smartShutdownTimeout 180 on one instance refused by the #2878 guard"
else
    echo "   FAIL: expected the #2878 guard to refuse smartShutdownTimeout 180 (rc=$rc)" >&2
    printf '%s\n' "$out" | tail -5 >&2
    failures=$((failures + 1))
fi
echo "── one CNPG instance renders the chart's smart shutdown bound (#2878)"
if helm template one "$UMBRELLA" --kube-version "$K8S_VERSION" "${UMBRELLA_HA[@]}" \
    --set postgresql.cnpg.instances=1 | grep -q '^  smartShutdownTimeout: 15$'; then
    echo "   ok: a one-instance Cluster renders smartShutdownTimeout: 15"
else
    echo "   FAIL: a one-instance Cluster did not render smartShutdownTimeout: 15" >&2
    failures=$((failures + 1))
fi
POSTURE_ARGS=""
coverage "$UMBRELLA" "${UMBRELLA_ALL_ON[@]}" "${UMBRELLA_HA[@]}" "${UMBRELLA_EXTERNAL[@]}" \
    "${UMBRELLA_APPLIANCE_CNPG[@]}"

# #1553 — the dns-agent template must REFUSE encrypted-transport ports a
# flavor cannot serve (DoQ on anything but Technitium; DoT/DoH on
# PowerDNS, which needs a dnsdist front that has no Kubernetes
# deployment), instead of rendering a Service port that forwards to
# nothing. Same grep-the-message discipline as the priorityClasses
# negative control below: an exit code alone would also pass if the
# render broke for a different reason.
echo "── negative controls: dns-agent encrypted ports on the wrong flavor must fail"
neg1553() { # label expected-message [helm --set args...]
    local label="$1" expect="$2"; shift 2
    local out rc
    out="$(helm template neg "$UMBRELLA" --kube-version "$K8S_VERSION" \
        --set dnsAgents.enabled=true "$@" 2>&1)" && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "$expect"; then
        echo "   ok: $label refused by the dns-agent flavor guard"
    else
        echo "   FAIL: $label — expected the dns-agent flavor guard to refuse this render (rc=$rc)" >&2
        printf '%s\n' "$out" | tail -5 >&2
        failures=$((failures + 1))
    fi
}
neg1553 "doqPort on bind9" "doqPort is only supported with flavor: technitium" \
    --set dnsAgents.servers[0].name=ns1 \
    --set dnsAgents.servers[0].flavor=bind9 \
    --set dnsAgents.servers[0].doqPort=853
neg1553 "dotPort on powerdns" "not supported with flavor: powerdns" \
    --set dnsAgents.servers[0].name=ns1 \
    --set dnsAgents.servers[0].flavor=powerdns \
    --set dnsAgents.servers[0].dotPort=853
neg1553 "dohPort on powerdns" "not supported with flavor: powerdns" \
    --set dnsAgents.servers[0].name=ns1 \
    --set dnsAgents.servers[0].flavor=powerdns \
    --set dnsAgents.servers[0].dohPort=8443

# #1548 — the DNS agent Service render that exercises every field
# ``server.service`` now carries beyond ``type``: a pinned MetalLB VIP,
# source ranges, the IP family policy and a provider annotation, on a
# Technitium server (the one flavor that may declare all three encrypted
# transports at once). chart-dns-agent-service.py --require asserts the
# fields actually reach the Service and the policy stayed Local.
render umbrella-dns-agent-lb "$UMBRELLA" \
    --set dnsAgents.enabled=true \
    --set dnsAgents.servers[0].name=ns1 \
    --set dnsAgents.servers[0].flavor=technitium \
    --set dnsAgents.servers[0].dotPort=853 \
    --set dnsAgents.servers[0].dohPort=8443 \
    --set dnsAgents.servers[0].doqPort=853 \
    --set dnsAgents.servers[0].service.loadBalancerIP=10.0.0.53 \
    --set dnsAgents.servers[0].service.loadBalancerSourceRanges[0]=192.0.2.0/24 \
    --set dnsAgents.servers[0].service.ipFamilyPolicy=PreferDualStack \
    --set 'dnsAgents.servers[0].service.annotations.metallb\.universe\.tf/loadBalancerIPs=10.0.0.53' \
    --set 'dnsAgents.servers[0].service.annotations.metallb\.universe\.tf/address-pool=default'
echo "── dns-agent Service fields (umbrella, #1548)"
python3 "$ROOT/.github/scripts/chart-dns-agent-service.py" --require \
    --expect externalTrafficPolicy=Local \
    --expect loadBalancerIP=10.0.0.53 \
    --expect loadBalancerSourceRanges=192.0.2.0/24 \
    --expect ipFamilyPolicy=PreferDualStack \
    --expect-annotation metallb.universe.tf/loadBalancerIPs=10.0.0.53 \
    --expect-annotation metallb.universe.tf/address-pool=default \
    "$OUT/umbrella-dns-agent-lb.yaml" || failures=$((failures + 1))
echo "── BIND9 memory limit (umbrella, #1725)"
python3 "$ROOT/.github/scripts/chart-dns-memory-limit.py" --require \
    "$OUT/umbrella-dns-agent-lb.yaml" || failures=$((failures + 1))
echo "── DNS startup probe (umbrella, #2223)"
python3 "$ROOT/.github/scripts/chart-dns-startup-probe.py" --require \
    "$OUT/umbrella-dns-agent-lb.yaml" || failures=$((failures + 1))
echo "── negative control: a DNS container with liveness and no startup probe must fail"
if python3 "$ROOT/.github/scripts/chart-dns-startup-probe.py" \
    <(python3 - "$OUT/umbrella-dns-agent-lb.yaml" <<'PYEOF'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
for d in docs:
    if d.get("kind") == "StatefulSet":
        for c in d["spec"]["template"]["spec"]["containers"]:
            c.pop("startupProbe", None)
print(yaml.safe_dump_all(docs))
PYEOF
) >/dev/null 2>&1; then
    echo "   FAIL: chart-dns-startup-probe.py passed a DNS container with no startup probe" >&2
    failures=$((failures + 1))
else
    echo "   ok: DNS container with no startup probe refused"
fi

# ── Appliance chart ─────────────────────────────────────────────────────────
# Every role + every feature on at once. This is not a valid appliance (one
# node never runs all three DNS drivers) — it is the render that exercises
# every template, which is what matters here.
APPLIANCE_ALL_ON=(
    --set dnsBind9.enabled=true
    --set dnsPowerdns.enabled=true
    --set dnsTechnitium.enabled=true
    --set dhcpKea.enabled=true
    --set dhcpKea.relayVIP=10.0.0.5
    --set lookingGlass.enabled=true
    --set supervisor.enabled=true
    --set observability.kubeStateMetrics.enabled=true
    --set observability.nodeExporter.enabled=true
    --set dns.useMetalLBVIP=true
    --set dns.vip=10.0.0.53
    --set cnpg.enabled=true
    # #1281 — the off-cluster shape: an external control-plane URL renders
    # the pinned-certificate env, mount and hostPath volume in every role
    # pod. appliance-full-stack below keeps the in-cluster (no URL) branch.
    --set dnsBind9.controlPlaneUrl=https://cp.example
    --set dnsPowerdns.controlPlaneUrl=https://cp.example
    --set dnsTechnitium.controlPlaneUrl=https://cp.example
    --set dhcpKea.controlPlaneUrl=https://cp.example
    --set lookingGlass.controlPlaneUrl=https://cp.example
)
lint "$APPLIANCE"
lint "$APPLIANCE" "${APPLIANCE_ALL_ON[@]}"
# #983 — this chart renders the PriorityClasses it names, so every appliance
# pod must carry one. ``agent-landing`` is the recorded exception: a courtesy
# redirect page that must not outrank anything, and at priority 0 it is also
# the natural first eviction candidate.
POSTURE_ARGS="--require-priority --allow-no-priority agent-landing"
render appliance-defaults "$APPLIANCE"
render appliance-all-on "$APPLIANCE" "${APPLIANCE_ALL_ON[@]}"
# #1510 — all three DNS engines on with a DNS VIP: exactly one Service may ask
# for it, and its selector must reach every engine's pods, so an engine switch
# never leaves the VIP on a Service without endpoints.
python3 "$ROOT/.github/scripts/chart-lb-address-single-owner.py" --require \
    --dns-vip 10.0.0.53 "$OUT/appliance-all-on.yaml" || failures=$((failures + 1))
echo "── BIND9 memory limit (appliance, #1725)"
python3 "$ROOT/.github/scripts/chart-dns-memory-limit.py" --require \
    "$OUT/appliance-all-on.yaml" || failures=$((failures + 1))
echo "── DNS startup probe (appliance, #2223)"
python3 "$ROOT/.github/scripts/chart-dns-startup-probe.py" --require \
    "$OUT/appliance-all-on.yaml" || failures=$((failures + 1))
echo "── supervisor may re-clone a stuck Postgres instance (appliance, #2132)"
python3 "$ROOT/.github/scripts/chart-cnpg-recovery.py" --require-supervisor-role \
    "$OUT/appliance-all-on.yaml" || failures=$((failures + 1))
echo "── negative control: a supervisor Role without pods/log must fail"
if python3 "$ROOT/.github/scripts/chart-cnpg-recovery.py" --require-supervisor-role \
    <(python3 - "$OUT/appliance-all-on.yaml" <<'PYEOF'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
for d in docs:
    if d.get("kind") == "Role" and d["metadata"]["name"] == "spatium-supervisor-namespace":
        for rule in d["rules"]:
            rule["resources"] = [r for r in rule["resources"] if r != "pods/log"]
print(yaml.safe_dump_all(docs))
PYEOF
) >/dev/null 2>&1; then
    echo "   FAIL: chart-cnpg-recovery.py passed a supervisor Role without pods/log" >&2
    failures=$((failures + 1))
else
    echo "   ok: supervisor Role without pods/log refused"
fi
# The single-node default install shape: one DNS driver + DHCP + supervisor.
render appliance-full-stack "$APPLIANCE" \
    --set dnsBind9.enabled=true --set dhcpKea.enabled=true --set supervisor.enabled=true
# #1281 — the other branch of the off-cluster TLS choice: a supervisor started
# with the skip pins nothing, so its agents skip too and mount no pin.
render appliance-offcluster-skip "$APPLIANCE" \
    --set dnsBind9.enabled=true --set dnsBind9.controlPlaneUrl=https://cp.example \
    --set controlPlaneTls.insecureSkipVerify=true

# #2223 — the dns-bind9 memory limit is sized from node RAM: the supervisor
# writes ``dnsBind9.memory``, and an explicit memory in ``dnsBind9.resources``
# (an operator's HelmChartConfig) must still win over it.
bind9_mem() { # file want-limit want-request
    python3 - "$@" <<'PYEOF'
import sys, yaml
path, want_limit, want_request = sys.argv[1:4]
for d in yaml.safe_load_all(open(path)):
    if d and d.get("kind") == "DaemonSet":
        for c in d["spec"]["template"]["spec"]["containers"]:
            if c["name"] == "dns-bind9":
                r = c.get("resources") or {}
                got = ((r.get("limits") or {}).get("memory"), (r.get("requests") or {}).get("memory"))
                if got != (want_limit, want_request):
                    sys.exit(f"   FAIL: {path}: dns-bind9 memory {got}, want {(want_limit, want_request)}")
                if (r.get("requests") or {}).get("cpu") != "250m":
                    sys.exit(f"   FAIL: {path}: dns-bind9 lost its CPU request")
                print(f"   ok: dns-bind9 memory {got}")
                sys.exit(0)
sys.exit(f"   FAIL: {path}: no dns-bind9 container")
PYEOF
}
echo "── dns-bind9 memory sizing (appliance, #2223)"
bind9_mem "$OUT/appliance-full-stack.yaml" 2Gi 256Mi || failures=$((failures + 1))
render appliance-bind9-sized "$APPLIANCE" \
    --set dnsBind9.enabled=true \
    --set dnsBind9.memory.limit=8Gi --set dnsBind9.memory.request=1024Mi
bind9_mem "$OUT/appliance-bind9-sized.yaml" 8Gi 1024Mi || failures=$((failures + 1))
render appliance-bind9-override "$APPLIANCE" \
    --set dnsBind9.enabled=true \
    --set dnsBind9.memory.limit=8Gi --set dnsBind9.memory.request=1024Mi \
    --set dnsBind9.resources.limits.memory=6Gi
bind9_mem "$OUT/appliance-bind9-override.yaml" 6Gi 1024Mi || failures=$((failures + 1))

# #992 — the two release shapes this chart is ACTUALLY installed as, on every
# appliance. Rendering the chart once (as everything above does) can never see
# the bug that shipped in #988: a cluster-scoped object rendered by both
# releases makes whichever install runs second fail whole with ``invalid
# ownership metadata``, and under k3s's helm-controller that is a job retrying
# forever rather than an error anyone sees.
#
#   bootstrap   firstboot writes it; supervisor + CNPG operator, roles off.
#               Owns the PriorityClasses (it installs first, and firstboot
#               re-renders it from the slot's baked chart on every boot).
#   supervisor  the supervisor writes it; every role on, supervisor off.
#
# The supervisor's flags are mirrored from ``_build_values`` in
# agent/supervisor/spatium_supervisor/service_lifecycle.py. That mirror is
# pinned from the other side by
# agent/supervisor/tests/test_role_chart_values.py, which asserts the Python
# emits exactly the priorityClasses block set here — so the two cannot drift
# without one of them failing.
render appliance-release-bootstrap "$APPLIANCE" \
    --set supervisor.enabled=true \
    --set cnpg.enabled=true \
    --set dnsBind9.enabled=false \
    --set dhcpKea.enabled=false \
    --set priorityClasses.create=true
render appliance-release-supervisor "$APPLIANCE" \
    --set supervisor.enabled=false \
    --set dnsBind9.enabled=true \
    --set dnsPowerdns.enabled=true \
    --set dnsTechnitium.enabled=true \
    --set dhcpKea.enabled=true \
    --set lookingGlass.enabled=true \
    --set agentLanding.enabled=false \
    --set priorityClasses.create=false \
    --set priorityClasses.external=true
echo "── cluster-scoped collision (appliance, two release shapes)"
python3 "$ROOT/.github/scripts/chart-cluster-scoped-collision.py" \
    bootstrap="$OUT/appliance-release-bootstrap.yaml" \
    supervisor="$OUT/appliance-release-supervisor.yaml" || failures=$((failures + 1))

# The guard in templates/priorityclasses.yaml must still FIRE for the
# combination it exists to catch: ``create: false`` with no ``external``
# assertion and workloads still naming a class. Offline there is no cluster
# to ask, so every named class reads as missing — which is exactly the
# render a fresh appliance must never be given. A guard nothing tests is a
# guard that stops working silently, and this one now has two ways to pass.
echo "── negative control: priorityClasses.create=false without external must fail"
neg_out="$(helm template neg "$APPLIANCE" --kube-version "$K8S_VERSION" \
    --set dnsBind9.enabled=true \
    --set priorityClasses.create=false 2>&1)" && neg_rc=0 || neg_rc=$?
# Grep the message, not just the exit code. ``helm template`` exits non-zero
# for a syntax error, a bad --set path or a missing dependency too, so an
# exit-code-only check would keep passing after the guard was deleted — the
# control would then be asserting that the chart is broken, which it would
# be, for a different reason.
if [ "$neg_rc" -ne 0 ] && printf '%s' "$neg_out" | grep -q "priorityClasses.create is false"; then
    echo "   ok: render refused by the priorityClasses guard"
else
    echo "   FAIL: expected the priorityClasses guard to refuse this render (rc=$neg_rc)" >&2
    printf '%s\n' "$neg_out" | tail -5 >&2
    failures=$((failures + 1))
fi

POSTURE_ARGS=""
coverage "$APPLIANCE" "${APPLIANCE_ALL_ON[@]}"

# ── MetalLB wrapper chart ───────────────────────────────────────────────────
# #983 — this chart was rendered by NOTHING on a PR (the two blocks above name
# the other two charts explicitly), which is how its speaker and controller
# stayed BestEffort at priority 0 while every workload around them was ranked:
# no gate could see them. It ships ``metallb.enabled: false``, so the
# render that matters is the one with it on — the shape the supervisor
# applies the moment an operator sets a control-plane VIP.
METALLB_ALL_ON=(
    --set metallb.enabled=true
    --set metallb.ipPool.addresses[0]=10.0.0.20-10.0.0.30
    --set metallb.bgp.enabled=true
)
lint "$METALLB"
lint "$METALLB" "${METALLB_ALL_ON[@]}"
render metallb-defaults "$METALLB"
POSTURE_ARGS="--require-priority"
render metallb-all-on "$METALLB" "${METALLB_ALL_ON[@]}"
# #1103 — the webhooks must fail open, or the CRs in the same install are
# refused while the controller that serves the webhook is still starting.
# Only a live apiserver shows it; lint and template pass either way. MetalLB's
# one webhook configuration covers the BGP kinds too, so this render is the
# whole check; the BGP render's extra frr-k8s webhook is left at Fail on
# purpose (see the script's docstring).
python3 "$ROOT/.github/scripts/chart-webhooks-fail-open.py" "$OUT/metallb-all-on.yaml" --require \
    || failures=$((failures + 1))
# BGP mode (#566 D1) — the supervisor flips ``frrk8s.enabled`` on together
# with ``bgp.enabled`` the moment a peer is configured, so this shape reaches
# real appliances and has to be rendered. The two frr-k8s workloads are
# exempted from the seccomp check ONLY: the frr-k8s 0.0.21 subchart exposes no
# pod-securityContext knob, so no values override can supply a profile.
# Exempting them by name is strictly better than not rendering the chart,
# which is how their missing priority class and BestEffort QoS survived #965.
# The same subchart gives its four ``cp-*`` init containers no resources knob
# either (#3208), so the init-resources check exempts frr-k8s by name too.
POSTURE_ARGS="--require-priority --allow-no-seccomp frr-k8s,frr-k8s-statuscleaner --allow-no-init-resources frr-k8s"
# One peer, because the API refuses BGP mode without one: without it this
# render held no BGPPeer at all, so the CR every BGP appliance carries was
# never schema-checked.
METALLB_BGP=(
    --set metallb.frrk8s.enabled=true
    --set metallb.bgp.peers[0].myASN=64512
    --set metallb.bgp.peers[0].peerASN=64513
    --set metallb.bgp.peers[0].peerAddress=10.0.0.1
)
render metallb-bgp "$METALLB" "${METALLB_ALL_ON[@]}" "${METALLB_BGP[@]}"
POSTURE_ARGS=""
coverage "$METALLB" "${METALLB_ALL_ON[@]}" "${METALLB_BGP[@]}"

# ── Raw manifests ───────────────────────────────────────────────────────────
# Not rendered by helm, so the per-render guard above never sees them.
echo "── no external Kea HA port (raw k8s/dhcp manifests)"
python3 "$ROOT/.github/scripts/chart-no-external-kea-ha.py" "$ROOT"/k8s/dhcp/*.yaml \
    || failures=$((failures + 1))
echo "── BIND9 memory limit (raw k8s/dns manifest, #1725)"
python3 "$ROOT/.github/scripts/chart-dns-memory-limit.py" --require \
    "$ROOT/k8s/dns/bind9-statefulset.yaml" || failures=$((failures + 1))

# #1589 — the DHCP agent's readiness probe must test the Kea control
# socket, not the HA listener, in the umbrella chart's render (the
# posture render is the one that names a DHCP server) and in the raw
# manifests alike. --require so a render that stops exercising the
# template fails instead of passing vacuously.
echo "── DHCP agent readiness probes the Kea control socket (#1589)"
python3 "$ROOT/.github/scripts/chart-dhcp-readiness.py" \
    --require --require-kea-socket \
    "$OUT/umbrella-posture.yaml" "$ROOT/k8s/dhcp/kea-statefulset.yaml" \
    || failures=$((failures + 1))

# The guard must still FIRE on the probe shape it exists to catch.
# Grep the message, not just the exit code (same reasoning as the
# priorityClasses negative control above).
echo "── negative control: tcpSocket readiness on the Kea HA port must fail"
cat > "$OUT/neg-dhcp-readiness.yaml" <<'EOF'
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: dhcp-kea-dhcp1
  labels:
    app.kubernetes.io/name: spatium-dhcp
spec:
  template:
    metadata:
      labels:
        app.kubernetes.io/name: spatium-dhcp
    spec:
      containers:
        - name: dhcp
          readinessProbe:
            tcpSocket: { port: 8000 }
EOF
neg_out="$(python3 "$ROOT/.github/scripts/chart-dhcp-readiness.py" \
    --require-kea-socket "$OUT/neg-dhcp-readiness.yaml" 2>&1)" && neg_rc=0 || neg_rc=$?
if [ "$neg_rc" -ne 0 ] && printf '%s' "$neg_out" | grep -q "HA peer listener"; then
    echo "   ok: tcpSocket readiness on port 8000 refused by the #1589 guard"
else
    echo "   FAIL: expected the #1589 readiness guard to refuse a tcpSocket probe on port 8000 (rc=$neg_rc)" >&2
    printf '%s\n' "$neg_out" | tail -5 >&2
    failures=$((failures + 1))
fi

# #3208 — an init container without resources must fail the pod-posture gate.
# Grep the message, not just the exit code: a bare non-zero could come from
# anything.
echo "── negative control: an init container without resources must fail (#3208)"
cat > "$OUT/neg-init-resources.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: neg-init
spec:
  template:
    spec:
      securityContext:
        seccompProfile: { type: RuntimeDefault }
      initContainers:
        - name: wait-for-thing
          image: busybox
      containers:
        - name: main
          image: busybox
YAML
neg_out="$(python3 "$ROOT/.github/scripts/chart-pod-posture.py" "$OUT/neg-init-resources.yaml" 2>&1)" && neg_rc=0 || neg_rc=$?
if [ "$neg_rc" -ne 0 ] && printf '%s' "$neg_out" | grep -q "init container wait-for-thing has no resources"; then
    echo "   ok: resource-less init container refused by the #3208 guard"
else
    echo "   FAIL: expected the pod-posture gate to refuse an init container without resources (rc=$neg_rc)" >&2
    printf '%s\n' "$neg_out" | tail -5 >&2
    failures=$((failures + 1))
fi

# #3204-#3209 — the single-instance k8s placement + naming fixes. One render
# carries every new value so kubeconform checks it (the CNPG Cluster's
# spec.affinity.nodeAffinity included), then grep assertions on the shapes.
UMBRELLA_PLACEMENT=(
    --set postgresql.kind=cnpg --set postgresql.cnpg.instances=1
    --set-json 'postgresql.affinity={"nodeAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":[{"weight":100,"preference":{"matchExpressions":[{"key":"kubernetes.io/hostname","operator":"In","values":["node-a"]}]}}]}}'
    --set-json 'api.affinity={"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"pool","operator":"In","values":["cp"]}]}]}},"podAntiAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":[{"weight":100,"podAffinityTerm":{"labelSelector":{"matchLabels":{"app.kubernetes.io/component":"api"}},"topologyKey":"kubernetes.io/hostname"}}]}}'
    --set dnsAgents.enabled=true --set dnsAgents.agentKey.value=x
    --set dnsAgents.prefixWithFullname=true --set dnsAgents.storageClass=slow
    --set-json 'dnsAgents.servers=[{"name":"ns1","storageClass":"fast","affinity":{"nodeAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":[{"weight":50,"preference":{"matchExpressions":[{"key":"zone","operator":"In","values":["a"]}]}}]}}},{"name":"a-very-long-server-name-number-one-xx1"},{"name":"a-very-long-server-name-number-one-xx2"}]'
    --set dhcpAgents.enabled=true --set dhcpAgents.agentKey.value=x --set dhcpAgents.prefixWithFullname=true
    --set-json 'dhcpAgents.servers=[{"name":"d1","nodeSelector":{"pool":"edge"},"tolerations":[{"key":"edge","operator":"Exists"}]}]'
)
render umbrella-placement "$UMBRELLA" "${UMBRELLA_PLACEMENT[@]}"
python3 - "$OUT/umbrella-placement.yaml" <<'PY' || failures=$((failures + 1))
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
bad = []
cl = next(d for d in docs if d["kind"] == "Cluster")
if cl["spec"].get("enablePDB") is not False:
    bad.append("#3204: one CNPG instance with enablePDB unset must render enablePDB: false")
if "preferredDuringSchedulingIgnoredDuringExecution" not in (cl["spec"]["affinity"].get("nodeAffinity") or {}):
    bad.append("#3205: postgresql.affinity.nodeAffinity missing from the Cluster's spec.affinity")
job = next(d for d in docs if d["kind"] == "Job" and "-migrate-" in d["metadata"]["name"])
aff = job["spec"]["template"]["spec"].get("affinity") or {}
if "nodeAffinity" not in aff:
    bad.append("#3207: the migrate Job did not follow api.affinity.nodeAffinity")
if "podAntiAffinity" in aff or "podAffinity" in aff:
    bad.append("#3207: the migrate Job copied the api's pod (anti-)affinity, which keeps it off the api's nodes")
sts = {d["metadata"]["name"]: d for d in docs if d["kind"] == "StatefulSet"
       and d["spec"]["template"]["metadata"]["labels"].get("app.kubernetes.io/component") in ("dns-agent", "dhcp-agent")}
names = sorted(sts)
if len(names) != 4:
    bad.append(f"#3209: expected 4 distinct agent StatefulSets, got {names}")
for n, d in sts.items():
    if len(n) > 52:
        bad.append(f"#3209: agent name {n} is {len(n)} > 52 characters")
    if not n.startswith("umbrella-placement-spatiumddi-"):
        bad.append(f"#3209: agent name {n} is not prefixed with the release fullname")
    spec = d["spec"]["template"]["spec"]
    if d["spec"]["serviceName"] != n + "-headless":
        bad.append(f"#3209: {n} serviceName {d['spec']['serviceName']}")
    if "podAntiAffinity" not in spec.get("affinity", {}):
        bad.append(f"#3206: {n} lost the chart's one-per-node anti-affinity")
    want = "fast" if n.endswith("-ns1") else ("slow" if "dns" in n else None)
    for c in d["spec"]["volumeClaimTemplates"]:
        if c["spec"].get("storageClassName") != want:
            bad.append(f"#3206: {n} claim {c['metadata']['name']} storageClassName {c['spec'].get('storageClassName')} != {want}")
    if n.endswith("-ns1") and "nodeAffinity" not in spec["affinity"]:
        bad.append(f"#3206: {n} lost its own nodeAffinity")
    if "dhcp" in n and (spec.get("nodeSelector") != {"pool": "edge"} or not spec.get("tolerations")):
        bad.append(f"#3206: {n} did not carry its nodeSelector / tolerations")
svcs = [d["metadata"]["name"] for d in docs if d["kind"] == "Service"]
if len(svcs) != len(set(svcs)):
    bad.append(f"#3209: duplicate Service names {svcs}")
for b in bad:
    print("   FAIL:", b, file=sys.stderr)
if not bad:
    print("   ok: #3204-#3209 placement / naming shapes")
sys.exit(1 if bad else 0)
PY
for case in "1:false:unset" "1:true:true" "1:false:false" "3:true:unset" "3:true:true" "3:false:false"; do
    IFS=: read -r inst want set <<<"$case"
    args=(--set postgresql.kind=cnpg --set "postgresql.cnpg.instances=$inst")
    [ "$set" = unset ] || args+=(--set "postgresql.cnpg.enablePDB=$set")
    got="$(helm template pdb "$UMBRELLA" --kube-version "$K8S_VERSION" "${args[@]}" | sed -n 's/^  enablePDB: //p')"
    if [ "$got" = "$want" ]; then
        echo "   ok: #3204 instances=$inst enablePDB=$set renders $got"
    else
        echo "   FAIL: #3204 instances=$inst enablePDB=$set rendered '$got', want $want" >&2
        failures=$((failures + 1))
    fi
done
neg3209() { # label expected-message [helm args...]
    local label="$1" msg="$2"; shift 2
    local rel="${REL:-neg}"
    if out="$(helm template "$rel" "$UMBRELLA" --kube-version "$K8S_VERSION" \
            --set dnsAgents.enabled=true --set dnsAgents.agentKey.value=x "$@" 2>&1)"; then
        echo "   FAIL: #3209 $label rendered" >&2; failures=$((failures + 1))
    elif printf '%s' "$out" | grep -q "$msg"; then
        echo "   ok: #3209 $label refused"
    else
        echo "   FAIL: #3209 $label failed for another reason:" >&2
        printf '%s\n' "$out" | tail -3 >&2; failures=$((failures + 1))
    fi
}
echo "── negative controls: agent object names (#3209)"
neg3209 "two servers with one name" "server names must be unique" \
    --set-json 'dnsAgents.servers=[{"name":"ns1"},{"name":"ns1"}]'
REL=1dev neg3209 "a prefixed name starting with a digit" "must start with a lowercase letter" \
    --set dnsAgents.prefixWithFullname=true --set-json 'dnsAgents.servers=[{"name":"ns1"}]'

# #3206 follow-up — adopting storageClass on a live StatefulSet is refused by
# helm via `lookup`, which is empty without a cluster. So here we can only pin
# the half that must never regress: with no cluster (helm template, Argo CD)
# setting a class renders, and NOTES carries the static pointer only then.
echo "── storageClass adoption: renders without a cluster, NOTES pointer (#3206)"
# NOTES.txt is not a manifest, so `helm template --show-only` cannot select it;
# a client-side dry-run install needs no cluster and prints it.
sc_notes() { helm install sc "$UMBRELLA" --dry-run=client "$@" 2>&1 | sed -n '/^NOTES:/,$p'; }
if ! helm template sc "$UMBRELLA" --kube-version "$K8S_VERSION" --set dnsAgents.enabled=true \
        --set dnsAgents.agentKey.value=x --set dnsAgents.storageClass=slow --set dhcpAgents.enabled=true \
        --set dhcpAgents.storageClass=slow >/dev/null 2>/tmp/sc-render.err; then
    echo "   FAIL: #3206 storageClass set did not render without a cluster:" >&2
    tail -3 /tmp/sc-render.err >&2; failures=$((failures + 1))
elif ! sc_out="$(sc_notes --set dnsAgents.enabled=true --set dnsAgents.agentKey.value=x --set dnsAgents.storageClass=slow)" \
        || ! printf '%s' "$sc_out" | grep -q "Adopting storageClass on an existing install"; then
    echo "   FAIL: #3206 NOTES lacks the storageClass pointer when one is set" >&2; failures=$((failures + 1))
elif sc_out="$(sc_notes --set dnsAgents.enabled=true --set dnsAgents.agentKey.value=x)" \
        && printf '%s' "$sc_out" | grep -q "Adopting storageClass"; then
    echo "   FAIL: #3206 NOTES shows the storageClass pointer with none set" >&2; failures=$((failures + 1))
else
    echo "   ok: #3206 storageClass renders offline; NOTES pointer only when set"
fi

# #1550 — no render above sets frontend.controlPlaneVIP, so the
# frontend's LoadBalancer shape is exercised here, together with the
# appliance all-on render (DNS VIPs + DHCP relay VIP). --require so
# either side silently dropping its VIP Service fails the gate.
echo "── MetalLB VIP Services allocate no NodePorts (#1550)"
if helm template umbrella-vip "$UMBRELLA" --kube-version "$K8S_VERSION" \
        --set frontend.controlPlaneVIP=10.0.0.10 > "$OUT/umbrella-vip.yaml"; then
    python3 "$ROOT/.github/scripts/chart-vip-nodeports.py" --require \
        "$OUT/umbrella-vip.yaml" "$OUT/appliance-all-on.yaml" \
        || failures=$((failures + 1))
else
    echo "   FAIL: umbrella chart did not render with frontend.controlPlaneVIP set" >&2
    failures=$((failures + 1))
fi

echo "── negative control: a VIP LoadBalancer allocating NodePorts must fail"
cat > "$OUT/neg-vip-nodeports.yaml" <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: dns-bind9
spec:
  type: LoadBalancer
  ports:
    - name: dns-udp
      port: 53
      protocol: UDP
EOF
neg_out="$(python3 "$ROOT/.github/scripts/chart-vip-nodeports.py" \
    "$OUT/neg-vip-nodeports.yaml" 2>&1)" && neg_rc=0 || neg_rc=$?
if [ "$neg_rc" -ne 0 ] && printf '%s' "$neg_out" | grep -q "allocateLoadBalancerNodePorts"; then
    echo "   ok: VIP LoadBalancer without allocateLoadBalancerNodePorts: false refused by the #1550 guard"
else
    echo "   FAIL: expected the #1550 guard to refuse a VIP LoadBalancer allocating NodePorts (rc=$neg_rc)" >&2
    printf '%s\n' "$neg_out" | tail -5 >&2
    failures=$((failures + 1))
fi

# #1547 — the raw manifests must point at Services that exist (or
# that CNPG creates): postgres-rw, the `api` Service, sentinel://
# Redis URLs and a redis-sentinel Service.
echo "── raw k8s/ manifests point at Services that exist (#1547)"
python3 "$ROOT/.github/scripts/chart-raw-k8s-refs.py" "$ROOT/k8s" \
    || failures=$((failures + 1))

echo "── negative control: a DATABASE_URL host CNPG never creates must fail"
cp -r "$ROOT/k8s" "$OUT/neg-k8s"
sed -i 's/@postgres-rw:/@postgres-primary:/' "$OUT/neg-k8s/base/configmap.yaml"
neg_out="$(python3 "$ROOT/.github/scripts/chart-raw-k8s-refs.py" \
    "$OUT/neg-k8s" 2>&1)" && neg_rc=0 || neg_rc=$?
if [ "$neg_rc" -ne 0 ] && printf '%s' "$neg_out" | grep -q "postgres-primary"; then
    echo "   ok: DATABASE_URL at postgres-primary refused by the #1547 guard"
else
    echo "   FAIL: expected the #1547 guard to refuse a postgres-primary DATABASE_URL (rc=$neg_rc)" >&2
    printf '%s\n' "$neg_out" | tail -5 >&2
    failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
    echo "charts: $failures gate(s) failed" >&2
    exit 1
fi
echo "charts: all gates passed (renders in $OUT)"
