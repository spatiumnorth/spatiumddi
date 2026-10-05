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
#                      profile, and (where the render opts in) a
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
    --set redis.kind=sentinel
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
render umbrella-defaults "$UMBRELLA"
render umbrella-all-on "$UMBRELLA" "${UMBRELLA_ALL_ON[@]}"
render umbrella-ha "$UMBRELLA" "${UMBRELLA_HA[@]}"
# Bring-your-own database + Redis: the shape k8s/ha/ installs use.
render umbrella-external-db "$UMBRELLA" "${UMBRELLA_EXTERNAL[@]}"
POSTURE_ARGS="--require-priority"
render umbrella-posture "$UMBRELLA" "${UMBRELLA_POSTURE[@]}"
# ...and again on the HA topology. The CNPG ``Cluster`` and the Sentinel
# StatefulSet only exist in this shape, and the Cluster carries the posture on
# its OWN fields rather than on a pod template — so without this render a
# wrong values path in cnpg-cluster.yaml ships green with Postgres at
# priority 0, which is precisely what the gate exists to prevent.
render umbrella-posture-ha "$UMBRELLA" "${UMBRELLA_POSTURE[@]}" "${UMBRELLA_HA[@]}"
POSTURE_ARGS=""
coverage "$UMBRELLA" "${UMBRELLA_ALL_ON[@]}" "${UMBRELLA_HA[@]}" "${UMBRELLA_EXTERNAL[@]}"

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
# The single-node default install shape: one DNS driver + DHCP + supervisor.
render appliance-full-stack "$APPLIANCE" \
    --set dnsBind9.enabled=true --set dhcpKea.enabled=true --set supervisor.enabled=true
# #1281 — the other branch of the off-cluster TLS choice: a supervisor started
# with the skip pins nothing, so its agents skip too and mount no pin.
render appliance-offcluster-skip "$APPLIANCE" \
    --set dnsBind9.enabled=true --set dnsBind9.controlPlaneUrl=https://cp.example \
    --set controlPlaneTls.insecureSkipVerify=true

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
POSTURE_ARGS="--require-priority --allow-no-seccomp frr-k8s,frr-k8s-statuscleaner"
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
