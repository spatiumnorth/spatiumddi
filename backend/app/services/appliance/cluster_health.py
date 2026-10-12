"""Cluster health snapshot for the appliance "Cluster → Overview" screen (#402).

Aggregates a live picture of the k3s cluster *underneath* the appliance from
data the api pod's ServiceAccount can already read (nodes + pods cluster-wide)
plus the kubelet Summary API. This is the same data source the TTY console
uses — the appliance ships **no** metrics-server / Prometheus, so live CPU /
memory comes from the kubelet Summary API, not ``metrics.k8s.io``. Since
Kubernetes 1.36 that response also carries PSI stall percentages (#983).

Two transports reach it, per node: direct to the kubelet on :10250 under
``nodes/stats``, falling back to the apiserver proxy under ``nodes/proxy``.
See ``k8s.get_node_stats_summary``; which one served is reported back on the
snapshot so the broad proxy grant can eventually be dropped.

``get_cluster_health()`` is a synchronous gather (a handful of stdlib kubeapi
calls); the router runs it in a worker thread so the event loop never blocks,
and the SSE stream re-runs it every couple of seconds for the near-real-time
dashboard. The return value is a JSON-safe dict matching the ``ClusterHealth``
Pydantic model in ``app.api.v1.appliance.cluster`` (so the SSE loop can
``json.dumps`` it directly without re-validating each tick).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

import structlog

from app.services.appliance import k8s

logger = structlog.get_logger(__name__)

# Components we recognise for the workload-health rollup. Anything else still
# rolls up under its own ``app.kubernetes.io/component`` label (or a name-
# derived fallback) — this list only drives nice display ordering.
_COMPONENT_ORDER = [
    "api",
    "worker",
    "beat",
    "frontend",
    "postgresql",
    "redis",
    "supervisor",
    "dns-bind9",
    "dns-powerdns",
    "dns-technitium",
    "dhcp-kea",
]

_TOP_POD_LIMIT = 8


# ── quantity parsers ───────────────────────────────────────────────────────


def _cpu_cores(q: str | None) -> float | None:
    """k8s CPU quantity → cores. Handles ``n`` / ``u`` / ``m`` / plain."""
    if not q:
        return None
    q = q.strip()
    try:
        if q.endswith("n"):
            return float(q[:-1]) / 1e9
        if q.endswith("u"):
            return float(q[:-1]) / 1e6
        if q.endswith("m"):
            return float(q[:-1]) / 1e3
        return float(q)
    except ValueError:
        return None


_MEM_BIN = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4, "Pi": 1024**5, "Ei": 1024**6}
_MEM_DEC = {"k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18}


def _mem_bytes(q: str | None) -> int | None:
    """k8s memory quantity → bytes. Handles Ki/Mi/Gi… (1024) + K/M/G… (1000)."""
    if not q:
        return None
    q = q.strip()
    for suf, mult in _MEM_BIN.items():
        if q.endswith(suf):
            try:
                return int(float(q[:-2]) * mult)
            except ValueError:
                return None
    for suf, mult in _MEM_DEC.items():
        if q.endswith(suf):
            try:
                return int(float(q[:-1]) * mult)
            except ValueError:
                return None
    try:
        return int(float(q))
    except ValueError:
        return None


def _age_seconds(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return int((datetime.now(UTC) - dt).total_seconds())


# ── per-resource extractors ────────────────────────────────────────────────


_ROLE_LABEL_NS = "node-role.kubernetes.io"


def _node_roles(node: dict[str, Any]) -> list[str]:
    """Roles from ``node-role.kubernetes.io/<role>`` label keys (k3s sets
    control-plane / etcd / master). Match the label *namespace* exactly via
    ``partition`` rather than a prefix ``startswith`` — the latter is an
    incomplete-substring check (CodeQL py/incomplete-url-substring-sanitization)
    and an exact equality is also more precise."""
    labels = (node.get("metadata") or {}).get("labels") or {}
    roles: list[str] = []
    for key in labels:
        ns, sep, role = key.partition("/")
        if sep and ns == _ROLE_LABEL_NS and role:
            roles.append(role)
    return sorted(roles) or ["worker"]


def _node_condition(node: dict[str, Any], kind: str) -> bool:
    for c in (node.get("status") or {}).get("conditions") or []:
        if c.get("type") == kind:
            return c.get("status") == "True"
    return False


def _internal_ip(node: dict[str, Any]) -> str | None:
    for a in (node.get("status") or {}).get("addresses") or []:
        if a.get("type") == "InternalIP":
            return a.get("address")
    return None


# ── PSI (#983 Phase 2 item 7) ────────────────────────────────────────────────
# Pressure Stall Information, GA in Kubernetes 1.36 (``KubeletPSI``). The
# kubelet Summary API grows a ``psi`` block on the node's ``cpu`` and
# ``memory`` sections and a new ``io`` section, each shaped like
# /proc/pressure/<res>:
#
#   "psi": {"some": {"total": N, "avg10": x, "avg60": y, "avg300": z},
#           "full": { ...same... }}
#
# ``some`` is the share of wall-clock time at least one task was stalled on
# the resource; ``full`` is the share where EVERY runnable task was. For CPU,
# ``full`` is meaningless at the node level and the kernel reports it as 0 —
# so a CPU verdict has to read ``some``.
#
# Why this is worth parsing at all: #980 was the appliance dropping relayed
# DHCP under CPU pressure with every dashboard green. Utilisation cannot see
# that — a node at 70% CPU with a queue behind one core looks identical to a
# node at 70% with none. Stall time is the signal that separates them, and it
# arrives in a response this code already fetches.
_PSI_WINDOWS = ("avg10", "avg60", "avg300")


def _parse_psi(block: Any) -> dict[str, Any] | None:
    """One ``psi`` object → ``{"some": {...}, "full": {...}}`` of floats.

    Returns None when the block is absent or unusable, and the caller keeps
    that None all the way to the API. NULL here means UNRECORDED — a kubelet
    older than 1.36, or one with the feature off — and must never be
    flattened to 0.0, which is a real reading meaning "no pressure at all".
    Those are opposite facts about the node and the panel that shows them.
    """
    if not isinstance(block, dict):
        return None
    out: dict[str, Any] = {}
    for kind in ("some", "full"):
        raw = block.get(kind)
        if not isinstance(raw, dict):
            continue
        vals: dict[str, float] = {}
        for window in _PSI_WINDOWS:
            val = raw.get(window)
            # bool is an int subclass; a JSON ``true`` here would otherwise
            # become 1.0 and read as a real one-percent stall.
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                vals[window] = float(val)
        if vals:
            out[kind] = vals
    return out or None


def _kubelet_transport_report(
    by_node: dict[str, str], ip_by_node: dict[str, str]
) -> dict[str, Any]:
    """Per-node transport + the one verdict an operator acts on (#983).

    ``all_direct`` is the question the ``nodes/proxy`` grant hangs on, and it
    is False when NO node was probed — "we measured nothing" must never read
    as "safe to drop the broad grant". Reasons are keyed back to node names
    (k8s.py tracks them by IP, which is what it connects to) so the report can
    be read without cross-referencing addresses.
    """
    reasons_by_ip = k8s.kubelet_block_reasons()
    blocked = {name: reasons_by_ip[ip] for name, ip in ip_by_node.items() if ip in reasons_by_ip}
    direct = sum(1 for t in by_node.values() if t == k8s.TRANSPORT_DIRECT)
    return {
        "by_node": by_node,
        "direct_nodes": direct,
        "proxy_nodes": len(by_node) - direct,
        "all_direct": bool(by_node) and direct == len(by_node),
        "blocked_reasons": blocked,
    }


def _parse_node_stats(summary: dict[str, Any]) -> dict[str, Any]:
    node = summary.get("node") or {}
    cpu = node.get("cpu") or {}
    mem = node.get("memory") or {}
    fs = node.get("fs") or {}
    io = node.get("io") or {}
    nano = cpu.get("usageNanoCores")
    return {
        "cpu_usage_cores": (nano / 1e9) if isinstance(nano, (int, float)) else None,
        "memory_working_set_bytes": mem.get("workingSetBytes"),
        "memory_available_bytes": mem.get("availableBytes"),
        "fs_used_bytes": fs.get("usedBytes"),
        "fs_capacity_bytes": fs.get("capacityBytes"),
        # None (not {}) when the kubelet reports no PSI at all — see _parse_psi.
        "psi_cpu": _parse_psi(cpu.get("psi")),
        "psi_memory": _parse_psi(mem.get("psi")),
        "psi_io": _parse_psi(io.get("psi") if isinstance(io, dict) else None),
    }


def _parse_pod_stats(summary: dict[str, Any]) -> dict[tuple[str, str], tuple[float, int]]:
    """``{(namespace, pod): (cpu_cores, mem_bytes)}`` from a kubelet summary."""
    out: dict[tuple[str, str], tuple[float, int]] = {}
    for pod in summary.get("pods") or []:
        ref = pod.get("podRef") or {}
        ns, nm = ref.get("namespace", ""), ref.get("name", "")
        if not nm:
            continue
        nano = (pod.get("cpu") or {}).get("usageNanoCores") or 0
        mem = (pod.get("memory") or {}).get("workingSetBytes") or 0
        out[(ns, nm)] = (nano / 1e9, int(mem))
    return out


def _pod_component(pod: dict[str, Any]) -> str:
    labels = (pod.get("metadata") or {}).get("labels") or {}
    comp = labels.get("app.kubernetes.io/component")
    if comp:
        return comp
    # Fallback: strip the chart's release prefixes off the pod name.
    name = (pod.get("metadata") or {}).get("name") or "?"
    for pre in ("spatium-control-spatiumddi-", "spatium-bootstrap-", "spatium-"):
        if name.startswith(pre):
            name = name[len(pre) :]
            break
    # Drop the random replica suffix (…-abc123-x9y2z / …-0).
    parts = name.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else name


def _pod_state(pod: dict[str, Any]) -> str:
    """Human state — surfaces a waiting reason (CrashLoopBackOff) over phase."""
    status = pod.get("status") or {}
    for cs in status.get("containerStatuses") or []:
        waiting = (cs.get("state") or {}).get("waiting") or {}
        reason = waiting.get("reason")
        if reason:
            return reason
    return status.get("phase") or "Unknown"


def _pod_owner_kind(pod: dict[str, Any]) -> str | None:
    owners = (pod.get("metadata") or {}).get("ownerReferences") or []
    return owners[0].get("kind") if owners else None


def _ready_counts(pod: dict[str, Any]) -> tuple[int, int]:
    css = (pod.get("status") or {}).get("containerStatuses") or []
    ready = sum(1 for c in css if c.get("ready"))
    return ready, len(css)


# ── assembly ───────────────────────────────────────────────────────────────


# ── cluster DNS (CoreDNS) — issue #985 ────────────────────────────────
#
# The k3s cluster runs CoreDNS for every pod's ``*.svc.cluster.local``
# lookup: the api pod finds Postgres and Redis through it, the frontend
# nginx finds the api through it, and a cluster member's supervisor
# heartbeats the in-cluster api Service name through it. We already ACT
# on it in exactly one place — ``ensure_coredns_ha`` patches the bundled
# Deployment to match replica count and spread to the node count,
# because a single replica on a lost node took the whole cluster
# NotReady for five minutes (#590, #750) — and showed nothing about it
# anywhere. A CoreDNS that is down, single-replica, or co-located on one
# node read as "everything healthy" until some unrelated pod restart
# failed to resolve.
#
# Health visibility only. This is not a CoreDNS driver, not a zone
# surface, and not a ``coredns-custom`` editor: CoreDNS is not a server
# operators put zones on and no LAN client ever talks to it.

#: The label upstream Kubernetes, k3s and GKE all put on their cluster
#: DNS pods, and what the ``kube-dns`` Service selects. Deliberately NOT
#: the Deployment name ``coredns`` — the umbrella chart's cluster health
#: renders on BYO clusters too, and GKE calls its deployment ``kube-dns``.
_CLUSTER_DNS_SELECTOR = ("k8s-app", "kube-dns")
_CLUSTER_DNS_NAMESPACE = "kube-system"

#: What ``ensure_coredns_ha`` targets: stock (1 replica) on a single
#: node, two replicas on distinct nodes once a second node exists.
#:
#: **Re-declared, not shared** — the patcher lives in the supervisor
#: (``agent/supervisor/spatium_supervisor/k8s_api.py``), a separate
#: deployable that versions independently of this image, so there is no
#: import to share. That means the two CAN drift: raise the supervisor's
#: cap and this card keeps expecting 2, which would make a correctly
#: scaled CoreDNS read as over-provisioned and — worse — stop the
#: ``cluster_dns_degraded`` alert firing, since ``ready >= expected``
#: would be satisfied by a stale target. If the supervisor's policy ever
#: becomes a variable, report the applied value on the heartbeat (the
#: #402 pattern) and render that instead of re-deriving it here.
_CLUSTER_DNS_MAX_REPLICAS = 2

#: The name every conformant cluster resolves, and the one thing we can
#: query that proves the whole path works without depending on anything
#: SpatiumDDI deployed.
_CLUSTER_DNS_PROBE_NAME = "kubernetes.default.svc.cluster.local"

#: Short on purpose. This runs inside the health snapshot, which the
#: Cluster dashboard streams — a slow probe would stall the whole page,
#: and "cluster DNS took longer than two seconds" is already the answer.
_CLUSTER_DNS_PROBE_TIMEOUT_S = 2.0


def _resolver_ip(path: str = "/etc/resolv.conf") -> str | None:
    """The nameserver this pod actually queries.

    Read from our own ``resolv.conf`` rather than from the ``kube-dns``
    Service object, for two reasons: it needs no ``services get`` grant
    we do not already hold, and it is the more honest number — it is the
    address pods really send to, which is what a resolution failure is
    about.

    Parsed by dnspython rather than by hand. It is already a hard
    dependency and already relied on for exactly this in the DNSBL sweep
    and the reverse-DNS resolver; a bespoke reader would handle only the
    bare ``nameserver <ip>`` form and silently return None (rendering
    "Resolver: unknown" and skipping the probe) on anything else.
    """
    try:
        import dns.resolver  # noqa: PLC0415

        nameservers = dns.resolver.Resolver(filename=path).nameservers
    except Exception:  # noqa: BLE001 - a missing/……unparseable file is "unknown"
        return None
    return str(nameservers[0]) if nameservers else None


#: How long a probe verdict is reused. The Cluster dashboard streams the
#: whole snapshot every 2 s per connected client, and the alert sweep
#: gathers it too — without this, one open tab means a live DNS query
#: every 2 s against the very CoreDNS the panel reports on, and five tabs
#: means 2.5 queries/s. Worse in the case this feature exists for: a
#: failing probe blocks its thread for the full 2 s timeout, so the
#: stream cadence halves for every unrelated panel on the page exactly
#: when cluster DNS is down.
#:
#: 15 s is well inside the "is DNS working right now" question's useful
#: resolution and collapses N streams into one probe per window.
_CLUSTER_DNS_PROBE_TTL_S = 15.0

#: ``(monotonic_deadline, verdict)``. Process-local and best-effort — a
#: torn read across threads would at worst reuse a verdict a moment
#: longer, so it needs no lock.
_probe_cache: tuple[float, dict[str, Any]] | None = None


def _cluster_dns_probe(resolver_ip: str | None) -> dict[str, Any]:
    """Resolve a known cluster name against ``resolver_ip``.

    **This is the load-bearing half.** Replica counts say the pods
    exist; the probe says the path works. ``ready=2, spread_ok=true,
    probe failed`` is a real and interesting state — a kube-proxy or
    flannel problem rather than a CoreDNS one — so it is reported as
    itself rather than collapsed into one boolean.
    """
    global _probe_cache

    if not resolver_ip:
        return {
            "ok": False,
            "latency_ms": None,
            "error": "no nameserver found in /etc/resolv.conf",
        }
    cached = _probe_cache
    if cached is not None and cached[0] > time.monotonic():
        # Copy: callers stamp ``from_node`` onto the returned dict, and a
        # shared mutable verdict would attribute one vantage's probe to
        # whichever replica read it next.
        return dict(cached[1])
    try:
        import dns.exception  # noqa: PLC0415
        import dns.resolver  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - dnspython is a hard dep
        return {"ok": False, "latency_ms": None, "error": f"dnspython unavailable: {exc}"}

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [resolver_ip]
    resolver.timeout = _CLUSTER_DNS_PROBE_TIMEOUT_S
    resolver.lifetime = _CLUSTER_DNS_PROBE_TIMEOUT_S
    started = time.monotonic()
    try:
        resolver.resolve(_CLUSTER_DNS_PROBE_NAME, "A")
    except dns.exception.DNSException as exc:
        # ``str()`` on a dnspython exception is sometimes empty (the #735
        # lesson), so fall back to the class name rather than reporting
        # an error of "".
        detail = str(exc) or exc.__class__.__name__
        return _cache_probe(
            {
                "ok": False,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "error": f"{_CLUSTER_DNS_PROBE_NAME} did not resolve via {resolver_ip}: {detail}",
            }
        )
    except OSError as exc:
        return _cache_probe(
            {
                "ok": False,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "error": f"could not reach {resolver_ip}: {exc}",
            }
        )
    return _cache_probe(
        {
            "ok": True,
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "error": None,
        }
    )


def _own_node_name() -> str | None:
    """Which node this api replica runs on.

    ``settings.node_name`` is populated from the downward API
    (``spec.nodeName``) by the api Deployment, and the slot endpoints
    already read it for the same purpose — so this is one reader of one
    field, not a second env-var convention to keep in step with the chart.
    """
    from app.config import settings  # noqa: PLC0415

    return settings.node_name or None


def _cache_probe(verdict: dict[str, Any]) -> dict[str, Any]:
    """Store ``verdict`` for :data:`_CLUSTER_DNS_PROBE_TTL_S` and return it."""
    global _probe_cache

    _probe_cache = (time.monotonic() + _CLUSTER_DNS_PROBE_TTL_S, dict(verdict))
    return verdict


def invalidate_probe_cache() -> None:
    """Drop the memoized probe verdict.

    Exists for the test suite, which resets every process-global TTL cache
    around each test — these are keyed on a monotonic clock, not on the
    per-test database, so a stubbed verdict outlives the TRUNCATE and
    leaks into unrelated tests on the same worker. Third instance of the
    pattern after ``maintenance_mode`` and ``feature_modules``.
    """
    global _probe_cache

    _probe_cache = None


def _cluster_dns_unavailable(detail: str) -> dict[str, Any]:
    """The shape callers get when cluster DNS could not be assessed.

    Every count is ``None``, never ``0``: a zero would render as "no
    replicas" — an alarming and wrong claim — where the truth is that we
    could not look. The same NULL-is-UNKNOWN rule the agent config-apply
    status follows (#882).
    """
    return {
        "available": False,
        "detail": detail,
        "resolver_ip": None,
        "replicas_ready": None,
        "replicas_total": None,
        "expected_replicas": None,
        "nodes": [],
        "spread_ok": None,
        "resolve_probe": None,
        "checked_at": datetime.now(UTC).isoformat(),
    }


def _cluster_dns_health(
    pods_raw: list[dict[str, Any]],
    *,
    nodes_total: int,
    pods_listable: bool,
    from_node: str | None,
) -> dict[str, Any]:
    """Build the ``cluster_dns`` block from the pod list already fetched.

    No new RBAC: replicas and placement come from the cluster-wide pod
    list the snapshot fetches anyway, filtered on the cluster-DNS label.
    On someone else's cluster, where the ServiceAccount may not be able
    to list ``kube-system``, this degrades to ``available: false`` with a
    reason rather than reporting an empty deployment.
    """
    # **The probe runs first, and unconditionally.** It needs no RBAC at
    # all — it is a DNS query from this pod — whereas the replica view
    # needs a cluster-wide pod list. The Celery worker's ServiceAccount
    # deliberately does NOT carry that grant (see
    # charts/spatiumddi/templates/worker-rbac.yaml), and the alert
    # evaluator runs in the worker: with the probe behind the
    # pods-listable gate, the rule raised AlertDataUnavailable on every
    # tick forever, so CoreDNS could be entirely down and the alert stayed
    # silent while showing as enabled. Running the probe first is also
    # what makes the "second vantage" claim true rather than aspirational.
    resolver_ip = _resolver_ip()
    probe = _cluster_dns_probe(resolver_ip)
    probe["from_node"] = from_node

    if not pods_listable:
        out = _cluster_dns_unavailable(
            "pods could not be listed, so cluster DNS replicas are unknown — grant the "
            "api ServiceAccount cluster-wide pod read to populate this card. The "
            "resolve probe below still reports whether cluster DNS answers."
        )
        out["resolver_ip"] = resolver_ip
        out["resolve_probe"] = probe
        return out

    key, value = _CLUSTER_DNS_SELECTOR
    dns_pods = [
        p
        for p in pods_raw
        if (p.get("metadata") or {}).get("namespace") == _CLUSTER_DNS_NAMESPACE
        and ((p.get("metadata") or {}).get("labels") or {}).get(key) == value
    ]

    if not dns_pods:
        # An empty *result* is different from an unreadable list. Both
        # leave the counts unknown, but this one is worth its own
        # sentence: on a BYO cluster it usually means the cluster labels
        # its DNS differently, not that DNS is missing — and the probe
        # right above will have said whether resolution works.
        out = _cluster_dns_unavailable(
            f"no pods matching {key}={value} in {_CLUSTER_DNS_NAMESPACE} — this cluster "
            "may label its DNS differently. The resolve probe below still reports "
            "whether cluster DNS actually answers."
        )
        out["resolver_ip"] = resolver_ip
        out["resolve_probe"] = probe
        return out

    ready_nodes: list[str] = []
    replicas_ready = 0
    for p in dns_pods:
        phase = (p.get("status") or {}).get("phase")
        if phase in ("Succeeded", "Failed"):
            continue
        ready_n, total_n = _ready_counts(p)
        if phase == "Running" and total_n > 0 and ready_n == total_n:
            replicas_ready += 1
            node = (p.get("spec") or {}).get("nodeName")
            if node:
                ready_nodes.append(node)

    live_pods = [
        p for p in dns_pods if (p.get("status") or {}).get("phase") not in ("Succeeded", "Failed")
    ]
    # ``ensure_coredns_ha``'s own target, not the Deployment's
    # ``spec.replicas`` — reading that would need a ``deployments get``
    # grant in kube-system that this snapshot does not hold, and on a BYO
    # cluster it is not ours to have an opinion about anyway.
    expected = min(nodes_total, _CLUSTER_DNS_MAX_REPLICAS) if nodes_total else None

    spread_ok: bool | None
    if expected is None:
        spread_ok = None
    else:
        # Both halves matter, and the second is the one #633 was filed
        # for: two replicas parked on the SAME node is not HA, and
        # Kubernetes never rebalances running pods, so it stays that way
        # until something forces a reschedule.
        spread_ok = replicas_ready >= expected and len(set(ready_nodes)) == len(ready_nodes)

    return {
        "available": True,
        "detail": None,
        "resolver_ip": resolver_ip,
        "replicas_ready": replicas_ready,
        "replicas_total": len(live_pods),
        "expected_replicas": expected,
        "nodes": sorted(set(ready_nodes)),
        "spread_ok": spread_ok,
        "resolve_probe": probe,
        "checked_at": datetime.now(UTC).isoformat(),
    }


def _unavailable(detail: str) -> dict[str, Any]:
    return {
        "available": False,
        "detail": detail,
        "nodes_total": 0,
        "nodes_ready": 0,
        "pods_total": 0,
        "pods_running": 0,
        "pods_by_phase": {},
        "kubelet_version": None,
        "is_ha": False,
        "control_plane_nodes": 0,
        "metrics_available": False,
        # #983 Phase 2 item 6 — which kubelet transport served, so the
        # apiserver-proxy fallback is visible instead of silent.
        "kubelet_transport": {
            "by_node": {},
            "direct_nodes": 0,
            "proxy_nodes": 0,
            "all_direct": False,
            "blocked_reasons": {},
        },
        "cpu_usage_cores": None,
        "cpu_capacity_cores": None,
        "memory_working_set_bytes": None,
        "memory_capacity_bytes": None,
        # #985 — present even here so the key never has to be probed for.
        "cluster_dns": _cluster_dns_unavailable(detail),
        "nodes": [],
        "workloads": [],
        "top_pods_cpu": [],
        "top_pods_mem": [],
    }


def cluster_unavailable(detail: str) -> dict[str, Any]:
    """Public unavailable snapshot — used by the SSE stream when kubeapi is
    momentarily unreachable so the live dashboard shows a reason, not a stall."""
    return _unavailable(detail)


def _apply_cnpg_instances(
    workloads: list[dict[str, Any]],
    clusters: set[tuple[str, str]],
    components: set[str],
) -> None:
    """Take the database row's verdict from CNPG, not a pod count (#1387).

    A pod count cannot see what CNPG wants. A join Job that failed for good
    leaves only ``Failed`` pods, which are skipped, so a cluster that wants
    three instances read 2/2 healthy indefinitely; and during first
    bootstrap, while ``-initdb`` runs and no instance pod exists, there was
    no database row at all. So for one CNPG Cluster the row reads
    ``status.readyInstances`` of ``spec.instances`` (the check the rolling
    upgrade already makes, ``safety.check_cnpg_instances_ready``), and
    ``source`` says which. When the Cluster cannot be read (a 403, a non-CNPG
    install, or more than one Cluster) the pod rollup stands, marked
    ``source: "pods"``.
    """
    # The component CNPG's pods roll up under (``database`` from CNPG's own
    # app.kubernetes.io/component label), not a hard-coded name.
    if len(components) != 1:
        return
    comp = next(iter(components))
    row = next((w for w in workloads if w["component"] == comp), None)
    if row is not None:
        row["source"] = "pods"
    if len(clusters) != 1:
        return
    name, namespace = next(iter(clusters))
    try:
        status_code, body = k8s.get_cnpg_cluster(name, namespace=namespace or None)
    except k8s.KubeapiUnavailableError:
        return
    if status_code != 200 or not body:
        return
    wanted = int((body.get("spec") or {}).get("instances") or 0)
    if wanted <= 0:
        return
    ready = int((body.get("status") or {}).get("readyInstances") or 0)
    if row is None:
        row = {
            "component": comp,
            "kind": "Cluster",
            "ready": 0,
            "total": 0,
            "restarts": 0,
            "jobs_running": 0,
        }
        workloads.append(row)
    row["ready"] = min(ready, wanted)
    row["total"] = wanted
    row["source"] = "cnpg"
    if ready >= wanted and not row.get("jobs_running"):
        row["status"] = "healthy"
    elif ready > 0:
        row["status"] = "degraded"
    else:
        row["status"] = "down"


def get_cluster_health() -> dict[str, Any]:
    """Gather a full cluster-health snapshot. Synchronous (stdlib kubeapi).

    Raises ``k8s.KubeapiUnavailableError`` only when the ServiceAccount isn't
    mounted (non-k8s / non-appliance) — the router maps that to 503. A 403 on
    the node read (RBAC not granted) is returned as ``available=False`` with a
    diagnostic ``detail`` rather than an error, so the UI can explain it.
    """
    nstatus, nodes_raw = k8s.list_nodes()
    if nstatus == 403:
        return _unavailable(
            "The api ServiceAccount can't read Nodes — enable "
            "api.upgradeOrchestratorRBAC (the appliance default) and re-apply the chart."
        )
    if nstatus != 200:
        return _unavailable(f"kubeapi node list returned HTTP {nstatus}")

    pods_listable = True
    try:
        pstatus, pods_raw = k8s.list_all_pods()
        # A 403 returns (status, []) rather than raising, so without this
        # the cluster-DNS block would read an empty list as "no CoreDNS
        # pods" — an alarming claim about a cluster we simply cannot see.
        pods_listable = pstatus == 200
    except k8s.KubeapiUnavailableError:
        pods_raw = []
        pods_listable = False

    # Per-node kubelet Summary API (CPU / mem / fs + per-pod usage, and PSI
    # since 1.36). Degrades cleanly to "no live usage" when NEITHER transport
    # is granted (403 on both) or a kubelet is briefly unreachable.
    node_stats: dict[str, dict[str, Any]] = {}
    pod_usage: dict[tuple[str, str], tuple[float, int]] = {}
    metrics_available = False
    # #983 Phase 2 item 6 — record the transport PER NODE. A single value
    # would report whichever node was processed last, which can read "direct"
    # while another node was quietly served by the proxy — the exact wrong
    # answer to "is it safe to drop the nodes/proxy grant?".
    transport_by_node: dict[str, str] = {}
    transport_ip_by_node: dict[str, str] = {}
    for n in nodes_raw:
        nm = (n.get("metadata") or {}).get("name")
        if not nm:
            continue
        node_ip = _internal_ip(n)
        try:
            # Hand the node IP over so the direct kubelet transport
            # (``nodes/stats``) can be tried before the apiserver proxy
            # (``nodes/proxy``, which authorizes read GETs to every kubelet
            # endpoint). Falls back per node on its own; see k8s.py.
            sstatus, summary, transport = k8s.get_node_stats_summary(nm, node_ip)
        except k8s.KubeapiUnavailableError:
            continue
        transport_by_node[nm] = transport
        if node_ip:
            transport_ip_by_node[nm] = node_ip
        if sstatus == 200 and summary:
            metrics_available = True
            node_stats[nm] = _parse_node_stats(summary)
            pod_usage.update(_parse_pod_stats(summary))

    # ── nodes ──
    nodes: list[dict[str, Any]] = []
    nodes_ready = 0
    control_plane_nodes = 0
    cluster_cpu_used = 0.0
    cluster_cpu_cap = 0.0
    cluster_mem_used = 0
    cluster_mem_cap = 0
    kubelet_version: str | None = None
    pods_on_node: dict[str, int] = {}
    for p in pods_raw:
        nn = (p.get("spec") or {}).get("nodeName")
        if nn:
            pods_on_node[nn] = pods_on_node.get(nn, 0) + 1

    for n in nodes_raw:
        meta = n.get("metadata") or {}
        name = meta.get("name") or "?"
        info = (n.get("status") or {}).get("nodeInfo") or {}
        cap = (n.get("status") or {}).get("capacity") or {}
        roles = _node_roles(n)
        ready = k8s.is_node_ready(n)
        if ready:
            nodes_ready += 1
        if "control-plane" in roles or "master" in roles:
            control_plane_nodes += 1
        kubelet_version = kubelet_version or info.get("kubeletVersion")
        stats = node_stats.get(name) or {}
        cpu_cap = _cpu_cores(cap.get("cpu"))
        mem_cap = _mem_bytes(cap.get("memory"))
        if stats.get("cpu_usage_cores") is not None:
            cluster_cpu_used += stats["cpu_usage_cores"]
        if cpu_cap:
            cluster_cpu_cap += cpu_cap
        if stats.get("memory_working_set_bytes"):
            cluster_mem_used += int(stats["memory_working_set_bytes"])
        if mem_cap:
            cluster_mem_cap += mem_cap
        nodes.append(
            {
                "name": name,
                "ready": ready,
                "roles": roles,
                "schedulable": not (n.get("spec") or {}).get("unschedulable", False),
                "kubelet_version": info.get("kubeletVersion"),
                "os_image": info.get("osImage"),
                "kernel": info.get("kernelVersion"),
                "container_runtime": info.get("containerRuntimeVersion"),
                "architecture": info.get("architecture"),
                "internal_ip": _internal_ip(n),
                "age_seconds": _age_seconds(meta.get("creationTimestamp")),
                "memory_pressure": _node_condition(n, "MemoryPressure"),
                "disk_pressure": _node_condition(n, "DiskPressure"),
                "pid_pressure": _node_condition(n, "PIDPressure"),
                "cpu_capacity_cores": cpu_cap,
                "memory_capacity_bytes": mem_cap,
                "pods_capacity": int(cap["pods"]) if cap.get("pods") else None,
                "pods_running": pods_on_node.get(name, 0),
                "cpu_usage_cores": stats.get("cpu_usage_cores"),
                "memory_working_set_bytes": stats.get("memory_working_set_bytes"),
                "memory_available_bytes": stats.get("memory_available_bytes"),
                "fs_used_bytes": stats.get("fs_used_bytes"),
                "fs_capacity_bytes": stats.get("fs_capacity_bytes"),
                # #983 Phase 2 — PSI. null means the kubelet did not report it
                # (pre-1.36, or the feature gate off), NOT "no pressure".
                "psi_cpu": stats.get("psi_cpu"),
                "psi_memory": stats.get("psi_memory"),
                "psi_io": stats.get("psi_io"),
                # #402 — host disk partitions are merged in by the router from
                # the supervisor's cluster_health JSONB (the api pod can't see
                # host partitions itself); empty here so the shape is stable.
                "host_disk_partitions": [],
                # #999 Part A — md / multipath state, merged in the same way.
                # None, not {}: a node the supervisor has not reported storage
                # for is UNKNOWN, and an empty snapshot would read as "no
                # arrays, all clear".
                "host_storage": None,
            }
        )

    # ── pods + workload rollup + top pods ──
    pods_by_phase: dict[str, int] = {}
    pods_running = 0
    pod_rows: list[dict[str, Any]] = []
    rollup: dict[str, dict[str, Any]] = {}
    # Job pods still running per component (#1213): a CNPG
    # ``postgresql-N-join`` pod means an instance is still being created.
    jobs_running: dict[str, int] = {}
    # #1387 — the CNPG Clusters behind the database pods, from the label CNPG
    # puts on every pod it runs (instances, and its initdb / join Jobs).
    cnpg_clusters: set[tuple[str, str]] = set()
    cnpg_components: set[str] = set()
    for p in pods_raw:
        meta = p.get("metadata") or {}
        status = p.get("status") or {}
        ns = meta.get("namespace") or ""
        name = meta.get("name") or "?"
        cnpg_name = (meta.get("labels") or {}).get("cnpg.io/cluster")
        if cnpg_name:
            cnpg_clusters.add((str(cnpg_name), ns))
            cnpg_components.add(_pod_component(p))
        phase = status.get("phase") or "Unknown"
        pods_by_phase[phase] = pods_by_phase.get(phase, 0) + 1
        if phase == "Running":
            pods_running += 1
        ready_n, total_n = _ready_counts(p)
        restarts = sum(c.get("restartCount", 0) for c in status.get("containerStatuses") or [])
        cpu_u, mem_u = pod_usage.get((ns, name), (None, None))
        comp = _pod_component(p)
        owner = _pod_owner_kind(p)
        terminal = phase in ("Succeeded", "Failed")
        row = {
            "name": name,
            "namespace": ns,
            "component": comp,
            "node": (p.get("spec") or {}).get("nodeName"),
            "phase": phase,
            "state": _pod_state(p),
            "ready": f"{ready_n}/{total_n}" if total_n else "0/0",
            "restarts": restarts,
            "age_seconds": _age_seconds(meta.get("creationTimestamp")),
            "cpu_usage_cores": cpu_u,
            "memory_working_set_bytes": mem_u,
        }
        pod_rows.append(row)

        # Workload rollup — Job pods are not serving instances, so none of
        # them count toward a workload's ready / total (#1213). A running one
        # used to: CNPG's join pod read as a third ready database pod while
        # CNPG itself reported two instances, "Creating a new replica". A
        # Job still running instead keeps its component off "healthy" below.
        if owner == "Job":
            if not terminal:
                jobs_running[comp] = jobs_running.get(comp, 0) + 1
            continue
        agg = rollup.setdefault(
            comp,
            {"component": comp, "kind": owner, "ready": 0, "total": 0, "restarts": 0},
        )
        agg["total"] += 1
        agg["restarts"] += restarts
        fully_ready = (total_n > 0 and ready_n == total_n) or phase == "Succeeded"
        if fully_ready:
            agg["ready"] += 1
        if agg["kind"] is None:
            agg["kind"] = owner

    workloads: list[dict[str, Any]] = []
    for comp, agg in rollup.items():
        # Carried on the row so a "degraded" at ready == total says why,
        # rather than reading as 2/2 and degraded with no explanation.
        n_jobs = jobs_running.get(comp, 0)
        if agg["ready"] == agg["total"] and agg["total"] > 0 and not n_jobs:
            wstatus = "healthy"
        elif agg["ready"] > 0:
            wstatus = "degraded"
        else:
            wstatus = "down"
        workloads.append({**agg, "jobs_running": n_jobs, "status": wstatus})
    _apply_cnpg_instances(workloads, cnpg_clusters, cnpg_components)
    workloads.sort(
        key=lambda w: (
            (
                _COMPONENT_ORDER.index(w["component"])
                if w["component"] in _COMPONENT_ORDER
                else len(_COMPONENT_ORDER)
            ),
            w["component"],
        )
    )

    with_cpu = [r for r in pod_rows if r["cpu_usage_cores"] is not None]
    with_mem = [r for r in pod_rows if r["memory_working_set_bytes"] is not None]
    top_pods_cpu = sorted(with_cpu, key=lambda r: r["cpu_usage_cores"], reverse=True)[
        :_TOP_POD_LIMIT
    ]
    top_pods_mem = sorted(with_mem, key=lambda r: r["memory_working_set_bytes"], reverse=True)[
        :_TOP_POD_LIMIT
    ]

    return {
        "available": True,
        "detail": None,
        "nodes_total": len(nodes_raw),
        "nodes_ready": nodes_ready,
        "pods_total": len(pod_rows),
        "pods_running": pods_running,
        "pods_by_phase": pods_by_phase,
        "kubelet_version": kubelet_version,
        "is_ha": control_plane_nodes > 1,
        "control_plane_nodes": control_plane_nodes,
        "metrics_available": metrics_available,
        "kubelet_transport": _kubelet_transport_report(transport_by_node, transport_ip_by_node),
        # #985. The probe is labelled with the node this api replica runs
        # on: on a multi-node control plane the request is served by
        # whichever replica took it, and a probe that passes on node 1
        # says nothing about node 3.
        "cluster_dns": _cluster_dns_health(
            pods_raw,
            nodes_total=len(nodes_raw),
            pods_listable=pods_listable,
            from_node=_own_node_name(),
        ),
        "cpu_usage_cores": round(cluster_cpu_used, 4) if metrics_available else None,
        "cpu_capacity_cores": round(cluster_cpu_cap, 4) if cluster_cpu_cap else None,
        "memory_working_set_bytes": cluster_mem_used if metrics_available else None,
        "memory_capacity_bytes": cluster_mem_cap or None,
        "nodes": nodes,
        "workloads": workloads,
        "top_pods_cpu": top_pods_cpu,
        "top_pods_mem": top_pods_mem,
    }
