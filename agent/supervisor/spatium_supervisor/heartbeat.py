"""Periodic heartbeat to the control plane (#170 Wave C1).

Replaces the appliance-host telemetry the DNS / DHCP service agents
used to ship on their own per-row heartbeats in #138 Phase 8f-2. The
supervisor is now the single producer; service-container heartbeats
keep carrying service-level state (last_seen, agent_version, server
identity) but the appliance-host block (slot, deployment_kind,
upgrade state, snmpd/chrony status) lives here.

Loop shape:

1. Snapshot ``appliance_state.collect()`` for telemetry.
2. POST to ``/api/v1/appliance/supervisor/heartbeat`` with the
   appliance_id + telemetry + capabilities.
3. Backend persists + returns ``{desired_appliance_version,
   desired_slot_image_url, reboot_requested}``.
4. Compare desired to the local state; fire trigger files via
   ``appliance_state.maybe_fire_*``. Idempotent — trigger-file
   presence guards against double-firing.
5. Sleep ``heartbeat_interval_seconds``; repeat.

Auth: session-token interim. The supervisor cached the cleartext
token from the register response; we present it on every heartbeat
until the cert-issuance path lands the mTLS switch in C2/D. Approved
appliances no longer carry a session_token server-side; the backend
accepts heartbeat from any approved row in this interim window
(see SupervisorHeartbeatRequest docstring).

Network failures are logged but never raise into the caller — the
loop keeps running so a transient control-plane outage doesn't kill
the supervisor.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import httpx
import structlog

from . import appliance_state, approval_state, firewall_peer_audit, watchdog
from .cert_auth import build_auth_headers, load_cert, save_cert
from .config import SupervisorConfig
from .firewall_renderer import FirewallProfile, render_drop_in
from .identity import Identity
from .role_orchestrator import (
    compute_target_env,
    probe_port_conflicts,
    render_env_file,
)

# Issue #183 Phase 7 — k3s-only lifecycle. The pre-Phase-7 dispatcher
# (compose vs k3s on ``detect_runtime()``) is gone with the rest of
# docker; this is the only path now.
from .service_lifecycle import (
    apply_role_assignment,
    reconcile_node_labels,
    role_release_fingerprint,
    tear_down_supervised_services,
)

log = structlog.get_logger(__name__)

# #170 Wave C2 — role-driven compose env file. Written under the
# supervisor's state-dir so it survives slot swaps; the operator's
# baked compose file references it via ``--env-file`` (Wave C3
# subprocess piece). C2 ships only the env render; C3 wires the
# actual ``docker compose up -d`` invocation.
_ROLE_ENV_FILENAME = "role-compose.env"

# #170 Wave C3 — nftables drop-in path. Lives under /etc/nftables.d
# (bind-mounted rw on the supervisor compose entry). The host's
# Phase 9 trigger-file path used by spatium-firewall-reload.path on
# the host. Mounted into the supervisor pod via the
# /var/lib/spatiumddi-host/release-state hostPath bind (same dir
# used by snmp / chrony / slot-upgrade triggers). Writing to this
# path = "host runner please re-render".
_NFT_TRIGGER_PATH = Path("/var/lib/spatiumddi-host/release-state/firewall-pending")
_NFT_APPLIED_HASH_PATH = Path(
    "/var/lib/spatiumddi-host/release-state/firewall-applied-hash"
)

# #272 — in-cluster control-plane API Service. Every control-plane
# node runs the api Deployment behind this headless-routable
# ClusterIP Service, so a supervisor that is itself a cluster member
# should heartbeat *the cluster*, not the seed node's IP that was
# baked into CONTROL_PLANE_URL at install/join time. Reasons:
#   * The seed IP is a single point of failure — if that one node is
#     down, every other node's supervisor would lose its control
#     plane even though the api is healthy on the surviving nodes.
#   * kube-proxy load-balances the Service across all ready api pods,
#     so heartbeats spread across the cluster instead of hammering
#     one node.
# Remote (off-cluster) DNS/DHCP agents keep using their configured
# CONTROL_PLANE_URL — ideally the MetalLB VIP — since they have no
# in-cluster DNS to resolve the .svc name. See
# ``_effective_control_plane_url`` for the member-vs-remote split.
# Trailing dot is load-bearing (#777). Without it the name has 4 dots, which
# is under the pod's ``ndots:5``, so the resolver walks its search list first —
# and kubelet appends the NODE's own DHCP search domain to every pod's list. If
# that domain's zone answers NOERROR/NODATA (rather than NXDOMAIN) for a
# nonexistent name — Cloudflare-hosted zones do, among others — musl stops the
# walk there and returns EAI_NODATA without ever trying the bare name. The
# supervisor then never registers, on a network it has no control over. The dot
# makes the name absolute and skips the search list entirely.
_IN_CLUSTER_CONTROL_PLANE_URL = (
    "http://spatium-control-spatiumddi-api.spatium.svc.cluster.local.:8000"
)


def _is_control_plane_member() -> bool:
    """True when this supervisor runs on a node that is part of the
    control-plane k3s cluster (the seed itself, or an appliance that
    has been promoted and finished joining).

    Two independent signals, either is sufficient:
      * ``detect_appliance_variant() == "control-plane"`` — the node
        was installed as a control-plane seed.
      * ``read_cluster_join_state()[0] == "ready"`` — an appliance
        that was promoted into the control plane and whose host
        runner has reported the join completed.
    """
    if appliance_state.detect_appliance_variant() == "control-plane":
        return True
    join_state, _ = appliance_state.read_cluster_join_state()
    return join_state == "ready"


def _effective_control_plane_url(cfg: SupervisorConfig) -> str:
    """Resolve the heartbeat target.

    Cluster members talk to the in-cluster api Service (resilient to
    any single node loss + load-balanced); everyone else uses the
    configured ``CONTROL_PLANE_URL``. Returns ``""`` only when a
    non-member has no configured URL — the caller skips the
    heartbeat in that case.
    """
    if _is_control_plane_member():
        return _IN_CLUSTER_CONTROL_PLANE_URL
    return cfg.control_plane_url


# Issue #183 Phase 7 — capability reporting is now trivially true on
# any baked appliance. The slot's containerd content store is
# preloaded with every service image (see appliance/scripts/bake-
# images.sh + k3s's airgap-images auto-import). If we got far enough
# to be sending heartbeats, the images are there. Hardcoded to True
# instead of probing /var/run/docker.sock (which doesn't exist
# anymore — the appliance is k3s-only).
#
# Issue #566 — ``can_run_looking_glass`` (the BGP Looking Glass
# collector, GoBGP) joins this tuple rather than getting its own
# bespoke always-true literal (like ``can_run_observer`` below): it
# has a real service container (the ``looking-glass`` image), baked
# into every slot per decision D3, so it belongs alongside DNS/DHCP.
_CAPABILITY_FLAGS = (
    "can_run_dns_bind9",
    "can_run_dns_powerdns",
    "can_run_dns_technitium",
    "can_run_dhcp",
    "can_run_looking_glass",
)


def _detect_storage_type() -> str:
    """Return ``"ssd"`` / ``"hdd"`` / ``"unknown"`` for the host's
    root block device.

    Phase 10 follow-up: the supervisor runs inside a k3s pod so its
    own /proc/mounts shows ``overlay`` mounted at / — the
    ``/dev/<name>`` parse below always falls through to "unknown".
    Fix: firstboot writes a sidecar at /var/lib/spatiumddi-host/
    release-state/host-storage-type (mounted into the pod via the
    existing release-state hostPath) with the host-detected value.
    Read that first; fall back to in-pod detection for non-
    appliance deployments where the sidecar isn't present.
    """
    sidecar = Path("/var/lib/spatiumddi-host/release-state/host-storage-type")
    if sidecar.exists():
        try:
            value = sidecar.read_text(encoding="utf-8").strip()
            if value in ("ssd", "hdd", "unknown"):
                return value
        except OSError as exc:
            # Sidecar present but unreadable (permissions / mid-write).
            # Fall through to in-pod detection below; log so a recurring
            # bind-mount permission regression doesn't stay hidden.
            log.debug(
                "supervisor.storage_type.sidecar_read_failed",
                path=str(sidecar),
                error=str(exc),
            )
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "/":
                    dev = parts[0]
                    if dev.startswith("/dev/"):
                        name = dev[5:]
                        while name and name[-1].isdigit():
                            name = name[:-1]
                        if name.endswith("p"):
                            name = name[:-1]
                        rot_path = f"/sys/block/{name}/queue/rotational"
                        try:
                            with open(rot_path, "r", encoding="utf-8") as r:
                                return "hdd" if r.read().strip() == "1" else "ssd"
                        except OSError:
                            return "unknown"
                    break
    except OSError:
        pass
    return "unknown"


def _detect_host_nics() -> list[str]:
    """Return the appliance's physical / virtual NIC names (e.g.
    ``["ens18", "eth0"]``). Skips loopback, docker bridges, virtual
    veth pairs, and the container's own bridge interface so the list
    is the operator-visible host hardware."""
    nics: list[str] = []
    try:
        import os

        for name in sorted(os.listdir("/sys/class/net")):
            if name == "lo":
                continue
            if name.startswith(("docker", "br-", "veth", "virbr", "tailscale")):
                continue
            nics.append(name)
    except OSError:
        pass
    return nics


def _capabilities_payload() -> dict[str, Any]:
    """Build the supervisor-capabilities block reported on every
    heartbeat. Matches the schema in issue #170 ("Multi-role +
    capability reporting"):

    * ``can_run_dns_bind9`` / ``can_run_dns_powerdns`` /
      ``can_run_dns_technitium`` / ``can_run_dhcp`` /
      ``can_run_looking_glass`` — hardcoded
      ``True`` post-Phase-7 (looking-glass joins under #566). The
      slot's containerd content store is preloaded with every
      service image; if we're heartbeating, the images are there.
    * ``can_run_observer`` — always true. The observer role is a
      pure supervisor-side metrics/log shipper with no separate
      service container, so any approved supervisor can run it.
    * ``has_baked_images`` — true on appliance deployments. The
      slot's ``/var/lib/rancher/k3s/agent/images/*.tar.zst`` archives
      pre-load containerd; nothing pulls at runtime.
    * ``supervisor_version`` — packaging metadata.
    * ``cpu_count`` / ``memory_mb`` — host capacity from /proc.
    * ``storage_type`` — ``"ssd"`` / ``"hdd"`` / ``"unknown"``.
    * ``host_nics`` — physical / virtual NIC names (lo + docker
      bridges filtered out).
    """
    out: dict[str, Any] = {
        "has_baked_images": appliance_state.detect_deployment_kind() == "appliance",
        "supervisor_version": _supervisor_version(),
        # observer is always compatible (#170 multi-role table:
        # "always compatible") — no service container needed, the
        # supervisor itself is the observer.
        "can_run_observer": True,
    }
    # Every baked appliance has every service image preloaded; the
    # control plane's role-checkbox UI uses these flags to gate
    # operator choice, and the answer is "yes, you can pick any role".
    for cap_field in _CAPABILITY_FLAGS:
        out[cap_field] = True
    try:
        import os

        cpu = os.cpu_count()
        if cpu is not None:
            out["cpu_count"] = cpu
    except Exception:  # noqa: BLE001
        pass
    try:
        # /proc/meminfo is small + parseable without psutil.
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    out["memory_mb"] = kb // 1024
                    break
    except OSError:
        pass
    out["storage_type"] = _detect_storage_type()
    out["host_nics"] = _detect_host_nics()
    return out


def _supervisor_version() -> str:
    from . import __version__

    return __version__


# #170 Wave E — periodic service-container watchdog. Heartbeat
# carries the watchdog's last verdict to the control plane (one
# entry per assigned compose service). Watchdog itself fires every
# ``_WATCHDOG_INTERVAL_S`` (5 min by default) — same shape as the
# firewall drift check below: a short throttled run shared across
# multiple heartbeats so the watchdog signal is fresh without
# spamming the docker daemon every minute.
_WATCHDOG_INTERVAL_S = 300.0  # 5 minutes
_last_watchdog_at: float = 0.0
_cached_role_health: dict[str, Any] = {}

# #285 Phase 5 — throttle for the warn-only etcd/peer-drift cross-check.
_PEER_DRIFT_INTERVAL_S = 300.0  # 5 minutes
_last_peer_drift_at: float = 0.0

# #272 Phase 9 — k8s Node names this seed has successfully evicted but
# the backend hasn't yet confirmed cleared. Reported on each heartbeat
# request; pruned once the backend drops the name from its evict list.
_evicted_pending: set[str] = set()

# #1058 — hostnames whose stranded CNPG claims the reclaim still owes (a
# deferral: the instance was the primary, or the Cluster named none). Handed
# back to the sweep as evicted names next tick so it scans past its
# "Postgres is whole" early-out; cleared by the tick that settles them.
_stranded_pending: set[str] = set()


class _ReplaceHold:
    """#1059 — the CloudNativePG size hold a dead-node replace arms.

    ``/fleet/control-plane/{id}/replace`` drops the replaced row from the
    committed control-plane count at once and asks the seed to evict its
    Node, so from the eviction tick until the replacement is promoted the
    count the heartbeat carries is one short of what the cluster is
    committed to — and a replace is never a scale-down by intent (the
    product refuses an even count). Only ``/replace`` sets
    ``evict_requested``; a demote is a ``leaving`` row, never an eviction —
    so an eviction tick is a replace tick by construction. The hold is
    armed on it and kept until the count is back at the size CNPG has
    (``settle``: the replacement settled) or the operator shrinks the
    control plane below the count the eviction tick carried (a deliberate
    demote: the slot is abandoned). Module state, like ``_evicted_pending``:
    a supervisor restart mid-replace forgets it, and ``patch_cnpg_instances``'s
    own readiness guard covers the rest of the install window (the Cluster
    is not whole until the replacement joins).
    """

    def __init__(self) -> None:
        self.armed = False
        self.cp_size = 0
        self.nodes: list[str] = []

    def _why(self, cp_size: int) -> str:
        return (
            f"replacing {self.nodes}: the committed count {cp_size} is short until the "
            "replacement is promoted"
        )

    def reason(self, evict_names: Iterable[str], cp_size: int) -> str:
        """Arm (or re-arm) on an eviction tick; otherwise why this tick must
        not scale CNPG down, or ``""`` when it may."""
        evicting = sorted(str(n) for n in evict_names if n)
        if evicting:
            self.armed, self.cp_size, self.nodes = True, cp_size, evicting
            return self._why(cp_size)
        if not self.armed:
            return ""
        if cp_size < self.cp_size:
            # Below what the eviction left: the operator demoted on purpose.
            self.clear()
            return ""
        return self._why(cp_size)

    def settle(self, cp_size: int, current_spec: int | None) -> None:
        """Release once the committed count is back at (or above) the size
        CNPG has — ``current_spec`` is ``spec.instances`` as the tick read it;
        an unreadable Cluster keeps the hold."""
        if self.armed and current_spec is not None and cp_size >= current_spec:
            self.clear()

    def clear(self) -> None:
        self.armed, self.cp_size, self.nodes = False, 0, []


_replace_hold = _ReplaceHold()


def _carry_stranded(previous: set[str], evicted_now: list[str], outcome) -> set[str]:
    """PURE — what the next tick must force: after a clean sweep, exactly
    what it left owed; after a failed one (kubeapi error), everything that
    was owed plus this tick's evictions, so an outage never drops a node."""
    if outcome.error is not None:
        return set(previous) | {str(n) for n in evicted_now}
    return set(outcome.pending_nodes)


def _watchdog_check_due() -> bool:
    """First call always returns True (forces a probe within the
    first watchdog cadence after startup); subsequent calls gate on
    monotonic elapsed."""
    return time.monotonic() - _last_watchdog_at >= _WATCHDOG_INTERVAL_S


# Phase 9 rewrite — the pre-Phase-9 drift detector (live nft -j
# parse + missing-port diff) ran from inside the supervisor pod
# where nft can't actually read the host's ruleset, so it was
# always force-re-applying. The new trigger-file shape inverts the
# responsibility: the host runner is the source of truth (writes
# the applied-hash sidecar), the supervisor compares the rendered
# body's hash to the sidecar each tick. Operator's manual nft
# edits → host runner doesn't write a new sidecar → mismatch on
# next supervisor tick → trigger fires → canonical state restored.
# The drift-port-list helpers from the in-pod era are gone.


def _maybe_apply_firewall(
    role_assignment: dict[str, Any] | None,
    log: structlog.stdlib.BoundLogger,
    cluster_peer_cidrs: list[Any] | None = None,
    *,
    pod_cidrs: list[Any] | None = None,
    service_cidrs: list[Any] | None = None,
    cp_member_count: int = 1,
    vip_configured: bool = False,
    web_ui_allowed_cidrs: list[Any] | None = None,
    ssh_scope_cidrs: list[Any] | None = None,
) -> None:
    """Render the firewall drop-in + write a trigger file the host
    runner picks up.

    Phase 9 rewrite (#183): the pre-Phase-9 path tried to write
    /etc/nftables.d/spatium-role.nft directly and call ``nft -f
    /etc/nftables.conf`` from inside the supervisor pod. Neither
    worked — the pod's /etc is its own mount namespace (writes don't
    reach the host) and /etc/nftables.conf doesn't exist in the
    pod fs. Every heartbeat logged ``firewall.reload_failed``.

    New shape: render the body + write
    /var/lib/spatiumddi-host/release-state/firewall-pending as
    ``<sha256>\\n<body>``. The host-side spatium-firewall-reload.path
    unit watches that path, fires the matching .service, and the
    runner (``/usr/local/bin/spatium-firewall-reload``) does the
    actual nft validate + apply. Same trigger-file shape as
    spatium-snmp-reload / spatium-chrony-reload.

    Short-circuits on unchanged body — the host runner writes the
    applied-hash sidecar after a successful apply; we read that
    on every tick and skip the write when the rendered body's hash
    matches the last-applied hash. Operator's manual nft edits
    out-of-band → hash mismatches on next render → trigger fires →
    canonical state restored.
    """
    if appliance_state.detect_deployment_kind() != "appliance":
        return

    # #285 Phase 5 — warn-only etcd/peer-drift cross-check. Throttled +
    # best-effort + run BEFORE the unchanged-body short-circuit, so a
    # membership change the peer set hasn't caught up to is surfaced even when
    # the local render is stable. Seed-only in practice — a non-seed node's
    # kubeapi read fails and the helper returns None (no-op).
    #
    # Deliberately keyed off the CONTROL PLANE's peer set, before any #593
    # recovery below replaces it. Recovery derives its peers FROM live
    # membership, so drift-checking the recovered set against that same
    # membership can only ever report "no drift" — blinding the diagnostic
    # exactly when the row/reality divergence it exists to surface is happening.
    global _last_peer_drift_at
    if (
        cluster_peer_cidrs
        and time.monotonic() - _last_peer_drift_at >= _PEER_DRIFT_INTERVAL_S
    ):
        _last_peer_drift_at = time.monotonic()
        try:
            firewall_peer_audit.warn_on_peer_drift(
                [str(c) for c in cluster_peer_cidrs],
                appliance_state.read_node_ips() or [],
            )
        except Exception as exc:  # noqa: BLE001 — warn-only, never break apply
            log.debug("supervisor.firewall.peer_drift_check_failed", error=str(exc))

    profile: FirewallProfile = render_drop_in(
        role_assignment,
        cluster_peer_cidrs,
        pod_cidrs=pod_cidrs,
        service_cidrs=service_cidrs,
        cp_member_count=cp_member_count,
        vip_configured=vip_configured,
        web_ui_allowed_cidrs=web_ui_allowed_cidrs,
        ssh_scope_cidrs=ssh_scope_cidrs,
    )
    body = profile.body

    # ── #593 — never render a body that firewalls this node out of raft ──
    #
    # Membership is probed ONLY when the body lacks a peer rule. A healthy
    # control-plane node's body always has one, so it never touches the kube
    # API here; a node whose body has none pays exactly one 2s-bounded GET per
    # heartbeat, which is the price of never trusting a stale "not a member".
    if not firewall_peer_audit.body_opens_etcd_peers(body):
        is_etcd_member = firewall_peer_audit.local_node_is_etcd_member()

        # The live peer set, read once and shared by both defences below.
        # None = membership unreadable; [] = readable and this node is the
        # cluster's ONLY member — a fresh single-node seed, whose correct
        # body legitimately has no peer rule (refusing that pinned every
        # fresh seed on the k3s-bootstrap firewall forever; found live on
        # ddi-pg dev rigs 2026-07-10).
        live_peers = None
        if is_etcd_member is True:
            live_peers = firewall_peer_audit.observed_peer_cidrs(
                appliance_state.read_node_ips() or []
            )

        # Defence 1 — the row gave us no peers, but k3s says we ARE a member.
        # Re-derive the peer set from live membership and re-render.
        if is_etcd_member is True and not cluster_peer_cidrs and live_peers:
            log.warning(
                "supervisor.firewall.peer_cidrs_recovered",
                reason="control plane sent no peers but this node is a live etcd member",
                peers=live_peers,
            )
            profile = render_drop_in(
                role_assignment,
                live_peers,
                pod_cidrs=pod_cidrs,
                service_cidrs=service_cidrs,
                cp_member_count=cp_member_count,
                vip_configured=vip_configured,
                web_ui_allowed_cidrs=web_ui_allowed_cidrs,
                ssh_scope_cidrs=ssh_scope_cidrs,
            )
            body = profile.body

        # Defence 2 — refuse rather than partition, but only when the danger
        # can exist: membership unreadable (can't prove safety), or live
        # peers present while the body still has no rule. A stale peer rule
        # only over-permits to real cluster members, while a wrongly-applied
        # body drops a voting member out of raft. Non-negotiable #5. A
        # readable sole member ([]) falls through and applies.
        if firewall_peer_audit.would_self_partition(
            body, is_etcd_member=is_etcd_member, live_peers=live_peers
        ):
            reason = (
                "rendered drop-in has no etcd peer rule but this node is a live "
                "etcd member; keeping the last-good ruleset"
            )
            log.error(
                "supervisor.firewall.refused_self_partition",
                profile=profile.name,
                reason=reason,
            )
            appliance_state.record_firewall_refusal("in-pod", reason)
            return

    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

    # Read the applied-hash sidecar the host runner writes. Matching
    # = already applied; we leave the trigger file alone so the
    # .path unit doesn't fire pointlessly. Missing or mismatching =
    # re-write the trigger.
    try:
        applied_hash = _NFT_APPLIED_HASH_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        applied_hash = ""

    if applied_hash == body_hash:
        appliance_state.clear_firewall_refusal()
        return

    try:
        _NFT_TRIGGER_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _NFT_TRIGGER_PATH.with_suffix(".new")
        tmp.write_text(f"{body_hash}\n{body}", encoding="utf-8")
        # Atomic rename — the .path unit watches PathChanged which
        # fires on close-after-write of the final path, so the
        # rename ensures the runner sees a complete trigger file
        # rather than a half-written one.
        tmp.replace(_NFT_TRIGGER_PATH)
        # #593 — a body we were willing to write is, by construction, one that
        # doesn't partition us. Drop any refusal marker so a healed node stops
        # reporting a divergence it no longer has.
        appliance_state.clear_firewall_refusal()
        log.info(
            "supervisor.firewall.trigger_written",
            profile=profile.name,
            body_hash=body_hash[:12],
            roles=role_assignment.get("roles") if role_assignment else [],
        )
    except OSError as exc:
        log.warning("supervisor.firewall.trigger_write_failed", error=str(exc))


def _server_firewall_body_is_usable(
    fw_settings: object, log: structlog.stdlib.BoundLogger
) -> bool:
    """#285 Phase 2a bundle-first dispatch, with the #593 guard (#5).

    False means "don't pipe the server's body" — either because the control
    plane has no firewall authority (old control plane, or ``firewall_enabled``
    off), or because that body would firewall this node out of its own cluster.

    The distinction that matters: a refusal must fall through to the IN-POD
    renderer, not merely skip the write. The server renders from the appliance
    ROW, so a stale row ships the same peer-less body on every tick, forever;
    and since #285 Phase 1b removed the LAN-wide accept from the base config,
    a node that joined while its row was already wrong has no last-good ruleset
    to fall back on. The in-pod path can re-derive the peer set from live
    membership and produce a body that keeps this node in raft.

    The structural test runs first, so a body that already opens 2380 — every
    healthy control-plane node — costs no apiserver read.
    """
    if not isinstance(fw_settings, dict) or not fw_settings.get("config_hash"):
        return False

    conf = str(fw_settings.get("firewall_conf") or "")
    if firewall_peer_audit.body_opens_etcd_peers(conf):
        return True
    if firewall_peer_audit.local_node_is_etcd_member() is not True:
        return True

    reason = (
        "server-rendered drop-in has no etcd peer rule but this node is a live "
        "etcd member; re-deriving peers locally"
    )
    log.error(
        "supervisor.firewall.refused_self_partition",
        source="control-plane",
        reason=reason,
    )
    appliance_state.record_firewall_refusal("control-plane", reason)
    return False


def heartbeat_once(
    cfg: SupervisorConfig,
    appliance_id: uuid.UUID,
    session_token: str | None,
    identity: Identity,
    client: httpx.Client,
    log: structlog.stdlib.BoundLogger,
) -> bool:
    """One heartbeat round-trip + trigger-file follow-up.

    Never raises. Logs every error path so a real outage shows up in
    journalctl without taking down the supervisor process.
    """
    state = appliance_state.collect()
    # #358 Phase 1b — ask the control plane to long-poll-hold this
    # heartbeat (Redis-woken) up to the interval so operator commands start
    # in ~0 s. Old control planes ignore it + return at once; the widened
    # client timeout below covers the hold.
    hold_s = max(0, int(cfg.heartbeat_interval_seconds))
    body: dict[str, Any] = {
        "appliance_id": str(appliance_id),
        "wait_seconds": hold_s,
        "session_token": session_token,
        "capabilities": _capabilities_payload(),
        **state,
        # #170 Phase E2 — probe UDP+TCP/53 + UDP/67 every tick. Empty
        # dict explicitly clears any prior conflict server-side;
        # ``None`` would skip the overwrite, which isn't what we want
        # if the conflict went away. The probe is cheap (``ss``) so
        # running it every heartbeat is fine.
        "port_conflicts": probe_port_conflicts(),
        # #593 — a self-partition refusal, or {} when healthy. Without this the
        # guard is silent: the control plane keeps re-shipping the same wrong
        # body from the same stale row and nothing surfaces the divergence.
        # ``{}`` (not None) so a healed node explicitly CLEARS the row, exactly
        # as port_conflicts does; None is reserved for "an old supervisor didn't
        # report", which must leave the stored value untouched.
        "firewall_state": appliance_state.read_firewall_state() or {},
        # #272 Phase 9 — report the k8s Nodes this seed evicted on prior
        # ticks so the backend clears their ``evict_requested`` flag +
        # settles them to ``left``. Empty on non-seed / nothing-evicted.
        "evicted_node_names": sorted(_evicted_pending),
    }
    # #170 Wave D follow-up — surface the outcome of the previous
    # heartbeat's compose-lifecycle apply. Empty / None on the first
    # heartbeat or before any role assignment has been issued.
    last_lifecycle_state, last_lifecycle_reason = _read_lifecycle_state(cfg.state_dir)
    if last_lifecycle_state is not None:
        body["role_switch_state"] = last_lifecycle_state
        if last_lifecycle_reason is not None:
            body["role_switch_reason"] = last_lifecycle_reason

    # #170 Wave E — service-container watchdog. Every
    # ``_WATCHDOG_INTERVAL_S`` we snapshot the running containers and
    # diff against the supervisor's persisted role assignment; the
    # result rides on every heartbeat (cached between watchdog runs so
    # the Fleet UI doesn't see the field flicker between probes). On
    # the appliance only — docker/k8s deployments don't run this
    # lifecycle path, so the watchdog has nothing to watch.
    global _last_watchdog_at, _cached_role_health
    if appliance_state.detect_deployment_kind() == "appliance":
        if _watchdog_check_due():
            try:
                env_file = cfg.state_dir / _ROLE_ENV_FILENAME
                _cached_role_health = watchdog.check_health(env_file)
                _last_watchdog_at = time.monotonic()
            except Exception as exc:  # noqa: BLE001
                # Never let a watchdog crash kill the heartbeat path.
                log.warning("supervisor.watchdog.crashed", error=str(exc))
        if _cached_role_health:
            body["role_health"] = _cached_role_health

        # #59 — host NICs (ens18, cni0, …) for the appliance-vantage
        # packet-capture interface picker. Only shipped when non-empty so
        # a transient empty /run/udev read never wipes the learned set.
        try:
            ifaces = appliance_state.host_network_interfaces()
            if ifaces:
                body["host_interfaces"] = ifaces
        except Exception as exc:  # noqa: BLE001 — never break the heartbeat
            log.warning("supervisor.host_interfaces.failed", error=str(exc))

        # #272 Phase 9b — report the seed's etcd snapshot inventory (read
        # from the k3s ETCDSnapshotFile CRs over the kubeapi, no host k3s
        # binary needed) so Fleet can show recoverable snapshots without an
        # operator SSH. Seed-only: the kubeapi read on a non-control-plane
        # node 403s / returns [] (the helper swallows it). Plus the
        # guided-restore .state sidecar, so the backend can settle the
        # desired snapshot once the runner reports ``done``.
        if appliance_state.detect_appliance_variant() == "control-plane":
            from . import k8s_api  # noqa: PLC0415

            body["etcd_snapshots"] = k8s_api.list_etcd_snapshots()
        restore_state, restore_reason = appliance_state.read_cluster_restore_state()
        if restore_state is not None:
            body["restore_state"] = restore_state
            body["restore_reason"] = restore_reason
    url_path = "/api/v1/appliance/supervisor/heartbeat"
    # #272 — cluster members POST to the in-cluster api Service; remote
    # agents to their configured CONTROL_PLANE_URL. See
    # ``_effective_control_plane_url``.
    url = _effective_control_plane_url(cfg).rstrip("/") + url_path

    # #170 Wave D follow-up — cert auth supersedes session-token
    # auth once the cert is on disk. Build the headers + sign with
    # the supervisor's Ed25519 private key; the backend's
    # cert_auth.py middleware validates the chain + signature + the
    # timestamp skew. When no cert yet (pre-approval), fall through
    # to the session_token body field — same shape as today.
    cached_cert = load_cert(cfg.state_dir)
    headers: dict[str, str] = {}
    if cached_cert is not None:
        try:
            headers = build_auth_headers(
                "POST", url_path, cached_cert, identity.private_key, appliance_id
            )
            # #411 — KEEP the session token in the body as a fallback even
            # when we present a cert. The server prefers the cert; if cert-
            # auth doesn't validate (the cert pipeline isn't proven in the
            # field yet), it falls back to the session token rather than
            # 403ing. Previously we popped the token here in anticipation of
            # cert-only enforcement — but combined with #400 C1 removing the
            # approved-state bypass, that left the heartbeat with no usable
            # credential whenever cert-auth wasn't accepted, silently
            # killing reboot / fleet-upgrade / role delivery. Re-add the pop
            # once cert-auth is enforced end-to-end (the #411 follow-up).
        except Exception as exc:  # noqa: BLE001
            log.warning("supervisor.heartbeat.cert_auth_skipped", error=str(exc))

    try:
        resp = client.post(
            url, json=body, headers=headers, timeout=float(hold_s) + 10.0
        )
    except httpx.HTTPError as exc:
        # Transient network / DNS / timeout — don't count toward
        # revocation strikes. The control plane is unreachable, not
        # rejecting us; once it comes back the 200 path resumes.
        log.warning("supervisor.heartbeat.failed", error=str(exc))
        return False
    if resp.status_code == 403 or resp.status_code == 404:
        # 403 = approval revoked or cert no longer valid for any
        # known appliance row. 404 = appliance row deleted, or the
        # control plane's supervisor_registration_enabled flag is
        # off. Both mean "you shouldn't be talking to me anymore" —
        # increment the consecutive-strike counter; flip to
        # ``revoked`` once REVOCATION_STRIKE_LIMIT in a row, which
        # de-noises a short control-plane restart.
        prior_state = approval_state.read_state(cfg.state_dir)
        new_state, strikes = approval_state.record_revocation_signal(cfg.state_dir)
        log.warning(
            "supervisor.heartbeat.rejected",
            status_code=resp.status_code,
            strikes=strikes,
            new_state=new_state,
            appliance_id=str(appliance_id),
        )
        # Tear down any supervised service containers whenever we're
        # in the revoked state and any are still running. The first
        # invocation is the threshold crossing; subsequent invocations
        # catch host-reboot recovery.
        #
        # Phase 7 retired the docker compose teardown: ``tear_down_
        # supervised_services`` now ``DELETE``s the HelmChart CR via
        # the local kubeapi. helm-controller catches the delete +
        # runs ``helm uninstall`` against the spatium namespace.
        # Idempotent — calling on every revoked heartbeat is a no-op
        # once the CR is gone.
        if new_state == "revoked":
            if appliance_state.detect_deployment_kind() == "appliance":
                try:
                    lifecycle = tear_down_supervised_services()
                    if lifecycle.stopped:
                        log.warning(
                            "supervisor.heartbeat.revoked_teardown",
                            state=lifecycle.state,
                            stopped=list(lifecycle.stopped),
                            reason=lifecycle.reason,
                            transition=(prior_state != "revoked"),
                        )
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "supervisor.heartbeat.revoked_teardown_failed",
                        error=str(exc),
                    )
        return False
    if resp.status_code >= 500:
        # 5xx is the control plane crashing mid-flight, not a
        # deliberate rejection — don't count toward revocation.
        log.warning(
            "supervisor.heartbeat.server_error",
            status_code=resp.status_code,
        )
        return False
    if resp.status_code != 200:
        log.warning(
            "supervisor.heartbeat.unexpected_status",
            status_code=resp.status_code,
        )
        return False
    # Heartbeat accepted — clear any prior strike counter and stamp
    # ``approved`` if we weren't there yet.
    approval_state.record_success(cfg.state_dir)

    try:
        body_out = resp.json()
    except ValueError:
        log.warning("supervisor.heartbeat.bad_json")
        return False
    # #358 Phase 1b — True when the control plane long-poll-held this
    # heartbeat (new server); lets the loop re-arm the hold immediately.
    held = bool(body_out.get("long_poll"))

    # #170 Wave D follow-up — pick up cert + CA chain on the first
    # heartbeat after approval. Subsequent heartbeats include the
    # same bytes; ``save_cert`` is content-addressed so re-saving
    # the same body is a disk no-op.
    cert_pem = body_out.get("cert_pem")
    ca_chain_pem = body_out.get("ca_chain_pem")
    if cert_pem and ca_chain_pem:
        try:
            save_cert(cfg.state_dir, cert_pem, ca_chain_pem)
            if cached_cert is None:
                log.info(
                    "supervisor.heartbeat.cert_received",
                    cert_expires_at=body_out.get("cert_expires_at"),
                )
        except OSError as exc:
            log.warning("supervisor.heartbeat.cert_save_failed", error=str(exc))

    desired_version = body_out.get("desired_appliance_version")
    desired_url = body_out.get("desired_slot_image_url")
    desired_sha256 = body_out.get("desired_slot_image_sha256")
    desired_tls_insecure = bool(body_out.get("desired_slot_image_tls_insecure"))
    desired_next_boot_slot = body_out.get("desired_next_boot_slot")
    desired_default_slot = body_out.get("desired_default_slot")
    reboot_requested = bool(body_out.get("reboot_requested"))
    clear_upgrade_requested = bool(body_out.get("clear_upgrade_requested"))

    # #786 — an explicit "Clear failed upgrade" outranks everything below.
    # Handled BEFORE the desired-upgrade branch so a clear issued while a
    # failed desired-state is still on the row resets the host in the same
    # heartbeat, and before the passive heal because only this path is
    # allowed to remove a stranded trigger file.
    if clear_upgrade_requested:
        if appliance_state.apply_clear_upgrade_command():
            log.info("supervisor.heartbeat.clear_upgrade_applied")

    if desired_version and desired_url:
        if appliance_state.maybe_fire_fleet_upgrade(
            desired_version,
            desired_url,
            desired_sha256,  # type: ignore[arg-type]
            desired_tls_insecure,
        ):
            log.info(
                "supervisor.heartbeat.upgrade_trigger_fired",
                desired_version=desired_version,
            )
    else:
        # #386 Part B — no upgrade desired (cleared via Cancel, or never
        # set). Drop the fire-once marker so a future Apply re-fires, and
        # heal a stale ``failed`` state so a cancelled attempt stops
        # sticking on the Fleet chip.
        appliance_state.clear_fleet_upgrade_marker()
    # Per-slot boot intents. Both compare against the freshly-collected
    # local state (snapshotted at the top of this function) so a
    # supervisor that just rebooted into the requested slot doesn't
    # re-fire — the backend will auto-clear the desired field on the
    # next heartbeat once it sees current_slot / durable_default match.
    if desired_next_boot_slot:
        if appliance_state.maybe_fire_set_next_boot(
            desired_next_boot_slot,
            state.get("current_slot"),  # type: ignore[arg-type]
        ):
            log.info(
                "supervisor.heartbeat.set_next_boot_trigger_fired",
                desired_slot=desired_next_boot_slot,
            )
    if desired_default_slot:
        if appliance_state.maybe_fire_set_default(
            desired_default_slot,
            state.get("durable_default"),  # type: ignore[arg-type]
        ):
            log.info(
                "supervisor.heartbeat.set_default_trigger_fired",
                desired_slot=desired_default_slot,
            )
    if reboot_requested:
        if appliance_state.maybe_fire_reboot(True):
            log.info("supervisor.heartbeat.reboot_trigger_fired")

    # Issue #165 — operator-set timezone. Empty / missing → no
    # override (host stays on install-time default). Non-empty +
    # different from the host runner's last-applied → trigger
    # ``spatiumddi-tz-reload`` via the trigger-file convention the
    # SNMP / chrony / firewall / slot-upgrade runners all use.
    desired_timezone = body_out.get("desired_timezone")
    if desired_timezone and isinstance(desired_timezone, str):
        if appliance_state.maybe_fire_timezone(desired_timezone):
            log.info(
                "supervisor.heartbeat.timezone_trigger_fired",
                desired_timezone=desired_timezone,
            )

    # #393 — appliance console mode. Always evaluated (a definite value, not an
    # opt-in override like timezone); maybe_fire_console_mode short-circuits
    # against its applied sidecar so it only writes the grubenv trigger on a
    # real change. Applies next reboot.
    desired_console_mode = body_out.get("desired_console_mode")
    if appliance_state.maybe_fire_console_mode(
        desired_console_mode if isinstance(desired_console_mode, str) else None
    ):
        log.info(
            "supervisor.heartbeat.console_mode_trigger_fired",
            desired_console_mode=desired_console_mode,
        )

    # Issue #346 — appliance host-config (snmp / chrony / lldp). The control
    # plane ships each rendered block + its config_hash; the maybe_fire_*
    # writers compare against their applied-hash sidecar and fire the matching
    # host-side reload trigger only when it differs (appliance-only, idempotent
    # — safe to call every heartbeat). This is the runtime-activation path for
    # #153 / #154 / #343.
    if appliance_state.maybe_fire_snmp_reload(body_out.get("snmp_settings")):
        log.info("supervisor.heartbeat.snmp_trigger_fired")
    if appliance_state.maybe_fire_ntp_reload(body_out.get("ntp_settings")):
        log.info("supervisor.heartbeat.ntp_trigger_fired")
    if appliance_state.maybe_fire_lldp_reload(body_out.get("lldp_settings")):
        log.info("supervisor.heartbeat.lldp_trigger_fired")
    # Issue #156 — rsyslog forwarding config-reload trigger.
    if appliance_state.maybe_fire_syslog_reload(body_out.get("syslog_settings")):
        log.info("supervisor.heartbeat.syslog_trigger_fired")
    # Issue #157 — SSH authorized_keys + sshd config-reload trigger.
    if appliance_state.maybe_fire_ssh_reload(body_out.get("ssh_settings")):
        log.info("supervisor.heartbeat.ssh_trigger_fired")
    # Issue #158 — systemd-resolved config-reload trigger.
    if appliance_state.maybe_fire_resolver_reload(body_out.get("resolver_settings")):
        log.info("supervisor.heartbeat.resolver_trigger_fired")
    # Issue #155 — APT sources / proxy / GPG-key config-reload trigger.
    if appliance_state.maybe_fire_apt_reload(body_out.get("apt_settings")):
        log.info("supervisor.heartbeat.apt_trigger_fired")
    # #989 item 3 — removable (USB) disk mount plane. Unlike its
    # siblings this block is PER-APPLIANCE, so it is rendered from the
    # appliance row rather than from platform settings.
    if appliance_state.maybe_fire_removable_reload(body_out.get("removable_settings")):
        log.info("supervisor.heartbeat.removable_trigger_fired")

    # #272 Phase 7b — control-plane promote/demote. The host-side runner
    # (spatium-cluster-join) reconfigures k3s + reports back via the
    # .state sidecar that collect() ships on the next heartbeat; the
    # backend then settles cluster_role + clears the desired-state.
    desired_cluster_role = body_out.get("desired_cluster_role")
    if desired_cluster_role == "member":
        if appliance_state.maybe_fire_cluster_join(
            desired_cluster_role,
            body_out.get("desired_k3s_server_url"),  # type: ignore[arg-type]
            body_out.get("desired_k3s_join_token"),  # type: ignore[arg-type]
        ):
            log.info(
                "supervisor.heartbeat.cluster_join_trigger_fired",
                server_url=body_out.get("desired_k3s_server_url"),
            )
    elif desired_cluster_role == "none":
        if appliance_state.maybe_fire_cluster_leave(desired_cluster_role):
            log.info("supervisor.heartbeat.cluster_leave_trigger_fired")
    else:
        # #590 — no desired cluster role: the control plane settled this
        # episode (or gave up on it after a reported ``failed``). Two
        # cleanups, both of which make the NEXT promote work:
        #   1. Drop the attempt ledger, or a re-promote against the same
        #      seed would inherit an exhausted budget and never fire.
        #   2. Retire the terminal .state verdict, or re-reporting it would
        #      clear the next promote's desired-state before its join fired.
        appliance_state.reset_cluster_join_attempts()
        appliance_state.mark_cluster_join_state_consumed()

    # #272 Phase 9b — guided etcd restore. The backend stamps
    # ``desired_restore_snapshot`` only on the seed row (after a superadmin
    # + typed-hostname confirm), so this fires only on the seed. The
    # host-side spatium-cluster-restore runner does the destructive
    # cluster-reset; collect() ships the .state sidecar back so the backend
    # clears the desired-state once it lands ``done``.
    restore_snapshot = body_out.get("desired_restore_snapshot")
    if appliance_state.maybe_fire_cluster_restore(restore_snapshot):  # type: ignore[arg-type]
        log.warning(
            "supervisor.heartbeat.cluster_restore_trigger_fired",
            snapshot=restore_snapshot,
        )

    # #277 — scale the CNPG postgres cluster + control-plane workload
    # replicas to the committed member count. Only the SEED acts (the
    # spatium-control HelmChart lives there; on members the GET 404s and
    # this is a no-op). The seed is the lone control-plane-variant node;
    # promoted members are `appliance` variant. Idempotent — patches
    # only when the rendered cp-size differs, so it converges one tick
    # after a promote/demote settles and stays quiet otherwise.
    cp_size = body_out.get("control_plane_size")
    if (
        isinstance(cp_size, int)
        and cp_size >= 1
        and appliance_state.detect_appliance_variant() == "control-plane"
    ):
        from . import k8s_api  # noqa: PLC0415

        # #272 — write the supervisor-owned overrides to HelmChartConfigs
        # (reboot-safe). Patching the HelmChart CR directly is clobbered
        # when k3s re-applies the on-disk firstboot manifest on restart;
        # a HelmChartConfig is a separate CR helm-controller merges on top
        # + the deploy controller never reverts. cp-size + the VIP go on
        # spatium-control; the MetalLB pool on spatium-bootstrap.
        # Idempotent — only writes when the rendered values differ.
        ml_enabled = bool(body_out.get("desired_metallb_enabled"))
        ml_pool = body_out.get("desired_metallb_pool_addresses") or []
        ml_vip = body_out.get("desired_control_plane_vip") or ""
        # #285 Phase 6 — source-scope the VIP path too (loadBalancerSourceRanges).
        web_ui_cidrs = body_out.get("web_ui_allowed_cidrs") or []
        # #566 decision D1 — BGP mode (export path: advertise the VIP to
        # upstream routers). Folded into the SAME apply_metallb_overrides
        # call below (one combined HelmChartConfig body).
        ml_bgp_enabled = bool(body_out.get("desired_metallb_bgp_enabled"))
        ml_bgp_peers = body_out.get("desired_metallb_bgp_peers") or []
        ml_bgp_advertisements = body_out.get("desired_metallb_bgp_advertisements") or []

        # The api / worker memory limits and worker concurrency ride along,
        # sized from this node's RAM (k8s_api.control_plane_resources) — the
        # chart's BYO-cluster defaults gave way before the VM did on the
        # appliance, and a kubectl patch never survived a k3s restart.
        cp_changed, cp_err = k8s_api.apply_control_plane_overrides(
            cp_size,
            str(ml_vip),
            web_ui_allowed_cidrs=list(web_ui_cidrs),
            mem_total_mib=k8s_api.node_memory_mib(),
        )
        if cp_changed:
            log.info(
                "supervisor.heartbeat.control_plane_overrides_applied",
                size=cp_size,
                vip=ml_vip,
            )
        elif cp_err:
            log.warning(
                "supervisor.heartbeat.control_plane_overrides_failed",
                error=cp_err,
                size=cp_size,
            )

        # #272 — the CNPG Cluster carries ``helm.sh/resource-policy: keep``
        # (so a failed-release recovery can't wipe the DB), which also
        # makes the helm-controller skip patching its spec on upgrade. The
        # HelmChartConfig above scales api/worker/frontend/redis but the
        # kept Cluster stays at its initial instance count, so scale it
        # directly here (a merge-patch isn't a Helm op → keep doesn't
        # apply). Idempotent — only patches on a real size change.
        #
        # #1059 — never DOWN while a dead node is being replaced. The replace
        # endpoint drops the replaced row from the committed count at once,
        # so this tick — the one that also deletes the Node below — used to
        # ask for one instance fewer, and every tick after it too, until the
        # replacement was promoted (~10 min). CNPG took the smaller spec while
        # the dead node's pod still read Ready and deleted whichever ready
        # non-primary instance had the highest serial (the dead one by luck,
        # or a healthy replica); on a later tick it refused instead, and the
        # smaller spec then only stopped it re-creating the dead instance —
        # Postgres two of three until the promote restored the count. The
        # eviction tick arms _replace_hold, which keeps the size until the
        # committed count is back (or the operator shrinks on purpose), and
        # patch_cnpg_instances itself defers any scale-down the Cluster
        # reports it cannot take. Scale-up is untouched; a real demote lands
        # on the first tick the cluster is whole.
        hold = _replace_hold.reason(body_out.get("evict_node_names") or [], cp_size)
        pg_scale = k8s_api.patch_cnpg_instances(cp_size, scale_down=not hold, hold_reason=hold)
        _replace_hold.settle(cp_size, pg_scale.current)
        if pg_scale.scaled:
            log.info("supervisor.heartbeat.cnpg_instances_scaled", size=cp_size)
        elif pg_scale.deferred:
            log.info(
                "supervisor.heartbeat.cnpg_instances_scale_down_deferred",
                size=cp_size,
                current=pg_scale.current,
                ready=pg_scale.ready,
                instances=pg_scale.reported,
                reason=pg_scale.deferred,
            )
        elif pg_scale.error:
            log.warning(
                "supervisor.heartbeat.cnpg_instances_scale_failed",
                error=pg_scale.error,
                size=cp_size,
            )

        bs_changed, bs_err = k8s_api.apply_metallb_overrides(
            metallb_enabled=ml_enabled,
            pool_addresses=list(ml_pool),
            bgp_enabled=ml_bgp_enabled,
            bgp_peers=list(ml_bgp_peers),
            bgp_advertisements=list(ml_bgp_advertisements),
        )
        if bs_changed:
            log.info(
                "supervisor.heartbeat.metallb_overrides_applied",
                enabled=ml_enabled,
                pool=list(ml_pool),
                bgp_enabled=ml_bgp_enabled,
            )
        elif bs_err:
            log.warning("supervisor.heartbeat.metallb_overrides_failed", error=bs_err)

        # #272 Phase 10 — data-plane resolver VIPs. Patches
        # dns.useMetalLBVIP / dns.vip / dhcpKea.relayVIP onto the
        # spatiumddi-appliance HelmChartConfig (a no-op merge until the
        # chart exists, i.e. until a DNS/DHCP role is assigned somewhere).
        dns_vip = body_out.get("desired_dns_vip") or ""
        relay_vip = body_out.get("desired_dhcp_relay_vip") or ""
        dp_changed, dp_err = k8s_api.apply_dataplane_vip_overrides(
            dns_vip=str(dns_vip), dhcp_relay_vip=str(relay_vip)
        )
        if dp_changed:
            log.info(
                "supervisor.heartbeat.dataplane_vip_overrides_applied",
                dns_vip=dns_vip,
                dhcp_relay_vip=relay_vip,
            )
        elif dp_err:
            log.warning(
                "supervisor.heartbeat.dataplane_vip_overrides_failed", error=dp_err
            )

        # #272 Phase 9 — dead-node replacement. The seed deletes each k8s
        # Node the backend flagged for eviction (deleting the Node makes
        # k3s drop the etcd member); newly-deleted names are stashed in
        # ``_evicted_pending`` and reported on the next heartbeat so the
        # backend clears the flag. Prune the stash to whatever the
        # backend still lists as pending (everything else is confirmed).
        evict_names = body_out.get("evict_node_names") or []
        evicted_now: list[str] = []
        for name in evict_names:
            if name in _evicted_pending:
                continue
            ok, evict_err = k8s_api.delete_node(str(name))
            if ok:
                _evicted_pending.add(str(name))
                evicted_now.append(str(name))
                log.info("supervisor.heartbeat.node_evicted", node=name)
                # #590 — the deleted node strands any local-path Redis PVC
                # provisioned on it (node-affine PV): the replacement
                # replica sits Pending forever and its missing sentinel
                # silently halves the failover quorum, so the NEXT node
                # loss takes the whole API down. Reclaim now — the
                # StatefulSet recreates pod + claim on a live node and the
                # replica resyncs from the master (cache/broker data;
                # Postgres is the store of record).
                pvcs, pvc_err = k8s_api.reclaim_stranded_redis_storage(str(name))
                if pvcs:
                    log.info(
                        "supervisor.heartbeat.redis_storage_reclaimed",
                        node=name,
                        pvcs=pvcs,
                    )
                elif pvc_err:
                    log.warning(
                        "supervisor.heartbeat.redis_storage_reclaim_failed",
                        node=name,
                        error=pvc_err,
                    )
            else:
                log.warning(
                    "supervisor.heartbeat.node_evict_failed", node=name, error=evict_err
                )
        _evicted_pending.intersection_update({str(n) for n in evict_names})

        # #1058 — the deleted Node strands the CloudNativePG instance claim
        # provisioned on it exactly as it strands Redis's, and the operator
        # does NOT reclaim it: the re-created pod sits Pending on the dead
        # node's PV affinity, Postgres runs 2 of 3 for good, and the
        # replacement member never hosts an instance. Reclaim it the way
        # the chart README says a human would — the claim, then the pod,
        # and ONLY a replica's: an instance the Cluster still names as its
        # primary is deferred to the next tick, by which time the operator
        # has failed over. Every seed tick, not only the eviction one, so a
        # deferred primary and a supervisor restart both converge; one CR
        # read per tick while Postgres is whole. The names evicted THIS
        # tick are handed in as authoritative (the Node DELETE is
        # milliseconds old and the name can still be listed), so a
        # replica's claim goes on the eviction tick itself.
        pg = k8s_api.reclaim_stranded_postgres_storage(
            evicted_nodes=set(evicted_now) | _stranded_pending
        )
        # Mutated in place rather than rebound: the module-level set is the
        # state, and a ``global`` rebinding reads as a never-read assignment
        # to a static analyser (it is read on the next tick).
        owed = _carry_stranded(_stranded_pending, evicted_now, pg)
        _stranded_pending.clear()
        _stranded_pending.update(owed)
        pg_reclaimed, pg_deferred, pg_err = pg.reclaimed, pg.deferred, pg.error
        if pg_reclaimed:
            log.info(
                "supervisor.heartbeat.postgres_storage_reclaimed",
                pvcs=pg_reclaimed,
                evicted=evicted_now,
                # which read decided each claim was stranded: the PV's node
                # affinity ("pv") or the scheduler's selected-node
                # annotation ("annotation", only when the PV is gone)
                affinity_source={name: pg.sources.get(name, "") for name in pg_reclaimed},
            )
        if pg_deferred:
            log.info(
                "supervisor.heartbeat.postgres_storage_reclaim_deferred",
                instances=pg_deferred,
                reason=pg.deferred_reason,
            )
        if pg.terminating:
            log.info(
                "supervisor.heartbeat.postgres_storage_reclaim_pending",
                pvcs=pg.terminating,
                reason="deleted on an earlier tick; pvc-protection is waiting for the pod",
            )
        if pg_err:
            log.warning("supervisor.heartbeat.postgres_storage_reclaim_failed", error=pg_err)

        # #590 — cluster DNS must survive a node loss. k3s's bundled
        # CoreDNS is a single replica that deterministically sits on the
        # seed and takes the k8s-default 300 s to evict, so a hard seed
        # kill silences ALL Service/pod-FQDN resolution — the api
        # readiness gate's Postgres and Redis lookups included — for
        # longer than the whole recovery budget. Re-converged every
        # heartbeat because k3s re-applies its bundled manifest (replicas
        # back to 1) on every restart.
        #
        # #750 — the reconciler now targets the HA shape only once a second
        # node exists, and reverts a single-node box to stock; applying it to
        # one node deadlocked the rollout permanently. So a "changed" here can
        # mean either direction, and the reconciler logs which.
        _dns_changed, dns_err = k8s_api.ensure_coredns_ha()
        if dns_err:
            log.warning("supervisor.heartbeat.coredns_ha_failed", error=dns_err)

    # #170 Wave C2 — render the role-driven compose env. C3 will
    # consume this via ``docker compose --env-file`` to actually
    # bring services up/down; for now we just write the file so the
    # operator can inspect what the supervisor would do next.
    role_assignment = body_out.get("role_assignment") or {}

    # #170 Wave C3 — render + apply the nftables drop-in. Phase 9
    # (#183) gates this behind cfg.in_pod_firewall_enabled (default
    # off): the supervisor runs in a k3s pod where the host's
    # /etc/nftables.conf isn't visible, so `nft -f` fails on every
    # heartbeat. The host's static /etc/nftables.conf already opens
    # SSH/53/67/80/443 and the role pods use hostNetwork=true, so
    # the in-pod drop-in is duplicative — kept here only for the
    # operator-CIDR-allowlist (Phase 6 kubeapi_expose_cidrs) case,
    # which needs a host-side trigger-file path before it works
    # in-pod (Phase 9 follow-up).
    # #272 Phase 7b — control-plane peer firewall openings. The base
    # appliance /etc/nftables.conf only accepts :6443 from the pod CIDR,
    # so a multi-node join + etcd quorum is dropped without opening the
    # k3s server ports to the peer node IPs. Unlike the role-driven
    # rules (which the host static config already covers, hence the
    # default-off in_pod_firewall_enabled gate), the peer openings are
    # ESSENTIAL — apply them whenever the control plane hands us a peer
    # set, regardless of that gate.
    cluster_peer_cidrs = body_out.get("cluster_peer_cidrs") or []
    # #285 Phase 1 — derived firewall inputs the control plane now ships:
    # pod/service CIDR widen the 6443 accept (in-cluster apiserver access).
    # cp_member_count + the VIP gate whether MetalLB memberlist (7946) is
    # opened, and cp_member_count >= 2 drives the bootstrap-sentinel retire
    # directive the renderer emits.
    fw_pod_cidrs = body_out.get("firewall_pod_cidrs") or []
    fw_service_cidrs = body_out.get("firewall_service_cidrs") or []
    fw_cp_member_count = int(body_out.get("control_plane_size") or 1)
    fw_vip_configured = bool(body_out.get("desired_control_plane_vip") or "")
    # #285 Phase 6 — operator Web-UI source restriction (empty = open).
    fw_web_ui_cidrs = body_out.get("web_ui_allowed_cidrs") or []
    # #1009 — the EFFECTIVE ssh scope (empty unless the operator turned
    # lockdown on). Non-empty retires the baked port-22 floor and scopes
    # the management line; absent from an older control plane, which
    # keeps the floor — the safe direction.
    fw_ssh_scope_cidrs = body_out.get("ssh_scope_cidrs") or []
    # #285 Phase 2a — bundle-first / renderer-fallback dispatch. When the
    # control plane has firewall authority (firewall_enabled on → a non-empty
    # ``firewall_settings.config_hash``), pipe its server-rendered body to the
    # host runner. Otherwise (master switch off, or an OLD control plane that
    # doesn't ship the block) fall back to the in-pod renderer. Both render
    # the BYTE-IDENTICAL body, so applied state is the same whichever ran —
    # this is what makes the rolling upgrade (supervisor/control-plane skew in
    # either direction) safe.
    fw_settings = body_out.get("firewall_settings")
    use_bundle = _server_firewall_body_is_usable(fw_settings, log)

    if use_bundle:
        if appliance_state.maybe_fire_firewall_reload(fw_settings):
            log.info(
                "supervisor.heartbeat.firewall_trigger_fired", source="control-plane"
            )
    else:
        # #5 fallback — control plane too old to render, or firewall_enabled
        # still off; render in-pod from the same derived inputs.
        #
        # #285 Phase 6 — this branch now fires UNCONDITIONALLY (it used to gate
        # on ``cfg.in_pod_firewall_enabled or cluster_peer_cidrs or fw_pod_cidrs``).
        # The base /etc/nftables.conf no longer opens the Web UI (80/443); the
        # rendered drop-in is now the SOLE source of that accept, so it must be
        # present on EVERY appliance node — including idle / non-CP nodes that
        # carry no roles, no peers and no pods. ``_maybe_apply_firewall`` already
        # self-gates on ``detect_deployment_kind() == "appliance"`` and the host
        # runner short-circuits on an unchanged body hash, so an unconditional
        # call is cheap + idempotent. SSH/22 is opened by the baked sentinel
        # 00-spatium-ssh.nft (#1009 — it used to be in the base conf), which is
        # a separate file the glob pulls in, so even a total drop-in failure
        # still leaves the node SSH-recoverable.
        _maybe_apply_firewall(
            role_assignment,
            log,
            cluster_peer_cidrs,
            pod_cidrs=fw_pod_cidrs,
            service_cidrs=fw_service_cidrs,
            cp_member_count=fw_cp_member_count,
            vip_configured=fw_vip_configured,
            web_ui_allowed_cidrs=fw_web_ui_cidrs,
            ssh_scope_cidrs=fw_ssh_scope_cidrs,
        )

    target = compute_target_env(role_assignment)
    # #170 Wave D follow-up — the role env file carries ONLY role-
    # scoped vars (``COMPOSE_PROFILES``, ``AGENT_GROUP``,
    # ``DNS_ENGINE``). The compose-service interpolation for static
    # appliance config (``${SPATIUMDDI_VERSION}``,
    # ``${CONTROL_PLANE_URL}``, ``${APPLIANCE_HOSTNAME}``,
    # ``${DNS_AGENT_KEY}``, ``${DOCKER_GID}``, ...) is satisfied by
    # the host's main ``/etc/spatiumddi/.env`` — see
    # ``service_lifecycle._HOST_ENV_FILE``, which is passed to
    # ``docker compose`` as an additional ``--env-file`` ahead of
    # this one. That keeps the role env file scoped to what the
    # supervisor actually decides and avoids stale duplication when
    # the host .env is upgraded out-of-band.
    env_path = cfg.state_dir / _ROLE_ENV_FILENAME
    env_write_failed = False
    try:
        env_path.parent.mkdir(parents=True, exist_ok=True)
        rendered = render_env_file(target)
        # Atomic write — partial files would confuse the compose
        # subprocess below if the supervisor crashed mid-write.
        # #555 — owner-only (0600) at creation: role-compose.env carries
        # DNS_AGENT_KEY / DHCP_AGENT_KEY bootstrap PSKs, and a plain
        # write_text lands it at the umask default (0644, world-readable in
        # the 1777 release-state dir) before any chmod. Reuse the shared
        # O_NOFOLLOW+0600 writer.
        tmp = env_path.with_suffix(".tmp")
        appliance_state._write_owner_only(tmp, rendered)
        tmp.replace(env_path)
        log.info(
            "supervisor.heartbeat.role_env_rendered",
            profiles=target.profiles,
            env_path=str(env_path),
        )
    except OSError as exc:
        env_write_failed = True
        log.warning(
            "supervisor.heartbeat.role_env_write_failed",
            error=str(exc),
            env_path=str(env_path),
        )

    # #170 Wave D follow-up — actually run ``docker compose`` against
    # the freshly-written env file so the assigned service container
    # comes up (or comes down on de-assignment). Best-effort — on
    # failure we log + carry the failure state up to the control
    # plane in the next heartbeat's ``role_switch_state``.
    #
    # Skip the apply when nothing it would send has changed since the
    # last successful apply. The previous "fire every heartbeat" shape
    # ran ``docker compose ps`` + ``up -d`` every 60 s even during
    # steady state when nothing had changed. Each subprocess pair costs
    # ~600 ms on a 1-CPU VM (Go binary startup + arg parsing + JSON
    # formatting); 60-second cadence × 24h = ~14 minutes of wasted CPU
    # per day on a fleet that wasn't transitioning anything.
    #
    # #1203 — "nothing it would send" is the rendered role env AND the
    # image tag + chart the apply renders (``_role_apply_key``). The
    # stamp lives in the persistent state dir and is NOT reset on a
    # restart, and the role env carries no version, so a key on the env
    # alone made the first heartbeat on a new slot skip: the agents kept
    # the previous release's chart and images until a role next changed.
    # #170 Wave E follow-up — if the appliance row was deleted on the
    # control plane and we tripped the revocation threshold above
    # (well, on a prior heartbeat — the 200 path above wouldn't have
    # been reached if we were rejected now), stop touching the local
    # compose state. The cached role-compose.env is stale by
    # definition and re-applying it just keeps the supervisor sliding
    # toward a state the control plane no longer expects. The console
    # dashboard surfaces the red ``Approval revoked`` chip so the
    # operator knows the recovery is "re-pair from /appliance/pairing".
    if approval_state.read_state(cfg.state_dir) == "revoked":
        log.info("supervisor.heartbeat.lifecycle_skipped_revoked")
        _ = identity
        return False

    if not env_write_failed and appliance_state.detect_deployment_kind() == "appliance":
        # Phase 10 wave 2 — reconcile node labels every heartbeat
        # regardless of the env-hash skip below. patch_node_labels is
        # idempotent (same-value = no-op), so the cost is one PATCH
        # per minute; the win is catching drift from out-of-band
        # ``kubectl label node`` runs or manual unlabeling without
        # waiting for the operator to flip a role.
        try:
            label_ok, label_err = reconcile_node_labels(target.profiles)
            if not label_ok:
                log.warning(
                    "supervisor.heartbeat.labels_reconcile_failed",
                    error=label_err,
                )
        except Exception as exc:  # noqa: BLE001
            log.warning("supervisor.heartbeat.labels_reconcile_crashed", error=str(exc))

        apply_due, env_hash = _role_apply_due(cfg.state_dir, rendered, env_path)
        if not apply_due:
            log.info(
                "supervisor.heartbeat.lifecycle_skipped",
                reason="env_unchanged",
                env_hash=env_hash[:12],
            )
        else:
            lifecycle = apply_role_assignment(target.profiles, env_path)
            log.info(
                "supervisor.heartbeat.lifecycle_applied",
                state=lifecycle.state,
                reason=lifecycle.reason,
                started=list(lifecycle.started),
                stopped=list(lifecycle.stopped),
            )
            # The state + reason are returned on the NEXT heartbeat (not
            # this one — we've already POSTed). Cache them on disk so a
            # supervisor restart doesn't lose them.
            _persist_lifecycle_state(cfg.state_dir, lifecycle.state, lifecycle.reason)
            # The runtime set just changed (or attempted to) — invalidate
            # the watchdog cache so the next heartbeat re-probes
            # immediately rather than rendering 5-min-stale health.
            # ``_last_watchdog_at`` is already declared global at the
            # top of this function (one declaration per scope rule).
            _last_watchdog_at = 0.0
            # Only stamp the hash on success — a failed apply should
            # re-attempt on the next heartbeat (the failure may have
            # been transient: image pull glitch, transient port
            # conflict, etc).
            if lifecycle.state in ("ready", "idle"):
                _write_last_apply_hash(cfg.state_dir, env_hash)

    # Identity unused in C2's payload but kept on the signature so
    # C2's mTLS upgrade doesn't need to thread it back in. Silence
    # the linter without adding a runtime cost.
    _ = identity

    return held


_LIFECYCLE_STATE_FILE = "role-switch-state"
_LAST_APPLY_HASH_FILE = "role-compose.env.hash"


def _role_apply_key(rendered_env: str, env_path: Path) -> str:
    """The skip key for the role apply: everything the apply sends (#1203).

    The rendered role env plus ``role_release_fingerprint`` (the image tag and
    the chart the apply renders). Keyed on the env alone, a slot upgrade never
    changed the key, because the env carries only role-scoped values. A stamp
    written by a supervisor that keyed on the env alone never equals this key,
    so the first heartbeat after upgrading onto this code re-applies once.
    """
    material = rendered_env + role_release_fingerprint(env_path)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _role_apply_due(state_dir: Path, rendered_env: str, env_path: Path) -> tuple[bool, str]:
    """(whether the role apply must run on this heartbeat, its key).

    Due when the key differs from the one stamped after the last successful
    apply, or when there is no stamp."""
    key = _role_apply_key(rendered_env, env_path)
    return key != _read_last_apply_hash(state_dir), key


def _read_last_apply_hash(state_dir: Path) -> str | None:
    """Return the key (``_role_apply_key``) of the last successful
    ``apply_role_assignment``, or ``None`` on first boot / no prior
    apply / file missing. Used by the heartbeat to skip the apply
    when nothing it would send has changed."""
    path = state_dir / _LAST_APPLY_HASH_FILE
    try:
        return path.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _write_last_apply_hash(state_dir: Path, env_hash: str) -> None:
    """Stamp the apply key so subsequent heartbeats can skip the
    apply when nothing it would send has changed. Atomic write
    so a supervisor crash mid-flush can't leave a torn file that
    would silently skip a real divergence."""
    path = state_dir / _LAST_APPLY_HASH_FILE
    try:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(env_hash + "\n", encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def _persist_lifecycle_state(state_dir: Path, state: str, reason: str | None) -> None:
    """Write the most recent compose-lifecycle outcome to disk so the
    NEXT heartbeat reports it (this one has already left)."""
    path = state_dir / _LIFECYCLE_STATE_FILE
    payload = state
    if reason:
        payload += "\n" + reason
    try:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def _read_lifecycle_state(state_dir: Path) -> tuple[str | None, str | None]:
    """Read the last persisted lifecycle outcome. Returns
    ``(state, reason)`` — both ``None`` when no prior pass."""
    path = state_dir / _LIFECYCLE_STATE_FILE
    if not path.exists():
        return None, None
    try:
        body = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None, None
    state = body[0].strip() if body else None
    reason = "\n".join(body[1:]).strip() or None if len(body) > 1 else None
    return state, reason
