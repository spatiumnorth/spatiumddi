"""etcd / control-plane peer-drift cross-check (#285 Phase 5, warn-only).

The firewall opens etcd (2379/2380) + kubelet (10250) + memberlist (7946) to a
**peer CIDR set** the control plane derives from the known appliance rows. That
set can drift from the *live* cluster membership: a node that joined but whose
peer entry hasn't propagated (uncovered), or a left/dead member whose /32 is
still in the scope (stale). Neither breaks anything — the peer set only ever
GROWS access to real cluster members — but surfacing the drift helps operators
notice a wedged peer-resolve or a half-finished demote.

This is **warn-only**: it logs ``supervisor.firewall.peer_drift`` and never
mutates the ruleset. The live membership is read from the kube API (`GET
/api/v1/nodes`, control-plane-labelled), so it's effectively seed-only — a
non-seed node has no admin kubeconfig and the read fails best-effort to a no-op.
``compute_peer_drift`` is the pure, unit-tested core.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import structlog

from . import firewall_renderer, k8s_api

log = structlog.get_logger(__name__)

_CP_LABEL = "node-role.kubernetes.io/control-plane"

# #593 — k3s stamps this on every embedded-etcd server node. It is managed by
# k3s from ACTUAL membership, not by us: service_lifecycle.reconcile_node_labels
# only ever touches ``spatium.io/role-*``. That independence is the whole point
# — it is a statement about reality, not about the control plane's row.
_ETCD_LABEL = "node-role.kubernetes.io/etcd"

# etcd's raft peer port. Single source of truth is the renderer's port tuple,
# so a future change there can't leave this audit checking a stale port while
# the rendered rule opens a different one.
_ETCD_PEER_PORT = str(firewall_renderer.ETCD_PEER_PORT)

# nftables' own comment clause. NOT a "#" comment, and it must be stripped
# BEFORE splitting on "#", or a comment containing a "#" leaves an unterminated
# quote that this regex can no longer match — the comment's text then survives
# into the code and `comment "port 2380 #note"` reads as an etcd accept.
_NFT_COMMENT_RE = re.compile(r'comment\s+"[^"]*"')

# The port must appear in a DESTINATION-PORT position, not merely somewhere on
# an accept line. `ip6 saddr { fd00:2380::/64 } tcp dport 6443 accept` opens
# 6443 only, yet a bare number match finds "2380" in the address hextet
# (bracketed by ':' — not digits — so a \d-boundary guard does not help).
# Captures either a set `{ 2379, 2380, 10250 }` or a single token `2380`.
_DPORT_RE = re.compile(r"\bdport\s+(\{[^}]*\}|\S+)")
# Whole-number match inside that capture, so "12380" can't pass for "2380" and
# a range endpoint like "2379-2380" still counts.
_ETCD_PEER_PORT_RE = re.compile(rf"(?<!\d){_ETCD_PEER_PORT}(?!\d)")

# Sub-2s so a wedged apiserver can't stall the heartbeat loop — the same
# reasoning (and value) as k8s_api.check_kubeapi_ready, whose default we would
# otherwise inherit at 10s. ``None`` is never cached, so a 10s connect timeout
# would be re-paid on every heartbeat for the whole outage.
_KUBEAPI_TIMEOUT_S = 2.0


def compute_peer_drift(
    member_ips: list[str], peer_cidrs: list[str], self_ips: set[str]
) -> dict[str, list[str]]:
    """Pure drift computation.

    * ``member_ips`` — live control-plane node InternalIPs.
    * ``peer_cidrs`` — the firewall peer set we render.
    * ``self_ips`` — this node's own IPs (excluded; peers are the OTHERS).

    Returns ``{"uncovered_members": [...], "stale_cidrs": [...]}``:
    * uncovered — a live member IP (not self) not inside any peer CIDR.
    * stale — a host-route peer CIDR (/32 or /128) whose address is neither a
      live member nor self (a left/dead member still in scope). Broader CIDRs
      are skipped (can't attribute them to a single absent member).
    """

    def _addrs(values: Any) -> set[Any]:
        out: set[Any] = set()
        for v in values:
            try:
                out.add(ipaddress.ip_address(v))
            except ValueError:
                continue
        return out

    self_addrs = _addrs(self_ips)
    member_addrs = _addrs(member_ips)
    nets: list[tuple[str, Any]] = []
    for c in peer_cidrs:
        try:
            nets.append((c, ipaddress.ip_network(c, strict=False)))
        except ValueError:
            continue

    uncovered = sorted(
        str(a)
        for a in member_addrs
        if a not in self_addrs and not any(a in n for _, n in nets)
    )
    stale = sorted(
        c
        for c, n in nets
        if n.num_addresses == 1
        and n.network_address not in member_addrs
        and n.network_address not in self_addrs
    )
    return {"uncovered_members": uncovered, "stale_cidrs": stale}


def list_control_plane_node_ips() -> list[str] | None:
    """Live control-plane node InternalIPs via the kube API, or None when the
    API is unreachable (non-seed node / kubeapi down) — best-effort."""
    try:
        status, body = k8s_api._request("GET", "/api/v1/nodes", timeout=_KUBEAPI_TIMEOUT_S)
    except (RuntimeError, OSError):
        # OSError is NOT redundant: k8s_api._request builds its HTTPSConnection
        # (and reads the CA via _ssl_context) OUTSIDE the try that converts
        # transport errors to RuntimeError, so a missing/unreadable ca.crt
        # raises straight through. Its sibling _etcd_membership_uncached
        # already catches both.
        return None
    if status != 200:
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    ips: list[str] = []
    for item in data.get("items", []):
        labels = (item.get("metadata") or {}).get("labels") or {}
        if _CP_LABEL not in labels:
            continue
        for addr in (item.get("status") or {}).get("addresses") or []:
            if addr.get("type") == "InternalIP" and addr.get("address"):
                ips.append(str(addr["address"]))
    return ips


# ── #593 — never let the firewall partition a live etcd member ──────────────
#
# The per-role drop-in used to be rendered purely from the control plane's row
# (``cluster_role``). Observed live on a 3-node appliance: ddi2's row had gone
# ``cluster_role = NULL`` after a failed re-join, while ddi2 was still a voting
# etcd member. The supervisor concluded "plain agent node", rendered an agent
# firewall with no ``k3s-peer`` rule, and ddi2's own nftables silently dropped
# its peers' inbound raft traffic. Its peers logged ``dial tcp …:2380: i/o
# timeout`` every 5 s against a member that was up the whole time.
#
# The triggering row bug is fixed (#591), but the COUPLING is the hazard: any
# row/reality divergence reproduces this — a stuck heartbeat, a control plane
# restored from an older backup, a half-landed promote, an operator clearing
# state with the #591 escape hatch. And it fails in the worst direction:
# closing the peer port on a live member drops it out of raft, which on a
# 3-node cluster leaves you one node from losing quorum.
#
# So the peer rule is keyed off OBSERVED LOCAL STATE, with three defences:
#   1. recover a peer set from live membership when the row supplies none
#   2. refuse to apply any body that would close 2380 on a node that k3s says
#      is an etcd member — better a stale-but-open ruleset than a self-inflicted
#      partition (and non-negotiable #5: keep serving when the control plane is
#      wrong or unreachable)
#   3. fall back WITHOUT the network when the probe can't run, because the probe
#      itself depends on it. k8s_api reads the apiserver ClusterIP (the
#      supervisor pod has no hostNetwork, so there is no local-apiserver path
#      to use — k8s_proxy's "127.0.0.1:6443" docstring notwithstanding, it also
#      dials cfg.host). A partitioned node therefore cannot probe, and without
#      a fallback the guard would fail open exactly when it is needed. Falls
#      back to a purely local cluster-member signal, then to a previously
#      CONFIRMED membership on disk. Only ``True`` is ever remembered — see
#      _remember_membership for why a persisted ``False`` would be this bug.


# Last KNOWN membership, persisted across supervisor restarts on the host bind
# mount. The apiserver read below goes to the ``kubernetes`` Service ClusterIP
# (k8s_api resolves KUBERNETES_SERVICE_HOST; the supervisor DaemonSet has no
# hostNetwork), so kube-proxy may DNAT it to ANY apiserver endpoint — possibly
# a remote one. On a node partitioned at the network layer, i.e. exactly the
# fault this module guards, that read fails and the probe returns None.
#
# Without a memory of what we last knew, `None` would mean "don't know", the
# guard would fail open, and the partitioned member would firewall its own
# 2380 shut — after which it can never read membership again to reopen it.
# So a successful probe is written to disk, and an unreadable apiserver falls
# back to that last-known answer instead of to ignorance.
_ETCD_MEMBER_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/etcd-member")


def _remember_membership(value: bool) -> None:
    """Persist a KNOWN membership answer — but only a ``True``.

    A persisted ``False`` would be the #593 bug written to disk: a node
    promoted while its apiserver happens to be unreachable would probe None,
    recall "not a member", pass the guard, and firewall its own raft port shut.
    A confirmed ``False`` therefore CLEARS the marker rather than recording it.

    Best-effort: a read-only or missing release-state dir must never break the
    firewall path.
    """
    try:
        if not value:
            _ETCD_MEMBER_SIDECAR.unlink(missing_ok=True)
            return
        _ETCD_MEMBER_SIDECAR.parent.mkdir(parents=True, exist_ok=True)
        tmp = _ETCD_MEMBER_SIDECAR.with_name(_ETCD_MEMBER_SIDECAR.name + ".new")
        tmp.write_text("true\n", encoding="utf-8")
        tmp.replace(_ETCD_MEMBER_SIDECAR)
    except OSError as exc:
        log.debug("supervisor.firewall.membership_persist_failed", error=str(exc))


def _recall_membership() -> bool | None:
    """``True`` when a previous probe confirmed membership; otherwise None.
    Never ``False`` — see _remember_membership."""
    try:
        text = _ETCD_MEMBER_SIDECAR.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return True if text == "true" else None


def _local_cluster_member_signal() -> bool:
    """Is this node a control-plane cluster member, per purely LOCAL state?

    Needs no network, so it answers during the very partition that defeats the
    kube-API probe. The one local membership definition
    (``appliance_state.is_control_plane_member``, shared with the heartbeat and
    the role chart values): the node was installed as a control-plane seed, or
    it was promoted and its host runner reported the join completed. On this
    appliance a control-plane member always runs embedded etcd, so either
    implies an etcd member.
    """
    from . import appliance_state  # noqa: PLC0415 — avoid import cycle at load

    try:
        return appliance_state.is_control_plane_member()
    except Exception:  # noqa: BLE001 — a best-effort fallback must never raise
        return False


# Membership changes only on promote/demote, while the firewall path runs every
# heartbeat. Cache the answer — but ONLY ``True``.
#
# A stale ``True`` merely delays narrowing the firewall after a real demote,
# and the peer rule only ever over-permits to real cluster members. A stale
# ``False`` IS the #593 bug: a node promoted to etcd server whose control-plane
# row hasn't caught up would read the cached "not a member", pass the guard,
# and firewall its own raft port shut. That is the precise "half-landed
# promote" case this module exists for, so ``False`` is always re-probed.
# ``None`` is never cached either — an unreachable apiserver must be retried,
# not remembered as "don't know".
_ETCD_MEMBER_TTL_S = 300.0


@dataclass
class _MembershipCache:
    """In-process memo of the last probe that answered True.

    A one-field object rather than a module global + ``global`` statement: the
    field holds the monotonic timestamp of the last ``True``, and its type
    encodes the invariant — there is nowhere here to put a cached ``False``.
    """

    true_at: float | None = None


_membership_cache = _MembershipCache()


def _etcd_membership_uncached() -> bool | None:
    node_name = os.environ.get("NODE_NAME") or os.environ.get("APPLIANCE_HOSTNAME")
    if not node_name:
        return None
    try:
        status, body = k8s_api._request(
            "GET", f"/api/v1/nodes/{quote(node_name)}", timeout=_KUBEAPI_TIMEOUT_S
        )
    except (RuntimeError, OSError):
        return None
    if status != 200:
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    labels = (data.get("metadata") or {}).get("labels") or {}
    return _ETCD_LABEL in labels


def local_node_is_etcd_member() -> bool | None:
    """Does k3s consider THIS node an embedded-etcd server?

    Reads the local node's own labels. When the apiserver is unreachable — the
    partition this module guards against — falls back, in order, to a purely
    LOCAL cluster-member signal and then to a previously confirmed ``True``.

    ``None`` only when nothing says "member": no local signal, never a
    successful probe. Callers must treat ``None`` as "don't know", never as
    "no" — the guard fails open there, which is correct for a plain agent
    appliance and would otherwise freeze the firewall on every non-etcd node.

    Every fallback can only answer ``True`` or "don't know". A fallback that
    could answer ``False`` would be this bug on a slower timescale: a node
    promoted while its apiserver is unreachable would read "not a member",
    pass the guard, and firewall its own raft port shut.
    """
    now = time.monotonic()
    true_at = _membership_cache.true_at
    if true_at is not None and now - true_at < _ETCD_MEMBER_TTL_S:
        return True

    answer = _etcd_membership_uncached()
    if answer is not None:
        # Only a True is remembered in-process; a False clears the marker so the
        # very next tick re-probes and a promote is seen immediately.
        _membership_cache.true_at = now if answer else None
        _remember_membership(answer)
        return answer

    if _local_cluster_member_signal():
        log.warning(
            "supervisor.firewall.membership_probe_unreachable",
            using="local cluster-member signal",
            reason="kube apiserver unreadable; this node is a control-plane member",
        )
        return True

    if _recall_membership() is True:
        log.warning(
            "supervisor.firewall.membership_probe_unreachable",
            using="last confirmed membership",
            reason="kube apiserver unreadable; a previous probe confirmed this node is an etcd member",
        )
        return True

    return None


def _reset_etcd_member_cache() -> None:
    """Test hook — the marker is process-wide and would leak across cases."""
    _membership_cache.true_at = None


def body_opens_etcd_peers(body: str) -> bool:
    """True when `body` has at least one accept rule whose DESTINATION PORT
    covers etcd's raft peer port.

    Every subtlety here exists because a false positive is the dangerous
    direction: it tells `would_self_partition` the body is safe, and a live
    etcd member then firewalls itself out of raft.

    * nftables ``comment "..."`` clauses are stripped FIRST. They are not
      ``#`` comments, and splitting on ``#`` first would truncate a comment
      containing one (``comment "port 2380 #note"``) into an unterminated
      quote this regex can no longer match — leaking the comment's text, and
      its ``2380``, into the code.
    * ``#`` comments go next: the renderer's header names 2379/2380 in prose.
    * The port must sit in a ``dport`` position. ``ip6 saddr { fd00:2380::/64 }
      tcp dport 6443 accept`` opens only 6443, but a bare number match finds
      ``2380`` in the address hextet — it is bracketed by ``:``, not digits, so
      a digit-boundary guard does not save you.
    * Inside the dport capture the port is matched as a whole number, so
      ``12380`` cannot pass and a range endpoint (``2379-2380``) still counts.

    Known conservative gaps, all in the SAFE direction (a false negative makes
    the guard refuse a legitimate body, which leaves the last-good ruleset in
    place rather than partitioning the node): a rule split across physical
    lines with a trailing ``\\``, a numeric range that merely spans 2380
    (``2000-3000``), and a named port set (``tcp dport @etcd_ports``). Today's
    renderer emits one single-line rule per accept with a literal port set, so
    none of these occur; if that changes, the guard fails closed and loudly.
    """
    for raw in body.splitlines():
        code = _NFT_COMMENT_RE.sub("", raw).split("#", 1)[0].strip()
        if not code or "accept" not in code:
            continue
        for match in _DPORT_RE.finditer(code):
            if _ETCD_PEER_PORT_RE.search(match.group(1)):
                return True
    return False


def observed_peer_cidrs(self_ips: Iterable[str]) -> list[str] | None:
    """Host CIDRs for every live control-plane node except this one, read from
    the cluster itself.

    ``None`` when membership is unreadable — the caller then falls through to
    the refuse-to-apply guard rather than guessing. ``[]`` when the cluster IS
    readable and this node is the only control-plane member: a fresh
    single-node seed's correct body has no peer rule, and there is no raft
    peer to be partitioned from. Conflating those two empties made the guard
    refuse every fresh seed's firewall forever (no web-ui accepts; found live
    on ddi-pg dev rigs 2026-07-10)."""
    members = list_control_plane_node_ips()
    if not members:
        return None
    mine = set(self_ips)
    out: list[str] = []
    for ip in members:
        if ip in mine:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        out.append(f"{ip}/{addr.max_prefixlen}")
    return sorted(set(out))


def would_self_partition(body: str, *, is_etcd_member: bool | None,
                         live_peers: list[str] | None = None) -> bool:
    """True when applying `body` would close etcd's peer port on a live member.

    PURE — membership is passed in, never probed here, so a caller performs at
    most one apiserver read per firewall dispatch and the decision is trivially
    testable.

    False whenever membership is unknown: an unreadable kube API must not block
    a legitimate firewall update on a plain agent appliance, which would freeze
    the ruleset on every non-etcd node.

    ``live_peers`` is the observed_peer_cidrs() result: ``[]`` means the
    cluster was READ and this node is its only member — a fresh single-node
    seed. Its correct body has no peer rule and there is no peer to be
    partitioned from, so it must apply (refusing pinned every fresh seed on
    the k3s-bootstrap firewall forever — no web-ui accepts, API/UI dead from
    off-box; found live 2026-07-10). ``None`` means unknown — stay
    conservative and refuse a peer-rule-less body on a live member.
    """
    if is_etcd_member is not True:
        return False
    if live_peers is not None and not live_peers:
        return False
    return not body_opens_etcd_peers(body)


def warn_on_peer_drift(
    peer_cidrs: list[str], self_ips: list[str]
) -> dict[str, list[str]] | None:
    """Best-effort: read live CP members, compute drift, warn-log if any.
    Returns the drift dict (for tests) or None when membership is unreadable."""
    members = list_control_plane_node_ips()
    if members is None:
        return None
    drift = compute_peer_drift(members, peer_cidrs, set(self_ips))
    if drift["uncovered_members"] or drift["stale_cidrs"]:
        log.warning(
            "supervisor.firewall.peer_drift",
            uncovered_members=drift["uncovered_members"],
            stale_cidrs=drift["stale_cidrs"],
            peer_cidrs=peer_cidrs,
        )
    return drift
