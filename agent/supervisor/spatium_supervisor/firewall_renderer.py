"""Role-driven nftables drop-in renderer for the supervisor (#170 Wave C3).

Builds the body of ``/etc/nftables.d/spatium-role.nft`` from the
control plane's ``role_assignment`` block plus the derived firewall
inputs the heartbeat now carries (#285 Phase 1). The host's master
``/etc/nftables.conf`` includes everything under
``/etc/nftables.d/*.nft`` inside the inet filter table's ``input``
chain (same pattern the SNMP / NTP drop-ins already use, per
#153 + #154).

Always-open management rules (regardless of role):

* SSH (operator escape hatch).
* ICMP / ICMPv6 echo-request (monitoring).
* Loopback.
* Established / related (the master conf's first input rule
  already covers this — we don't restate it).

No data-plane (flannel/wireguard) INPUT rule is emitted: on k3s+flannel
that inter-node traffic does not traverse the host ``inet filter`` INPUT
chain (field-verified on a 3-node appliance — cross-node pods stay
healthy with no ``8472`` accept), so an INPUT rule for it would be dead
weight. **Keep it that way** — this body is rendered byte-identically by
``backend/app/services/appliance/firewall.py:compile_firewall_body`` once
#285 Phase 2a moves render authority server-side; do not add a one-sided
data-plane rule here or there (the identity regression test guards it).

Per-role openings:

* ``dns-bind9`` / ``dns-powerdns``: UDP + TCP / 53.
* ``dhcp``: UDP / 67, 68, 547 (547: DHCPv6 — on-link Solicit and relayed
  Relay-Forward, #1139).
* ``observer`` / ``custom``: no ports.

Control-plane derived (#272 Phase 7b + #285 Phase 1 — CP nodes only):

* kubelet ``10250`` additionally scoped to pod ∪ service CIDRs (#993) so
  the api pod can read its OWN node's kubelet — the peer rule below never
  covers that, and on a single node is not emitted at all
* etcd ``2379`` / ``2380`` + kubelet ``10250`` scoped to the peer
  node IPs — NEVER LAN-wide (the #285 hardening).
* kube-apiserver ``6443`` scoped to peers ∪ pod CIDR ∪ service CIDR ∪
  the operator ``kubeapi_expose_cidrs`` allowlist (in-cluster
  apiserver access traverses INPUT via the service-IP DNAT with
  ``saddr=pod-IP``).
* MetalLB memberlist ``7946`` tcp+udp scoped to peers, emitted only
  when the cluster is genuinely multi-node (``cp_member_count >= 2``)
  AND a control-plane VIP is configured — otherwise VIP failover
  silently stops the moment the base accept is removed.

All saddr sets are family-split (``ip saddr`` for v4, ``ip6 saddr``
for v6) so a v6 peer is scoped by its real ``/128`` rather than a
fabricated ``/32``, and a v6 entry can never leak into a v4 set.

Operator override: ``firewall_extra`` is appended verbatim at the
end of the drop-in. The supervisor runs ``nft -c -f`` against the
generated file before live-swap; a syntax error rejects the apply
without leaving the firewall in a half-rendered state.

Pure functions only — the actual file write + ``nft -f`` invocation
lives in the supervisor's heartbeat loop alongside the role-env
write, sharing the same atomic-rename + validation shape.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

import structlog

log = structlog.get_logger(__name__)


def _validated_cidrs(raw: list[Any]) -> list[str]:
    """Filter ``raw`` down to syntactically valid, canonicalised CIDR
    strings.

    Issue #236 — the control plane's CIDR lists were previously inlined
    verbatim into the nft rule. An invalid (or malicious) entry like
    ``1.2.3.4 }, drop; tcp dport 22 accept; #`` would inject extra nft
    rules into the host firewall. Reject anything that doesn't round-trip
    through ``ipaddress.ip_network`` in strict=False mode; log the bad
    entry + drop it from the rendered allowlist.
    """
    out: list[str] = []
    for c in raw:
        if not isinstance(c, str):
            log.warning("supervisor.firewall_renderer.invalid_cidr_type", value=c)
            continue
        s = c.strip()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except (ValueError, TypeError) as exc:
            log.warning(
                "supervisor.firewall_renderer.invalid_cidr",
                value=s,
                error=str(exc),
            )
            continue
        # Always re-render through ipaddress.ip_network's str() so the
        # output is canonical (e.g. "192.168.1.0/24" not the raw
        # input). nft accepts this form verbatim.
        out.append(str(net))
    return out


def _split_families(cidrs: list[Any]) -> tuple[list[str], list[str]]:
    """Validate ``cidrs`` and split into (v4, v6) canonical lists.

    Each list is de-duplicated + sorted so the rendered saddr set is
    deterministic (a benign reorder upstream doesn't shift the body
    hash the heartbeat compares against). #285 Phase 1 — the
    family-split is what lets a v6 peer be scoped by its ``/128``
    instead of leaking into / fabricating a v4 ``/32``.
    """
    v4: set[str] = set()
    v6: set[str] = set()
    for c in _validated_cidrs(cidrs):
        # _validated_cidrs already round-tripped through ip_network, so
        # this parse can't raise.
        if ipaddress.ip_network(c, strict=False).version == 6:
            v6.add(c)
        else:
            v4.add(c)
    return sorted(v4), sorted(v6)


@dataclass(frozen=True)
class FirewallProfile:
    """Result of compiling a role_assignment block into an nftables
    drop-in body.

    ``name`` is the operator-friendly profile label rendered in the
    fleet UI ("dns-only" / "dns-and-dhcp" / "idle"); the supervisor
    logs it on each apply so journalctl shows the active profile
    without having to inspect the file itself.

    ``expected_tcp_ports`` + ``expected_udp_ports`` carry the union of
    service ports the drop-in opens. Retained for reference / any
    future live-ruleset check; the supervisor's drift detection keys
    off the full-body hash (heartbeat.py Phase 9), not these sets.
    """

    name: str
    body: str
    expected_tcp_ports: frozenset[int] = frozenset()
    expected_udp_ports: frozenset[int] = frozenset()


# Per-role service port set. Empty = no service ports opened (the role
# still runs, just doesn't accept inbound on a known port — observer is
# the canonical example).
_ROLE_PORTS_TCP: dict[str, list[int]] = {
    "dns-bind9": [53],
    "dns-powerdns": [53],
    "dns-technitium": [53],
    # BGP (#566). The collector normally DIALS the router (outbound, allowed
    # by default egress), but opening inbound tcp/179 lets the router initiate
    # the session (passive collector) and keeps firewall drift-detection aware
    # of the port for the looking-glass role.
    "looking-glass": [179],
}
_ROLE_PORTS_UDP: dict[str, list[int]] = {
    "dns-bind9": [53],
    "dns-powerdns": [53],
    "dns-technitium": [53],
    # 547 is the DHCPv6 server port (#1139): on-link Solicits to ff02::1:2 and
    # relays' Relay-Forward to the server's address. Kea's v6 server has no
    # raw-socket mode, so without it every v6 packet dies on the drop policy.
    "dhcp": [67, 68, 547],
}

# #285 Phase 1 — control-plane peer ports, split by purpose so each can
# carry the right source scope. etcd + kubelet are peer-ONLY (the #285
# hardening); 6443 widens to peers ∪ pod ∪ svc ∪ kubeapi_expose;
# memberlist is peer-only + gated on multi-node + VIP.
# #593 — etcd's raft PEER port, exported because firewall_peer_audit audits
# rendered bodies for it. One definition, so a change here can never leave the
# audit checking a port the renderer no longer opens (which would silently
# re-enable the self-partition this guard exists to prevent).
ETCD_PEER_PORT = 2380
_K3S_ETCD_KUBELET_TCP: tuple[int, ...] = (2379, ETCD_PEER_PORT, 10250)
_K3S_APISERVER_TCP = 6443
# #993 — the kubelet, reachable from INSIDE the cluster as well as from
# peers. The peer-scoped rule above covers a kubelet on another node; this
# covers the api pod reading its OWN node's kubelet, which #990's direct
# cluster-health transport needs and which no rule opened: a non-hostNetwork
# pod talking to its node's IP enters via cni0 with a pod-CIDR source and
# traverses INPUT like any LAN packet, and ``cluster_peer_cidrs`` is EMPTY on
# a single node, so the peer rule was not even emitted. Every appliance
# therefore fell back to the apiserver ``nodes/proxy`` transport after a full
# connect timeout per node, on the request path.
#
# Scoped to pod ∪ service ONLY — deliberately NOT the operator's
# ``kubeapi_expose_cidrs`` allowlist that widens 6443. That list exists so an
# operator can reach the APISERVER from the LAN, which is guarded by RBAC on
# every request; the kubelet API is a different proposition (``/exec``,
# ``/run``, ``/attach``), and quietly extending a "let me run kubectl"
# allowlist to it would be a privilege escalation nobody asked for.
_K3S_KUBELET_TCP = 10250
_METALLB_MEMBERLIST = 7946


def _profile_name(roles: list[str]) -> str:
    has_dns = any(r in roles for r in ("dns-bind9", "dns-powerdns", "dns-technitium"))
    has_dhcp = "dhcp" in roles
    if has_dns and has_dhcp:
        return "dns-and-dhcp"
    if has_dns:
        return "dns-only"
    if has_dhcp:
        return "dhcp-only"
    return "idle"


def _emit_family_rule(
    lines: list[str],
    v4: list[str],
    v6: list[str],
    rule_suffix: str,
    comment: str,
) -> None:
    """Append family-split ``ip[6] saddr { ... } <rule_suffix>`` lines
    for whichever family has members. ``rule_suffix`` is e.g.
    ``tcp dport { 2379, 2380, 10250 } accept``."""
    if v4:
        lines.append(
            f'ip saddr {{ {", ".join(v4)} }} {rule_suffix} comment "{comment}-v4"'
        )
    if v6:
        lines.append(
            f'ip6 saddr {{ {", ".join(v6)} }} {rule_suffix} comment "{comment}-v6"'
        )


def render_drop_in(
    role_assignment: dict[str, Any] | None,
    cluster_peer_cidrs: list[Any] | None = None,
    *,
    pod_cidrs: list[Any] | None = None,
    service_cidrs: list[Any] | None = None,
    cp_member_count: int = 1,
    vip_configured: bool = False,
    web_ui_allowed_cidrs: list[Any] | None = None,
    ssh_scope_cidrs: list[Any] | None = None,
) -> FirewallProfile:
    """Translate a role_assignment + the heartbeat's derived firewall
    inputs into an nftables drop-in body.

    Emits the management rules, then per-role service rules, then the
    control-plane-derived peer/apiserver/memberlist rules (CP nodes only
    — ``cluster_peer_cidrs`` empty ⇒ skip etcd/kubelet), then the
    operator's ``firewall_extra``. Idle appliances get management rules
    only.

    The header carries a ``# spatium-bootstrap: retire|keep`` directive
    the host-side reload runner reads to retire the baked 6443 bootstrap
    sentinel once the cluster is genuinely multi-node (#285 Phase 1b —
    6443 then narrows to the scoped ``kubeapi`` rule below).

    Every fragment is a bare ``proto dport N accept`` (or
    ``ip[6] saddr { ... } …``) since the include glob sits *inside*
    ``chain input`` in the master conf.

    No data-plane (flannel VXLAN / wireguard) rule is emitted: on
    k3s+flannel that inter-node traffic does not traverse the host's
    ``inet filter`` INPUT chain (field-verified on a 3-node appliance —
    cross-node pods stay healthy with no 8472 accept), so an INPUT rule
    for it would be dead weight.
    """
    role_assignment = role_assignment or {}
    roles = [r for r in (role_assignment.get("roles") or []) if isinstance(r, str)]
    firewall_extra = role_assignment.get("firewall_extra") or ""
    # Issue #183 Phase 6 — operator-controlled CIDR allowlist for direct
    # kubeapi access on tcp/6443. Folded into the 6443 saddr set below.
    # Issue #236 — each entry MUST validate before it lands in the set.
    kubeapi_cidrs = role_assignment.get("kubeapi_expose_cidrs") or []

    profile = _profile_name(roles)
    peer_v4, peer_v6 = _split_families(cluster_peer_cidrs or [])
    is_cp = bool(peer_v4 or peer_v6) or bool(pod_cidrs) or bool(service_cidrs)

    tcp_ports: set[int] = set()
    udp_ports: set[int] = set()

    lines: list[str] = []
    lines.append(
        "# Auto-generated by spatium-supervisor — do not hand-edit. "
        "See /etc/spatiumddi/firewall-extra on the host (or the fleet UI)"
    )
    lines.append(
        "# for the operator-override surface that lands at the end of this file."
    )
    lines.append(f"# profile: {profile}")
    lines.append(f"# roles: {','.join(roles) if roles else '(idle)'}")
    # #285 Phase 1b — host-runner directive: retire the baked 6443
    # bootstrap sentinel once the control plane is genuinely multi-node
    # (settled CP members >= 2), at which point the scoped ``kubeapi``
    # rule below (peers ∪ pod ∪ svc ∪ kubeapi_expose) is the only path to
    # 6443 and the LAN-wide sentinel is no longer needed. Single-node →
    # keep it (etcd is loopback-only; 6443 must stay LAN-reachable for the
    # node's own pods + a first promote/join). The runner restores a
    # retired sentinel if the cluster ever shrinks back to single-node.
    bootstrap_action = "retire" if cp_member_count >= 2 else "keep"
    lines.append(f"# spatium-bootstrap: {bootstrap_action}")
    # #769 — host-runner directive for the baked Web-UI sentinel
    # (00-spatium-webui.nft), which opens 80/443 from first boot so the
    # "still initialising" page is reachable before the supervisor has
    # ever heartbeated. Retire it once a source scope is configured: the
    # sentinel's unconditional accept sorts EARLIER in the include glob
    # and nftables accepts on first match, so leaving it would silently
    # defeat the scoped rule emitted below. Unscoped → keep (both rules
    # say the same thing); clearing a scope restores it.
    webui_action = "retire" if web_ui_allowed_cidrs else "keep"
    lines.append(f"# spatium-webui: {webui_action}")
    # #1009 — host-runner directive for the baked SSH sentinel
    # (00-spatium-ssh.nft), which opens port 22 unconditionally from first
    # boot. Same shape as the Web-UI sentinel above and for the same
    # reason: it sorts EARLIER in the include glob than the scoped rule
    # spatiumddi-ssh-reload renders, and nftables accepts on first match,
    # so the operator's allowlist was dead code behind it.
    #
    # Retired only under ``ssh_lockdown`` (services.appliance.ssh.
    # effective_ssh_scope resolves the flag; an empty scope here means it
    # is off). That floor is what docs/design/FLEET_FIREWALL.md §6.1 calls
    # the irreducible recovery channel, so removing it is an explicit
    # operator decision, never a side effect of typing a CIDR.
    ssh_action = "retire" if ssh_scope_cidrs else "keep"
    lines.append(f"# spatium-ssh: {ssh_action}")
    lines.append("")
    lines.append("# ── Management (always open) ────────────────────────────────")
    # SSH — the management floor. Unconditional unless the operator has
    # turned on lockdown, in which case it is source-scoped to the same
    # CIDRs the sentinel directive above retires the baked floor for.
    # BOTH have to move together: this line sits AFTER 50-spatium-ssh.nft
    # in the include glob, so leaving it unconditional would let every
    # packet the scoped rule declined fall straight through to it (#1009).
    if ssh_scope_cidrs:
        ssh_v4, ssh_v6 = _split_families(list(ssh_scope_cidrs))
        _emit_family_rule(lines, ssh_v4, ssh_v6, "tcp dport 22 accept", "ssh")
    else:
        lines.append('tcp dport 22 accept comment "ssh"')
    lines.append('icmp type echo-request accept comment "icmpv4 ping"')
    lines.append('icmpv6 type echo-request accept comment "icmpv6 ping"')
    lines.append('iif lo accept comment "loopback"')
    # Web UI (HTTP + HTTPS) — #285 Phase 6. Open by default; source-scoped
    # when web_ui_allowed_cidrs is set (the base /etc/nftables.conf no longer
    # opens 80/443, so this drop-in is authoritative). MUST stay byte-identical
    # to the backend compile_firewall_body / compile_firewall_from_policies.
    if web_ui_allowed_cidrs:
        web_v4, web_v6 = _split_families(list(web_ui_allowed_cidrs))
        _emit_family_rule(
            lines, web_v4, web_v6, "tcp dport { 80, 443 } accept", "web-ui"
        )
    else:
        lines.append('tcp dport { 80, 443 } accept comment "web-ui"')

    # ── Per-role service ports ─────────────────────────────────────────
    role_tcp: set[int] = set()
    role_udp: set[int] = set()
    for role in roles:
        role_tcp.update(_ROLE_PORTS_TCP.get(role, []))
        role_udp.update(_ROLE_PORTS_UDP.get(role, []))
    # Issue #50 — DoT / DoH listen on operator-chosen ports, so unlike Do53
    # they can't come from the static table above. The control plane derives
    # them from the assigned DNS group's options (only when a cert is
    # actually present) and ships them on the role assignment. Ignored
    # unless a DNS role is assigned, so a stale value on a re-roled
    # appliance can't leave a port open.
    if any(r in roles for r in ("dns-bind9", "dns-powerdns", "dns-technitium")):
        for raw in role_assignment.get("dns_encrypted_tcp_ports") or []:
            try:
                port = int(raw)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                role_tcp.add(port)
        # #741 — DoQ is UDP. Same operator-chosen shape, different table:
        # adding it to role_tcp would leave the listener unreachable while
        # the rendered ruleset looked correct.
        for raw in role_assignment.get("dns_encrypted_udp_ports") or []:
            try:
                port = int(raw)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                role_udp.add(port)
    if role_udp or role_tcp:
        lines.append("")
        lines.append("# ── Per-role service ports ─────────────────────────────")
    for port in sorted(role_udp):
        lines.append(f'udp dport {port} accept comment "role:{profile}"')
    for port in sorted(role_tcp):
        lines.append(f'tcp dport {port} accept comment "role:{profile}"')
    tcp_ports.update(role_tcp)
    udp_ports.update(role_udp)

    # ── Control-plane derived (CP nodes only) ──────────────────────────
    if is_cp:
        lines.append("")
        lines.append("# ── Control-plane derived (peer-scoped, #272/#285) ─────")
        # etcd + kubelet — peers ONLY, never LAN-wide (the #285 fix).
        if peer_v4 or peer_v6:
            etcd_kubelet = (
                "{ " + ", ".join(str(p) for p in _K3S_ETCD_KUBELET_TCP) + " }"
            )
            _emit_family_rule(
                lines, peer_v4, peer_v6, f"tcp dport {etcd_kubelet} accept", "k3s-peer"
            )
            tcp_ports.update(_K3S_ETCD_KUBELET_TCP)
        # apiserver 6443 — peers ∪ pod ∪ svc ∪ kubeapi_expose.
        api_v4, api_v6 = _split_families(
            list(cluster_peer_cidrs or [])
            + list(pod_cidrs or [])
            + list(service_cidrs or [])
            + list(kubeapi_cidrs)
        )
        if api_v4 or api_v6:
            _emit_family_rule(
                lines,
                api_v4,
                api_v6,
                f"tcp dport {_K3S_APISERVER_TCP} accept",
                "kubeapi",
            )
            tcp_ports.add(_K3S_APISERVER_TCP)
        # kubelet 10250 — pod ∪ svc (peers are covered by the k3s-peer rule
        # above). Emitted whenever this is a CP node, single or HA.
        kubelet_v4, kubelet_v6 = _split_families(
            list(pod_cidrs or []) + list(service_cidrs or [])
        )
        if kubelet_v4 or kubelet_v6:
            _emit_family_rule(
                lines,
                kubelet_v4,
                kubelet_v6,
                f"tcp dport {_K3S_KUBELET_TCP} accept",
                "kubelet",
            )
            tcp_ports.add(_K3S_KUBELET_TCP)
        # MetalLB memberlist 7946 tcp+udp — peers only, gated on a
        # genuinely multi-node cluster + a configured VIP. Derived from
        # the membership model, NOT a metallb_enabled flag the
        # supervisor doesn't mirror; without it VIP failover silently
        # stops the moment the base accept is removed.
        if (peer_v4 or peer_v6) and cp_member_count >= 2 and vip_configured:
            _emit_family_rule(
                lines,
                peer_v4,
                peer_v6,
                f"tcp dport {_METALLB_MEMBERLIST} accept",
                "metallb-memberlist-tcp",
            )
            _emit_family_rule(
                lines,
                peer_v4,
                peer_v6,
                f"udp dport {_METALLB_MEMBERLIST} accept",
                "metallb-memberlist-udp",
            )
            tcp_ports.add(_METALLB_MEMBERLIST)
            udp_ports.add(_METALLB_MEMBERLIST)

    if firewall_extra.strip():
        lines.append("")
        lines.append("# ── Operator override (firewall_extra) ─────────────────")
        lines.append(firewall_extra.rstrip("\n"))

    body = "\n".join(lines) + "\n"
    return FirewallProfile(
        name=profile,
        body=body,
        expected_tcp_ports=frozenset(tcp_ports),
        expected_udp_ports=frozenset(udp_ports),
    )


__all__ = ["FirewallProfile", "render_drop_in"]
