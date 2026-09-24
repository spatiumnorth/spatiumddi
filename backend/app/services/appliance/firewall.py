"""Server-side fleet-firewall render (#285 Phase 2a).

Hoists the nftables drop-in render from the supervisor pod onto the
control plane (mirroring ``snmp_bundle`` / ``ntp_bundle`` / ``lldp_bundle``):
the heartbeat response carries the rendered body + a config hash, and the
supervisor becomes a pipe (``maybe_fire_firewall_reload``) that just writes
the host trigger. Gated behind ``platform_settings.firewall_enabled``
(default off) — when off, the supervisor keeps rendering in-pod via its
own ``firewall_renderer.render_drop_in`` (the #5 control-plane-loss
fallback, kept one release).

⚠️ KEEP IN SYNC — ``compile_firewall_body`` below is a VERBATIM port of
``agent/supervisor/spatium_supervisor/firewall_renderer.py:render_drop_in``
and MUST produce a byte-identical body (same helpers, constants, rule
order, comment text, the ``# spatium-bootstrap:`` directive). A divergence
means a node's rendered drop-in changes hash purely on which renderer ran,
re-firing the trigger + reload spuriously. A regression test asserts the
two outputs are identical across an input matrix; do not refactor one side
without the other. The in-pod copy is removed only in the release after 2a
ships fleet-wide.

The body hash is already canonical: peer/pod/service CIDR lists arrive
pre-sorted (``_cluster_peer_cidrs`` returns ``sorted(set(...))``) and
``_split_families`` sorts each family, so ``sha256(body)`` is stable under
a benign upstream reorder — no extra canonicalisation pass is needed. (If a
future renderer change emits an unsorted set, that is the regression, and
the identity test catches it.)
"""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Any

import structlog

log = structlog.get_logger(__name__)


def _validated_cidrs(raw: list[Any]) -> list[str]:
    """Filter ``raw`` to syntactically valid, canonicalised CIDR strings.

    Issue #236 — reject anything that doesn't round-trip through
    ``ipaddress.ip_network`` (strict=False) so an injected entry like
    ``1.2.3.4 }, drop; ... #`` can't slip arbitrary nft into the rule.
    """
    out: list[str] = []
    for c in raw:
        if not isinstance(c, str):
            log.warning("firewall.invalid_cidr_type", value=c)
            continue
        s = c.strip()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except (ValueError, TypeError) as exc:
            log.warning("firewall.invalid_cidr", value=s, error=str(exc))
            continue
        out.append(str(net))
    return out


def _split_families(cidrs: list[Any]) -> tuple[list[str], list[str]]:
    """Validate ``cidrs`` and split into (v4, v6) deduped + sorted lists."""
    v4: set[str] = set()
    v6: set[str] = set()
    for c in _validated_cidrs(cidrs):
        if ipaddress.ip_network(c, strict=False).version == 6:
            v6.add(c)
        else:
            v4.add(c)
    return sorted(v4), sorted(v6)


# Per-role service ports — must match firewall_renderer._ROLE_PORTS_*.
_ROLE_PORTS_TCP: dict[str, list[int]] = {
    "dns-bind9": [53],
    "dns-powerdns": [53],
    "dns-technitium": [53],
}
_ROLE_PORTS_UDP: dict[str, list[int]] = {
    "dns-bind9": [53],
    "dns-powerdns": [53],
    "dns-technitium": [53],
    "dhcp": [67, 68, 547],  # 547: DHCPv6 (#1139)
}
_K3S_ETCD_KUBELET_TCP: tuple[int, ...] = (2379, 2380, 10250)
_K3S_APISERVER_TCP = 6443
# #993 — the kubelet, from inside the cluster as well as from peers. See the
# long note on the same constant in the supervisor's ``firewall_renderer``;
# this renderer must stay byte-identical to it.
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
    if v4:
        lines.append(f'ip saddr {{ {", ".join(v4)} }} {rule_suffix} comment "{comment}-v4"')
    if v6:
        lines.append(f'ip6 saddr {{ {", ".join(v6)} }} {rule_suffix} comment "{comment}-v6"')


def compile_firewall_body(
    role_assignment: dict[str, Any] | None,
    cluster_peer_cidrs: list[Any] | None = None,
    *,
    pod_cidrs: list[Any] | None = None,
    service_cidrs: list[Any] | None = None,
    cp_member_count: int = 1,
    vip_configured: bool = False,
    web_ui_allowed_cidrs: list[Any] | None = None,
    ssh_scope_cidrs: list[Any] | None = None,
) -> str:
    """Byte-identical port of ``firewall_renderer.render_drop_in`` — returns
    just the drop-in body string (the supervisor wraps it in a
    FirewallProfile; the control plane only needs the body + its hash)."""
    role_assignment = role_assignment or {}
    roles = [r for r in (role_assignment.get("roles") or []) if isinstance(r, str)]
    firewall_extra = role_assignment.get("firewall_extra") or ""
    kubeapi_cidrs = role_assignment.get("kubeapi_expose_cidrs") or []

    profile = _profile_name(roles)
    peer_v4, peer_v6 = _split_families(cluster_peer_cidrs or [])
    is_cp = bool(peer_v4 or peer_v6) or bool(pod_cidrs) or bool(service_cidrs)

    lines: list[str] = []
    lines.append(
        "# Auto-generated by spatium-supervisor — do not hand-edit. "
        "See /etc/spatiumddi/firewall-extra on the host (or the fleet UI)"
    )
    lines.append("# for the operator-override surface that lands at the end of this file.")
    lines.append(f"# profile: {profile}")
    lines.append(f"# roles: {','.join(roles) if roles else '(idle)'}")
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
    # opens 80/443, so this drop-in is authoritative). SSH/22 above is the
    # escape hatch that keeps a bad Web-UI scope recoverable — open by
    # default, and only scoped when the operator turns on ``ssh_lockdown``
    # (#1009), which is a separate, deliberate act with its own guards.
    if web_ui_allowed_cidrs:
        web_v4, web_v6 = _split_families(list(web_ui_allowed_cidrs))
        _emit_family_rule(lines, web_v4, web_v6, "tcp dport { 80, 443 } accept", "web-ui")
    else:
        lines.append('tcp dport { 80, 443 } accept comment "web-ui"')

    role_tcp: set[int] = set()
    role_udp: set[int] = set()
    for role in roles:
        role_tcp.update(_ROLE_PORTS_TCP.get(role, []))
        role_udp.update(_ROLE_PORTS_UDP.get(role, []))
    # Issue #50 — operator-chosen DoT / DoH ports ride the role assignment
    # rather than the static table above. Keep this block byte-identical to
    # ``firewall_renderer.render_drop_in``.
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

    if is_cp:
        lines.append("")
        lines.append("# ── Control-plane derived (peer-scoped, #272/#285) ─────")
        if peer_v4 or peer_v6:
            etcd_kubelet = "{ " + ", ".join(str(p) for p in _K3S_ETCD_KUBELET_TCP) + " }"
            _emit_family_rule(
                lines, peer_v4, peer_v6, f"tcp dport {etcd_kubelet} accept", "k3s-peer"
            )
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
        kubelet_v4, kubelet_v6 = _split_families(list(pod_cidrs or []) + list(service_cidrs or []))
        if kubelet_v4 or kubelet_v6:
            _emit_family_rule(
                lines,
                kubelet_v4,
                kubelet_v6,
                f"tcp dport {_K3S_KUBELET_TCP} accept",
                "kubelet",
            )
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

    if firewall_extra.strip():
        lines.append("")
        lines.append("# ── Operator override (firewall_extra) ─────────────────")
        lines.append(firewall_extra.rstrip("\n"))

    return "\n".join(lines) + "\n"


async def firewall_bundle(
    db: Any,
    *,
    role_assignment: dict[str, Any],
    cluster_peer_cidrs: list[Any],
    pod_cidrs: list[Any],
    service_cidrs: list[Any],
    cp_member_count: int,
    vip_configured: bool,
    firewall_enabled: bool,
    appliance_id: Any = None,
    web_ui_allowed_cidrs: list[Any] | None = None,
    ssh_scope_cidrs: list[Any] | None = None,
    firewall_logging_enabled: bool = False,
) -> dict[str, Any]:
    """The ``firewall_settings`` block shipped on the supervisor heartbeat.

    Disabled-shape (empty ``config_hash``) when ``firewall_enabled`` is off
    — the supervisor reads the empty hash as "no server authority" and
    keeps its in-pod fallback render. Same key shape as ``snmp_bundle``.
    The disabled path short-circuits BEFORE any DB read.

    #285 Phase 3b — the body is now compiled from the declarative policy
    model (``compile_firewall_from_policies``), which SUBSUMES the frozen
    ``compile_firewall_body`` byte-for-byte when fed the seeded builtins.
    On an unseeded DB the merge renders from the in-code builtins, so the
    output is identical either way.
    """
    if not firewall_enabled:
        return {"enabled": False, "config_hash": "", "firewall_conf": ""}
    # Lazy import — firewall_merge imports the shared helpers from THIS module
    # at load, so importing it at module scope here would be a cycle.
    from app.services.appliance.firewall_merge import (
        compile_firewall_from_policies,
        load_appliance_policy,
        load_policy_set,
    )

    policy_set = await load_policy_set(db)
    appliance_policy = await load_appliance_policy(db, appliance_id)
    body = compile_firewall_from_policies(
        role_assignment,
        cluster_peer_cidrs,
        pod_cidrs=pod_cidrs,
        service_cidrs=service_cidrs,
        cp_member_count=cp_member_count,
        vip_configured=vip_configured,
        policy_set=policy_set,
        appliance_policy=appliance_policy,
        web_ui_allowed_cidrs=web_ui_allowed_cidrs,
        ssh_scope_cidrs=ssh_scope_cidrs,
    )
    if firewall_logging_enabled:
        # #404 — a rate-limited catch-all log just before the chain's
        # policy drop. The drop-in's accept rules terminate first; anything
        # falling through gets logged (≤10/s so a scan can't flood dmesg)
        # then hits the base chain's `policy drop`. The supervisor tails
        # /dev/kmsg for this prefix → Firewall → Logs viewer.
        body = body.rstrip("\n") + "\n" + _FIREWALL_LOG_RULE + "\n"
    return {
        "enabled": True,
        "config_hash": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "firewall_conf": body,
    }


# nft rule appended to the rendered drop-in when firewall logging is on. No
# verdict → it logs + continues, so the base chain's `policy drop` still drops.
_FIREWALL_LOG_RULE = (
    "limit rate 10/second burst 20 packets "
    'log prefix "spatium-fw: " level info '
    'comment "spatiumddi dropped-packet log (#404)"'
)


__all__ = ["compile_firewall_body", "firewall_bundle"]
