"""Tests for the supervisor nftables drop-in renderer.

Covers #272 Phase 7b + #285 Phase 1 — the renderer emits the full
authoritative scoped rule set: a data-plane floor (flannel/wireguard),
per-role service ports, peer-scoped etcd/kubelet (NEVER LAN-wide),
6443 widened to peers ∪ pod ∪ service ∪ kubeapi_expose, and MetalLB
memberlist gated on a multi-node + VIP cluster — all family-split
(``ip saddr`` v4 / ``ip6 saddr`` v6).

These rules are ADDITIVE on the current baked base conf; they only
become authoritative once #285 Phase 1b removes the LAN-wide base accept.
"""

from __future__ import annotations

from spatium_supervisor.firewall_renderer import render_drop_in

_PEERS_V4 = ["192.168.0.133", "192.168.0.125/32"]


# ── Management floor (always) ────────────────────────────────────────


def test_idle_renders_management_floor_only() -> None:
    p = render_drop_in({"roles": []})
    assert 'tcp dport 22 accept comment "ssh"' in p.body
    assert "icmp type echo-request accept" in p.body
    assert "icmpv6 type echo-request accept" in p.body
    assert "iif lo accept" in p.body
    # No CP / data-plane / role rules.
    assert "k3s-peer" not in p.body
    assert "kubeapi" not in p.body
    assert "dataplane" not in p.body
    assert "role:" not in p.body


# ── Per-role service ports ───────────────────────────────────────────


def test_role_ports() -> None:
    p = render_drop_in({"roles": ["dns-bind9", "dhcp"]})
    assert 'tcp dport 53 accept comment "role:dns-and-dhcp"' in p.body
    assert 'udp dport 53 accept comment "role:dns-and-dhcp"' in p.body
    assert "udp dport 67 accept" in p.body
    assert "udp dport 68 accept" in p.body
    # DHCPv6 (#1139): relayed Relay-Forward and on-link Solicit both land on 547.
    assert "udp dport 547 accept" in p.body
    assert 53 in p.expected_tcp_ports and 67 in p.expected_udp_ports
    assert 547 in p.expected_udp_ports



def test_kea_ha_listener_opens_to_the_pair_only() -> None:
    """#1167 — the HA hook's listener, scoped to the other Kea members."""
    p = render_drop_in(
        {
            "roles": ["dhcp"],
            "dhcp_ha_port": 8000,
            "dhcp_ha_peer_cidrs": ["192.168.0.12/32", "2001:db8::12/128"],
        }
    )
    assert 'ip saddr { 192.168.0.12/32 } tcp dport 8000 accept comment "role:dhcp-ha-v4"' in p.body
    assert 'ip6 saddr { 2001:db8::12/128 } tcp dport 8000 accept comment "role:dhcp-ha-v6"' in p.body
    # Every line opening the port is source-scoped — never ``any``.
    assert all("saddr" in line for line in p.body.splitlines() if "dport 8000" in line)
    assert 8000 in p.expected_tcp_ports
    # A stale value on a node without the dhcp role opens nothing.
    q = render_drop_in({"roles": [], "dhcp_ha_port": 8000, "dhcp_ha_peer_cidrs": ["10.0.0.1/32"]})
    assert "8000" not in q.body


# ── Control-plane peer scoping (the #285 hardening) ──────────────────


def test_peers_scope_etcd_kubelet_not_lanwide() -> None:
    p = render_drop_in({"roles": []}, _PEERS_V4)
    # etcd + kubelet bundled into ONE peer-scoped rule, never bare.
    assert (
        "ip saddr { 192.168.0.125/32, 192.168.0.133/32 } tcp dport { 2379, 2380, 10250 } accept"
        in (p.body)
    )
    # Crucially: no UNSCOPED accept for the sensitive ports.
    assert "tcp dport 2379 accept comment" not in p.body
    assert 'tcp dport { 2379, 2380, 10250 } accept comment "k3s-peer-v4"' in p.body
    for port in (2379, 2380, 10250, 6443):
        assert port in p.expected_tcp_ports


def test_6443_widens_to_peers_pod_service_kubeapi() -> None:
    p = render_drop_in(
        {"roles": [], "kubeapi_expose_cidrs": ["10.9.0.0/24"]},
        _PEERS_V4,
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=["10.43.0.0/16"],
    )
    # All four sources land in the 6443 saddr set, sorted + deduped.
    line = next(ln for ln in p.body.splitlines() if "kubeapi-v4" in ln and "dport 6443" in ln)
    for cidr in ("10.42.0.0/16", "10.43.0.0/16", "10.9.0.0/24", "192.168.0.133/32"):
        assert cidr in line


def test_single_node_cp_opens_6443_to_pod_only_no_etcd() -> None:
    # No peers (single-node), but it runs the apiserver → 6443 to pod/svc,
    # and NO etcd/kubelet rule (single-node etcd is loopback).
    p = render_drop_in(
        {"roles": []}, [], pod_cidrs=["10.42.0.0/16"], service_cidrs=["10.43.0.0/16"]
    )
    assert "dport 6443 accept" in p.body
    assert "10.42.0.0/16" in p.body
    assert "k3s-peer" not in p.body  # no etcd/kubelet without peers


# ── No data-plane floor (VXLAN bypasses our INPUT on k3s+flannel) ────


def test_no_dataplane_floor_emitted() -> None:
    # The renderer never emits a flannel/wireguard data-plane rule — that
    # inter-node traffic doesn't traverse the host INPUT chain (#285,
    # field-verified). No 8472 / 51820, ever.
    p = render_drop_in({"roles": []}, _PEERS_V4, pod_cidrs=["10.42.0.0/16"])
    assert "8472" not in p.body and "dataplane" not in p.body
    assert 8472 not in p.expected_udp_ports


# ── Bootstrap sentinel retire/keep directive (6443 tighten, #285 1b) ─


def test_bootstrap_directive_keep_single_node() -> None:
    # Single-node (cp_member_count default 1) → keep the LAN-wide 6443
    # bootstrap sentinel.
    p = render_drop_in({"roles": []}, [], pod_cidrs=["10.42.0.0/16"])
    assert "# spatium-bootstrap: keep" in p.body
    assert "# spatium-bootstrap: retire" not in p.body


def test_bootstrap_directive_retire_multinode() -> None:
    # Settled multi-node CP (>= 2) → retire the sentinel; 6443 is then
    # only the scoped kubeapi rule.
    p = render_drop_in({"roles": []}, _PEERS_V4, pod_cidrs=["10.42.0.0/16"], cp_member_count=3)
    assert "# spatium-bootstrap: retire" in p.body
    assert "# spatium-bootstrap: keep" not in p.body


# ── IPv6 family split (the v6 lockout fix) ───────────────────────────


def test_v6_peers_use_ip6_saddr_and_128() -> None:
    p = render_drop_in(
        {"roles": []},
        ["192.168.0.10", "2001:db8::10", "2001:db8::11/128"],
        pod_cidrs=["10.42.0.0/16", "2001:cafe:42::/56"],
    )
    # v6 peers render as ip6 saddr with /128, never folded into a v4 set.
    assert "ip6 saddr { 2001:db8::10/128, 2001:db8::11/128 } tcp dport { 2379, 2380, 10250 }" in (
        p.body
    )
    assert "ip saddr { 192.168.0.10/32 } tcp dport { 2379, 2380, 10250 }" in p.body
    # v6 pod CIDR lands in the v6 6443 set.
    assert "2001:cafe:42::/56" in next(ln for ln in p.body.splitlines() if "kubeapi-v6" in ln)


# ── MetalLB memberlist gating ────────────────────────────────────────


def test_memberlist_only_when_multinode_and_vip() -> None:
    # Single member or no VIP → no memberlist.
    assert (
        "memberlist"
        not in render_drop_in({"roles": []}, _PEERS_V4, cp_member_count=1, vip_configured=True).body
    )
    assert (
        "memberlist"
        not in render_drop_in(
            {"roles": []}, _PEERS_V4, cp_member_count=3, vip_configured=False
        ).body
    )
    # Multi-node + VIP → memberlist 7946 tcp AND udp, peer-scoped.
    p = render_drop_in({"roles": []}, _PEERS_V4, cp_member_count=3, vip_configured=True)
    assert "tcp dport 7946 accept" in p.body
    assert "udp dport 7946 accept" in p.body
    assert 7946 in p.expected_tcp_ports and 7946 in p.expected_udp_ports


# ── Injection safety + operator override ─────────────────────────────


def test_injection_rejected() -> None:
    p = render_drop_in({"roles": []}, ["1.2.3.4 }, drop; tcp dport 22 accept; #"])
    assert "drop;" not in p.body
    assert "k3s-peer" not in p.body  # the only "peer" was the injection attempt


def test_firewall_extra_appended_last() -> None:
    p = render_drop_in({"roles": ["dhcp"], "firewall_extra": 'udp dport 161 accept comment "snmp"'})
    assert p.body.rstrip().endswith('udp dport 161 accept comment "snmp"')


def test_deterministic() -> None:
    kw = dict(
        pod_cidrs=["10.42.0.0/16"],
        cp_member_count=3,
        vip_configured=True,
    )
    assert (
        render_drop_in({"roles": ["dns-bind9"]}, _PEERS_V4, **kw).body
        == render_drop_in({"roles": ["dns-bind9"]}, _PEERS_V4, **kw).body
    )


# ── Web-UI sentinel retire/keep directive (#769) ─────────────────────
#
# The baked 00-spatium-webui.nft opens 80/443 from first boot, before the
# supervisor has ever heartbeated — without it the Web UI port stays
# filtered for the whole cold-boot window and the "still initialising"
# page (#767) is unreachable exactly when it is wanted. It has to be
# retired once a source scope is configured: an unconditional accept in a
# 00- file sorts EARLIER in the include glob than the scoped rule here,
# and nftables accepts on first match, so leaving it would silently
# defeat the operator's scope.


def test_webui_directive_keep_when_unscoped() -> None:
    p = render_drop_in({"roles": []}, [])
    assert "# spatium-webui: keep" in p.body
    assert "# spatium-webui: retire" not in p.body
    # ...and the drop-in's own rule is the open one.
    assert 'tcp dport { 80, 443 } accept comment "web-ui"' in p.body


def test_webui_directive_retire_when_scoped() -> None:
    p = render_drop_in({"roles": []}, [], web_ui_allowed_cidrs=["192.168.0.0/24"])
    assert "# spatium-webui: retire" in p.body
    assert "# spatium-webui: keep" not in p.body
    # The scoped rule must be the only path to 80/443 in this body.
    assert 'tcp dport { 80, 443 } accept comment "web-ui"' not in p.body
    assert "192.168.0.0/24" in p.body


# ── #993 — kubelet 10250 reachable from inside the cluster ──────────────


def test_kubelet_open_to_pod_and_service_cidrs_on_a_single_node() -> None:
    """#990's direct cluster-health transport could never connect.

    10250 was opened to ``cluster_peer_cidrs`` only, which is EMPTY on a
    single node — so the rule was not emitted at all and the chain's
    ``policy drop`` took the packet. An api pod reading its own node's
    kubelet enters via cni0 with a pod-CIDR source and traverses INPUT like
    any LAN packet, which is why 6443 (widened to pod ∪ svc) worked from the
    same pod at the same moment.
    """
    p = render_drop_in(
        {"roles": ["dns-bind9"]},
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=["10.43.0.0/16"],
    )
    assert (
        'ip saddr { 10.42.0.0/16, 10.43.0.0/16 } tcp dport 10250 accept comment "kubelet-v4"'
    ) in p.body
    # The peer rule really is absent on this shape — narrow scoping was not
    # the problem, no rule at all was.
    assert "k3s-peer" not in p.body


def test_kubelet_port_is_expected_so_drift_re_applies() -> None:
    """The supervisor re-applies the ruleset when an expected port is missing
    from the live chain (an operator's ``nft flush``, a failed
    ``nft -f``). A port absent from this set is one that never comes back.
    """
    p = render_drop_in(
        {"roles": []},
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=["10.43.0.0/16"],
    )
    assert 10250 in p.expected_tcp_ports


def test_kubelet_excludes_the_operator_kubeapi_allowlist() -> None:
    """``kubeapi_expose_cidrs`` says "let me reach the apiserver from the
    LAN", and the apiserver guards every request with RBAC. The kubelet API
    serves /exec, /run and /attach. The two rules are one copy-paste apart,
    so assert they resolve different sources."""
    p = render_drop_in(
        {"roles": [], "kubeapi_expose_cidrs": ["10.9.0.0/24"]},
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=["10.43.0.0/16"],
    )
    kubelet = next(ln for ln in p.body.splitlines() if "kubelet-v4" in ln)
    kubeapi = next(ln for ln in p.body.splitlines() if "kubeapi-v4" in ln)
    assert "10.9.0.0/24" not in kubelet
    assert "10.9.0.0/24" in kubeapi


def test_ha_reaches_both_peer_and_own_node_kubelets() -> None:
    """On HA the peer rule covers OTHER nodes' kubelets and this one covers
    the api pod's own node — the case that stays broken if you read the peer
    rule as already handling 10250."""
    p = render_drop_in(
        {"roles": []},
        cluster_peer_cidrs=_PEERS_V4,
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=["10.43.0.0/16"],
        cp_member_count=3,
    )
    assert 'tcp dport { 2379, 2380, 10250 } accept comment "k3s-peer-v4"' in p.body
    assert 'ip saddr { 10.42.0.0/16, 10.43.0.0/16 } tcp dport 10250 accept' in p.body


def test_no_kubelet_rule_without_an_in_cluster_source() -> None:
    """An empty nft set is a syntax error that fails the whole ruleset, not
    a closed port — so a non-CP node must emit no rule at all."""
    p = render_drop_in({"roles": ["dns-bind9"]})
    assert "kubelet" not in p.body
    assert 10250 not in p.expected_tcp_ports


def test_kubelet_rule_is_family_split() -> None:
    """A v6 CIDR inside an ``ip saddr`` set is rejected by nft, which fails
    the drop-in whole — the v6-lockout shape _split_families exists for."""
    p = render_drop_in(
        {"roles": []},
        pod_cidrs=["10.42.0.0/16", "2001:cafe:42::/56"],
    )
    v4 = next(ln for ln in p.body.splitlines() if "kubelet-v4" in ln)
    v6 = next(ln for ln in p.body.splitlines() if "kubelet-v6" in ln)
    assert "2001:cafe:42::/56" not in v4
    assert "10.42.0.0/16" not in v6
