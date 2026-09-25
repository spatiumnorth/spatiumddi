"""Server-side firewall render (#285 Phase 2a + 3b) — render-identity tests.

The load-bearing contract is the THREE-WAY identity across an input matrix:

    render_drop_in (supervisor in-pod)
      == compile_firewall_body (frozen 2a port)
      == compile_firewall_from_policies (3b merge, fed the seeded builtins)

A one-byte divergence re-fires every node's host trigger on the
firewall_enabled flip (the merge runs when enabled; the in-pod renderer when
not). The pure-function legs run on the host venv; the supervisor leg loads
the in-pod renderer standalone via importlib and skips if it isn't on disk.
The async ``firewall_bundle`` legs use the empty-DB builtin fallback so they
need no seeding.
"""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import sys

import pytest

from app.services.appliance.firewall import compile_firewall_body, firewall_bundle
from app.services.appliance.firewall_merge import (
    builtin_policy_set,
    compile_firewall_from_policies,
    reset_policy_cache,
)

# The full input matrix the identity + smoke tests exercise.
_MATRIX: list[dict] = [
    {"role_assignment": {"roles": []}},  # idle
    {"role_assignment": {"roles": ["dns-bind9"]}},
    {"role_assignment": {"roles": ["dhcp"]}},
    {"role_assignment": {"roles": ["dns-powerdns", "dhcp"]}},
    # #1166 — looking-glass (tcp/179) existed in the supervisor renderer only.
    {"role_assignment": {"roles": ["looking-glass"]}},
    {"role_assignment": {"roles": ["dns-bind9", "dhcp", "looking-glass"]}},
    # #1167 — the Kea HA listener, scoped to the pair (dual-stack) …
    {
        "role_assignment": {
            "roles": ["dhcp"],
            "dhcp_ha_port": 8000,
            "dhcp_ha_peer_cidrs": ["192.168.0.12/32", "2001:db8::12/128", "192.168.0.13/32"],
        }
    },
    # … never on a node without the dhcp role, and never from a junk peer.
    {
        "role_assignment": {
            "roles": ["dns-bind9"],
            "dhcp_ha_port": 8000,
            "dhcp_ha_peer_cidrs": ["192.168.0.12/32"],
        }
    },
    {
        "role_assignment": {
            "roles": ["dhcp"],
            "dhcp_ha_port": 8000,
            "dhcp_ha_peer_cidrs": ["1.2.3.4 }, drop; tcp dport 22 accept; #"],
        }
    },
    # single-node CP: pod/service CIDR, no peers
    {
        "role_assignment": {"roles": []},
        "pod_cidrs": ["10.42.0.0/16"],
        "service_cidrs": ["10.43.0.0/16"],
    },
    # multi-node CP + VIP: peers, pod, svc, memberlist
    {
        "role_assignment": {"roles": ["dns-bind9"], "kubeapi_expose_cidrs": ["10.9.0.0/24"]},
        "cluster_peer_cidrs": ["192.168.0.133/32", "192.168.0.125/32"],
        "pod_cidrs": ["10.42.0.0/16"],
        "service_cidrs": ["10.43.0.0/16"],
        "cp_member_count": 3,
        "vip_configured": True,
    },
    # dual-stack peers
    {
        "role_assignment": {"roles": []},
        "cluster_peer_cidrs": ["192.168.0.10", "2001:db8::10", "2001:db8::11/128"],
        "pod_cidrs": ["10.42.0.0/16", "2001:cafe:42::/56"],
        "cp_member_count": 2,
    },
    # operator firewall_extra
    {"role_assignment": {"roles": ["dhcp"], "firewall_extra": 'udp dport 161 accept comment "x"'}},
    # Trap 1: junk pod CIDR — is_cp via RAW non-empty, but no valid union.
    {"role_assignment": {"roles": []}, "pod_cidrs": ["not-a-cidr"]},
    # multi-node but NO vip → memberlist guard fails (header + peer/api only)
    {
        "role_assignment": {"roles": []},
        "cluster_peer_cidrs": ["192.168.0.5/32"],
        "cp_member_count": 3,
        "vip_configured": False,
    },
    # #285 Phase 6 — Web-UI source-scoped (v4 only)
    {"role_assignment": {"roles": []}, "web_ui_allowed_cidrs": ["192.168.0.0/24", "10.0.0.0/8"]},
    # #285 Phase 6 — Web-UI source-scoped (dual-stack) on a DNS node
    {
        "role_assignment": {"roles": ["dns-bind9"]},
        "web_ui_allowed_cidrs": ["192.168.0.0/24", "2001:db8:f00d::/64"],
    },
]


@pytest.fixture(autouse=True)
def _reset_fw_cache():
    reset_policy_cache()
    yield
    reset_policy_cache()


def _call(fn, case: dict):
    return fn(
        case["role_assignment"],
        case.get("cluster_peer_cidrs"),
        pod_cidrs=case.get("pod_cidrs"),
        service_cidrs=case.get("service_cidrs"),
        cp_member_count=case.get("cp_member_count", 1),
        vip_configured=case.get("vip_configured", False),
        web_ui_allowed_cidrs=case.get("web_ui_allowed_cidrs"),
        ssh_scope_cidrs=case.get("ssh_scope_cidrs"),
    )


def _call_merge(case: dict) -> str:
    return compile_firewall_from_policies(
        case["role_assignment"],
        case.get("cluster_peer_cidrs"),
        pod_cidrs=case.get("pod_cidrs"),
        service_cidrs=case.get("service_cidrs"),
        cp_member_count=case.get("cp_member_count", 1),
        vip_configured=case.get("vip_configured", False),
        policy_set=builtin_policy_set(),
        web_ui_allowed_cidrs=case.get("web_ui_allowed_cidrs"),
        ssh_scope_cidrs=case.get("ssh_scope_cidrs"),
    )


def _load_supervisor_renderer():
    path = (
        pathlib.Path(__file__).resolve().parents[2]
        / "agent/supervisor/spatium_supervisor/firewall_renderer.py"
    )
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location("_sup_firewall_renderer", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # The renderer defines a @dataclass; dataclasses resolves the class's
    # module via sys.modules, so register it before exec_module.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_merge_subsumes_legacy_renderer() -> None:
    # The 3b merge fed the seeded builtins reproduces the frozen 2a renderer
    # BYTE-FOR-BYTE across the matrix (the half of the triangle that lives in
    # this repo without the supervisor file on disk).
    for case in _MATRIX:
        legacy = _call(compile_firewall_body, case)
        merged = _call_merge(case)
        assert (
            merged == legacy
        ), f"merge drift for {case!r}\n--legacy--\n{legacy}\n--merge--\n{merged}"


def test_byte_identical_with_supervisor_renderer() -> None:
    sup = _load_supervisor_renderer()
    if sup is None:
        pytest.skip("supervisor firewall_renderer not on disk (backend-only checkout)")
    for case in _MATRIX:
        backend_body = _call(compile_firewall_body, case)
        supervisor_body = _call(sup.render_drop_in, case).body
        assert backend_body == supervisor_body, f"render drift for {case!r}"
        # Close the triangle: supervisor == merge too.
        assert _call_merge(case) == supervisor_body, f"merge≠supervisor for {case!r}"


def test_no_dataplane_rule_any_renderer() -> None:
    # No renderer may emit a flannel/wireguard INPUT rule (#285 — VXLAN
    # bypasses our chain). Guards against a one-sided data-plane-floor add.
    sup = _load_supervisor_renderer()
    for case in _MATRIX:
        for body in (_call(compile_firewall_body, case), _call_merge(case)):
            assert "8472" not in body and "51820" not in body and "dataplane" not in body
        if sup is not None:
            assert "8472" not in _call(sup.render_drop_in, case).body


async def test_bundle_disabled_shape() -> None:
    # Disabled path short-circuits before any DB read → db can be None.
    b = await firewall_bundle(
        None,
        role_assignment={"roles": []},
        cluster_peer_cidrs=[],
        pod_cidrs=[],
        service_cidrs=[],
        cp_member_count=1,
        vip_configured=False,
        firewall_enabled=False,
    )
    assert b == {"enabled": False, "config_hash": "", "firewall_conf": ""}


async def test_bundle_enabled_shape(db_session) -> None:
    # Empty DB → builtin fallback → byte-identical to the legacy render.
    b = await firewall_bundle(
        db_session,
        role_assignment={"roles": ["dns-bind9"]},
        cluster_peer_cidrs=[],
        pod_cidrs=[],
        service_cidrs=[],
        cp_member_count=1,
        vip_configured=False,
        firewall_enabled=True,
    )
    assert b["enabled"] is True
    assert b["firewall_conf"].startswith("# Auto-generated by spatium-supervisor")
    assert "tcp dport 53 accept" in b["firewall_conf"]
    assert b["config_hash"] == hashlib.sha256(b["firewall_conf"].encode()).hexdigest()
    legacy = compile_firewall_body({"roles": ["dns-bind9"]}, [])
    assert b["firewall_conf"] == legacy


async def test_bundle_multinode_retire_directive(db_session) -> None:
    single = await firewall_bundle(
        db_session,
        role_assignment={"roles": []},
        cluster_peer_cidrs=[],
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=[],
        cp_member_count=1,
        vip_configured=False,
        firewall_enabled=True,
    )
    multi = await firewall_bundle(
        db_session,
        role_assignment={"roles": []},
        cluster_peer_cidrs=["192.168.0.2/32"],
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=[],
        cp_member_count=3,
        vip_configured=False,
        firewall_enabled=True,
    )
    assert "# spatium-bootstrap: keep" in single["firewall_conf"]
    assert "# spatium-bootstrap: retire" in multi["firewall_conf"]


def test_web_ui_default_open_all_renderers() -> None:
    # #285 Phase 6 — with no scope set, EVERY renderer must emit the un-scoped
    # `tcp dport { 80, 443 } accept` (the base /etc/nftables.conf no longer
    # opens it, so the default-open behaviour now lives in the drop-in). This
    # is the anti-lockout floor for a fresh install.
    sup = _load_supervisor_renderer()
    case = {"role_assignment": {"roles": []}}
    expect = 'tcp dport { 80, 443 } accept comment "web-ui"'
    bodies = [_call(compile_firewall_body, case), _call_merge(case)]
    if sup is not None:
        bodies.append(_call(sup.render_drop_in, case).body)
    for body in bodies:
        assert expect in body
        assert "ip saddr" not in body.split('comment "web-ui"')[0].rsplit("\n", 1)[-1]


def test_web_ui_scoped_drops_open_accept() -> None:
    # When scoped, the un-scoped open accept must be GONE (replaced by a
    # source-matched accept); policy-drop then denies everything else.
    case = {
        "role_assignment": {"roles": []},
        "web_ui_allowed_cidrs": ["192.168.0.0/24", "2001:db8:f00d::/64"],
    }
    for body in (_call(compile_firewall_body, case), _call_merge(case)):
        assert 'tcp dport { 80, 443 } accept comment "web-ui"' not in body
        assert (
            'ip saddr { 192.168.0.0/24 } tcp dport { 80, 443 } accept comment "web-ui-v4"' in body
        )
        assert (
            'ip6 saddr { 2001:db8:f00d::/64 } tcp dport { 80, 443 } accept comment "web-ui-v6"'
            in body
        )


# ── Web-UI bootstrap sentinel directive (#769) ───────────────────────


def test_webui_sentinel_directive_all_renderers() -> None:
    """The ``# spatium-webui:`` host-runner directive, in every renderer.

    The baked ``00-spatium-webui.nft`` opens 80/443 from first boot so the
    "still initialising" page (#767) is reachable before the supervisor
    has ever heartbeated — measured on a clean install, the port otherwise
    opened 41 s AFTER the api was already serving, so the page was
    unreachable for the entire window it exists for.

    Retire it exactly when a scope is configured: the sentinel's
    unconditional accept sorts EARLIER in the ``/etc/nftables.d/*.nft``
    include glob, and nftables accepts on first match, so leaving it in
    place would silently defeat the operator's ``web_ui_allowed_cidrs``.
    """
    sup = _load_supervisor_renderer()

    unscoped = {"role_assignment": {"roles": []}}
    scoped = {
        "role_assignment": {"roles": []},
        "web_ui_allowed_cidrs": ["192.168.0.0/24"],
    }

    for case, expected in ((unscoped, "keep"), (scoped, "retire")):
        other = "retire" if expected == "keep" else "keep"
        bodies = [_call(compile_firewall_body, case), _call_merge(case)]
        if sup is not None:
            bodies.append(_call(sup.render_drop_in, case).body)
        for body in bodies:
            assert f"# spatium-webui: {expected}" in body
            assert f"# spatium-webui: {other}" not in body


def test_ssh_sentinel_directive_all_renderers() -> None:
    """The ``# spatium-ssh:`` host-runner directive, in every renderer (#1009).

    The baked ``00-spatium-ssh.nft`` opens port 22 from first boot — the
    management escape hatch ``docs/design/FLEET_FIREWALL.md`` §6.1 calls the
    irreducible recovery channel. It sorts EARLIER in the include glob than
    the scoped rule ``spatiumddi-ssh-reload`` renders, and nftables accepts on
    first match, so the operator's allowlist was dead code behind it.

    Retire it exactly when lockdown is on — which is what a non-empty
    ``ssh_scope_cidrs`` means, since ``effective_ssh_scope`` resolves the flag
    server-side. Keep is the default, so an install that never opts in renders
    byte-for-byte as before.
    """
    sup = _load_supervisor_renderer()

    off = {"role_assignment": {"roles": []}}
    on = {"role_assignment": {"roles": []}, "ssh_scope_cidrs": ["192.168.0.0/24"]}

    for case, expected in ((off, "keep"), (on, "retire")):
        other = "retire" if expected == "keep" else "keep"
        bodies = [_call(compile_firewall_body, case), _call_merge(case)]
        if sup is not None:
            bodies.append(_call(sup.render_drop_in, case).body)
        for body in bodies:
            assert f"# spatium-ssh: {expected}" in body
            assert f"# spatium-ssh: {other}" not in body


def test_ssh_management_line_is_scoped_under_lockdown_all_renderers() -> None:
    """Retiring the sentinel alone would not be enough.

    Every renderer also emits an SSH accept in ``spatium-role.nft``, which
    sorts AFTER ``50-spatium-ssh.nft`` in the glob — so a packet the scoped
    rule declined would fall straight through to it and the restriction would
    still do nothing. The two have to move together.
    """
    sup = _load_supervisor_renderer()
    case = {"role_assignment": {"roles": []}, "ssh_scope_cidrs": ["10.0.0.0/8"]}

    bodies = [_call(compile_firewall_body, case), _call_merge(case)]
    if sup is not None:
        bodies.append(_call(sup.render_drop_in, case).body)
    for body in bodies:
        ssh_rules = [
            ln for ln in body.splitlines() if "dport 22" in ln and not ln.strip().startswith("#")
        ]
        assert ssh_rules, "no SSH accept at all — the floor must not vanish"
        assert all("saddr" in ln for ln in ssh_rules), ssh_rules
        assert any("10.0.0.0/8" in ln for ln in ssh_rules), ssh_rules


def test_the_ssh_floor_is_unconditional_when_lockdown_is_off() -> None:
    """The default, and the reason nothing tightens on upgrade."""
    sup = _load_supervisor_renderer()
    case = {"role_assignment": {"roles": []}}

    bodies = [_call(compile_firewall_body, case), _call_merge(case)]
    if sup is not None:
        bodies.append(_call(sup.render_drop_in, case).body)
    for body in bodies:
        assert 'tcp dport 22 accept comment "ssh"' in body


def test_a_configured_allowlist_alone_does_not_retire_the_floor() -> None:
    """``ssh_scope_cidrs`` IS the resolved answer, not the typed list.

    ``effective_ssh_scope`` returns [] while lockdown is off, so an operator
    who configured an allowlist back when it was inert does not have their
    SSH tightened by an upgrade they never asked for. Asserted here at the
    renderer boundary because that is where a future caller could pass the
    raw column by mistake and change every appliance's posture silently.
    """
    from app.models.settings import PlatformSettings
    from app.services.appliance.ssh import effective_ssh_scope

    row = PlatformSettings(ssh_allowed_source_networks=["10.0.0.0/8"], ssh_lockdown=False)
    assert effective_ssh_scope(row) == []

    body = _call(
        compile_firewall_body,
        {
            "role_assignment": {"roles": []},
            "ssh_scope_cidrs": effective_ssh_scope(row),
        },
    )
    assert "# spatium-ssh: keep" in body
    assert 'tcp dport 22 accept comment "ssh"' in body


# ── #993 — kubelet 10250 reachable from inside the cluster ──────────────


_SINGLE_NODE_CP = {
    "role_assignment": {"roles": ["dns-bind9"]},
    "pod_cidrs": ["10.42.0.0/16"],
    "service_cidrs": ["10.43.0.0/16"],
}


def test_kubelet_is_open_to_the_pod_cidr_on_a_single_node() -> None:
    """The bug #990 shipped into, and the reason it shipped unnoticed.

    10250 was opened to ``cluster_peer_cidrs`` only — an EMPTY set on a
    single node, so the rule was not emitted at all. An api pod reading its
    own node's kubelet enters via cni0 with a pod-CIDR source and traverses
    INPUT like any LAN packet, so the direct transport could never connect
    on the deployment shape every appliance starts as.
    """
    body = compile_firewall_body(**_SINGLE_NODE_CP)
    assert "ip saddr { 10.42.0.0/16, 10.43.0.0/16 } tcp dport 10250 accept" in body
    assert 'comment "kubelet-v4"' in body
    # …and the peer rule is genuinely absent here, which is what made the
    # port unreachable rather than merely narrowly scoped.
    assert "k3s-peer" not in body


def test_kubelet_does_not_inherit_the_kubeapi_expose_allowlist() -> None:
    """``kubeapi_expose_cidrs`` widens 6443 so an operator can run kubectl
    from the LAN. The apiserver guards every request with RBAC; the kubelet
    API serves /exec, /run and /attach. Extending one to the other would be
    a privilege escalation nobody asked for, so the two rules resolve
    different source sets — asserted, because they are one copy-paste apart.
    """
    body = compile_firewall_body(
        role_assignment={"roles": [], "kubeapi_expose_cidrs": ["10.9.0.0/24"]},
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=["10.43.0.0/16"],
    )
    kubelet = next(ln for ln in body.splitlines() if "kubelet-v4" in ln)
    kubeapi = next(ln for ln in body.splitlines() if "kubeapi-v4" in ln)
    assert "10.9.0.0/24" not in kubelet
    assert "10.9.0.0/24" in kubeapi


def test_kubelet_rule_is_family_split() -> None:
    """A v6 pod CIDR in a v4 nft set is the v6-lockout bug the whole
    _split_families discipline exists for."""
    body = compile_firewall_body(
        role_assignment={"roles": []},
        pod_cidrs=["10.42.0.0/16", "2001:cafe:42::/56"],
    )
    v4 = next(ln for ln in body.splitlines() if "kubelet-v4" in ln)
    v6 = next(ln for ln in body.splitlines() if "kubelet-v6" in ln)
    assert "2001:cafe:42::/56" not in v4
    assert "10.42.0.0/16" not in v6


def test_no_kubelet_rule_without_an_in_cluster_source() -> None:
    """A node with neither pod nor service CIDR is not running a kubelet we
    can reach in-cluster; emitting an empty nft set there is a syntax error,
    not an open port."""
    body = compile_firewall_body(role_assignment={"roles": ["dns-bind9"]})
    assert "kubelet" not in body
