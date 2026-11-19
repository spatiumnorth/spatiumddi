"""The firewall must never partition a live etcd member (#593).

The per-role nftables drop-in was rendered purely from the control plane's row
(``cluster_role``). Observed live on a 3-node appliance: ddi2's row had gone
``cluster_role = NULL`` after a failed re-join, while ddi2 was still a voting
etcd member. The supervisor rendered an agent firewall with no ``k3s-peer``
rule, and ddi2's own nftables dropped its peers' inbound raft traffic — the
peers logged ``dial tcp 192.168.0.133:2380: i/o timeout`` every 5 s against a
member that was up the whole time.

The row bug is fixed (#591). The COUPLING is what these tests pin: any
row/reality divergence must not be able to close etcd's peer port on a node
that k3s still calls an etcd member.

Three defences, all covered here:
  1. recover a peer set from live membership when the row supplies none
  2. refuse to apply any body that would close 2380 on a live etcd member
  3. fall back WITHOUT the network when the probe can't run — the supervisor pod
     has no hostNetwork, so its kube reads go to the apiserver ClusterIP and may
     be routed to a REMOTE apiserver. A partitioned node cannot probe, so it
     falls back to a purely local cluster-member signal and then to a previously
     CONFIRMED membership on disk. Only ``True`` is ever remembered: a persisted
     ``False`` would be this bug on disk, since a node promoted while its
     apiserver is unreachable would read "not a member" and partition itself.

And the counter-properties, which matter just as much: a plain agent appliance
(or a node that has never successfully probed) must still get its firewall.
A guard that failed closed there would freeze the ruleset on every non-etcd box.

    python3 -m pytest agent/supervisor/tests/test_firewall_self_partition.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_supervisor import firewall_peer_audit as fpa

# Captured before the autouse fixture stubs it out, so the two tests that
# exercise the real local signal can still reach it.
_REAL_LOCAL_SIGNAL = fpa._local_cluster_member_signal

# A real agent-profile body: mgmt + role ports, NO k3s-peer rule. This is what
# got applied to ddi2 and partitioned it.
AGENT_BODY = """\
# ── Base management ────────────────────────────────────────
tcp dport 22 accept comment "mgmt-ssh"
tcp dport { 80, 443 } accept comment "web-ui"

# ── Per-role service ports ─────────────────────────────
udp dport 53 accept comment "role:dns-only"
tcp dport 53 accept comment "role:dns-only"
"""

CP_BODY = """\
tcp dport 22 accept comment "mgmt-ssh"
ip saddr { 192.168.0.199, 192.168.0.125 } tcp dport { 2379, 2380, 10250 } \
accept comment "k3s-peer"
ip saddr { 10.42.0.0/16 } tcp dport 6443 accept comment "k3s-api"
"""


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path: Path):
    """The membership marker is a process global and the last-known answer is a
    file on the host bind mount — both would leak across cases. The local
    cluster-member signal reads real host paths, so it is pinned off by default
    and opted into by the tests that exercise it."""
    fpa._reset_etcd_member_cache()
    monkeypatch.setattr(fpa, "_ETCD_MEMBER_SIDECAR", tmp_path / "etcd-member")
    monkeypatch.setattr(fpa, "_local_cluster_member_signal", lambda: False)
    yield
    fpa._reset_etcd_member_cache()


# ── body_opens_etcd_peers: false positives are the DANGEROUS direction ───────
# A false "peers are open" tells would_self_partition the body is safe, and the
# member firewalls itself out of raft.


def test_cp_body_is_recognised_as_opening_the_peer_port() -> None:
    assert fpa.body_opens_etcd_peers(CP_BODY) is True


def test_agent_body_does_not_open_the_peer_port() -> None:
    assert fpa.body_opens_etcd_peers(AGENT_BODY) is False


def test_a_port_range_endpoint_counts() -> None:
    assert fpa.body_opens_etcd_peers('tcp dport 2379-2380 accept comment "peer"')


def test_the_port_named_only_in_a_hash_comment_does_not_count() -> None:
    """The renderer's header block names 2379/2380 in prose."""
    assert not fpa.body_opens_etcd_peers(
        "# etcd 2379 / 2380 + kubelet 10250 scoped to the peer set\n"
        'tcp dport 22 accept comment "mgmt-ssh"\n'
    )


def test_the_port_inside_an_nft_comment_does_not_count() -> None:
    """nftables' ``comment "..."`` is not a ``#`` comment."""
    assert not fpa.body_opens_etcd_peers('tcp dport 22 accept comment "ssh; not 2380"')


def test_a_hash_inside_an_nft_comment_does_not_leak_the_port() -> None:
    """REGRESSION. Splitting on '#' BEFORE stripping the comment clause
    truncates ``comment "port 2380 #note"`` into an unterminated quote the
    comment regex can no longer match, leaking its text — and its 2380 — into
    the code. The rule opens only :22, yet the guard would call it safe."""
    assert not fpa.body_opens_etcd_peers('tcp dport 22 accept comment "port 2380 #note"')


def test_an_ipv6_address_containing_2380_does_not_count() -> None:
    """REGRESSION. ``fd00:2380::/64`` puts 2380 between colons, not digits, so
    a whole-number guard passes. The rule opens 6443 only; matching must be
    anchored to a dport position."""
    assert not fpa.body_opens_etcd_peers(
        'ip6 saddr { fd00:2380::/64 } tcp dport 6443 accept comment "kubeapi-v6"'
    )


def test_a_longer_number_containing_2380_does_not_count() -> None:
    assert not fpa.body_opens_etcd_peers("tcp dport 12380 accept")


def test_the_audited_port_tracks_the_renderer() -> None:
    """One source of truth: an audit checking a port the renderer no longer
    opens would silently re-enable the self-partition."""
    from spatium_supervisor import firewall_renderer

    assert fpa._ETCD_PEER_PORT == str(firewall_renderer.ETCD_PEER_PORT)
    assert firewall_renderer.ETCD_PEER_PORT in firewall_renderer._K3S_ETCD_KUBELET_TCP


def test_the_guard_reads_the_real_renderer_output() -> None:
    """Fixtures can drift from reality; the renderer cannot."""
    from spatium_supervisor.firewall_renderer import render_drop_in

    cp = render_drop_in(
        {"roles": []},
        ["192.168.0.199/32"],
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=["10.43.0.0/16"],
        cp_member_count=3,
        vip_configured=True,
    )
    agent = render_drop_in({"roles": ["dns_bind9"]}, [], pod_cidrs=[], service_cidrs=[])
    assert fpa.body_opens_etcd_peers(cp.body) is True
    assert fpa.body_opens_etcd_peers(agent.body) is False


# ── would_self_partition is pure: membership is passed in ────────────────────


def test_refuses_an_agent_body_on_a_live_etcd_member() -> None:
    assert fpa.would_self_partition(AGENT_BODY, is_etcd_member=True) is True


def test_allows_a_cp_body_on_a_live_etcd_member() -> None:
    assert fpa.would_self_partition(CP_BODY, is_etcd_member=True) is False


def test_allows_an_agent_body_on_a_real_agent_node() -> None:
    """Counter-property: a DNS/DHCP agent appliance is not an etcd member and
    must still receive its (peer-less) firewall."""
    assert fpa.would_self_partition(AGENT_BODY, is_etcd_member=False) is False


def test_a_readable_sole_member_is_not_a_partition() -> None:
    """THE 2026-07-10 false positive: a fresh single-node seed IS a live etcd
    member, its correct body has no peer rule, and there is no peer to be
    partitioned from — the body must apply."""
    assert (
        fpa.would_self_partition(AGENT_BODY, is_etcd_member=True, live_peers=[])
        is False
    )


def test_live_peers_without_a_rule_still_refuses() -> None:
    assert (
        fpa.would_self_partition(
            AGENT_BODY, is_etcd_member=True, live_peers=["192.168.0.199/32"]
        )
        is True
    )


def test_unknown_live_peers_stays_conservative() -> None:
    assert (
        fpa.would_self_partition(AGENT_BODY, is_etcd_member=True, live_peers=None)
        is True
    )


def test_unknown_membership_never_blocks_an_update() -> None:
    """Failing closed on 'don't know' would wedge the firewall on every node
    that has never successfully probed."""
    assert fpa.would_self_partition(AGENT_BODY, is_etcd_member=None) is False


# ── membership probe: cache + persistence ───────────────────────────────────


def test_membership_reads_the_local_nodes_own_labels(monkeypatch) -> None:
    monkeypatch.setenv("NODE_NAME", "ddi2")
    seen: dict[str, object] = {}

    def fake_request(method: str, path: str, timeout: float | None = None):
        seen.update(method=method, path=path, timeout=timeout)
        return 200, '{"metadata":{"labels":{"node-role.kubernetes.io/etcd":"true"}}}'

    monkeypatch.setattr(fpa.k8s_api, "_request", fake_request)
    assert fpa.local_node_is_etcd_member() is True
    assert seen["method"] == "GET"
    assert seen["path"] == "/api/v1/nodes/ddi2"
    assert seen["timeout"] == fpa._KUBEAPI_TIMEOUT_S


def test_the_probe_timeout_is_short_enough_not_to_stall_the_heartbeat() -> None:
    """k8s_api._request defaults to 10s. check_kubeapi_ready deliberately uses
    2s 'so a wedged apiserver doesn't stall the heartbeat loop'. Because None is
    never cached, inheriting 10s would re-pay it every heartbeat of an outage."""
    assert fpa._KUBEAPI_TIMEOUT_S <= 2.0


def test_membership_is_false_when_the_etcd_label_is_absent(monkeypatch) -> None:
    monkeypatch.setenv("NODE_NAME", "agent1")
    monkeypatch.setattr(
        fpa.k8s_api,
        "_request",
        lambda m, p, timeout=None: (
            200,
            '{"metadata":{"labels":{"kubernetes.io/os":"linux"}}}',
        ),
    )
    assert fpa.local_node_is_etcd_member() is False


def test_membership_is_unknown_when_never_probed_and_api_unreachable(
    monkeypatch,
) -> None:
    monkeypatch.setenv("NODE_NAME", "ddi2")

    def boom(method: str, path: str, timeout: float | None = None):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(fpa.k8s_api, "_request", boom)
    assert fpa.local_node_is_etcd_member() is None


def test_membership_is_unknown_without_a_node_name(monkeypatch) -> None:
    monkeypatch.delenv("NODE_NAME", raising=False)
    monkeypatch.delenv("APPLIANCE_HOSTNAME", raising=False)
    assert fpa.local_node_is_etcd_member() is None


def test_false_is_never_cached_so_a_promote_is_seen_immediately(monkeypatch) -> None:
    """REGRESSION. Caching False gives a window where a node k3s has just
    labelled an etcd server still reads 'not a member', passes the guard, and
    firewalls its own raft port shut — the exact half-landed-promote case."""
    state = {"member": False}
    monkeypatch.setattr(fpa, "_etcd_membership_uncached", lambda: state["member"])

    assert fpa.local_node_is_etcd_member() is False
    state["member"] = True  # k3s stamps node-role.kubernetes.io/etcd
    assert fpa.local_node_is_etcd_member() is True
    assert fpa.would_self_partition(AGENT_BODY, is_etcd_member=True) is True


def test_true_is_cached_so_a_healthy_member_does_not_re_probe(monkeypatch) -> None:
    """A stale True only delays narrowing after a real demote — the safe
    direction, since the peer rule only over-permits to real cluster members."""
    calls = {"n": 0}

    def probe() -> bool:
        calls["n"] += 1
        return True

    monkeypatch.setattr(fpa, "_etcd_membership_uncached", probe)
    assert fpa.local_node_is_etcd_member() is True
    assert fpa.local_node_is_etcd_member() is True
    assert calls["n"] == 1


def test_a_known_answer_survives_a_partition(monkeypatch) -> None:
    """REGRESSION. The probe reads the apiserver ClusterIP (no hostNetwork), so
    a partitioned node cannot reach it. Without the persisted last-known answer
    the guard fails open precisely when it is needed, and the node then closes
    2380 on itself and can never read membership again to reopen it."""
    monkeypatch.setattr(fpa, "_etcd_membership_uncached", lambda: True)
    assert fpa.local_node_is_etcd_member() is True  # persists "true"

    fpa._reset_etcd_member_cache()  # cold cache: supervisor pod restarted
    monkeypatch.setattr(fpa, "_etcd_membership_uncached", lambda: None)  # partition

    assert fpa.local_node_is_etcd_member() is True
    assert fpa.would_self_partition(AGENT_BODY, is_etcd_member=True) is True


def test_a_demote_clears_the_persisted_answer(monkeypatch) -> None:
    """Persistence must not pin a node to 'member' forever after a real demote.
    A confirmed False CLEARS the marker (it is never written as False)."""
    monkeypatch.setattr(fpa, "_etcd_membership_uncached", lambda: True)
    assert fpa.local_node_is_etcd_member() is True
    assert fpa._ETCD_MEMBER_SIDECAR.exists()

    fpa._reset_etcd_member_cache()
    monkeypatch.setattr(fpa, "_etcd_membership_uncached", lambda: False)
    assert fpa.local_node_is_etcd_member() is False
    assert not fpa._ETCD_MEMBER_SIDECAR.exists(), "a False must never be persisted"

    # …and with the apiserver now unreadable, the demoted node reports "don't
    # know" and the guard fails open, so its firewall can finally narrow.
    fpa._reset_etcd_member_cache()
    monkeypatch.setattr(fpa, "_etcd_membership_uncached", lambda: None)
    assert fpa.local_node_is_etcd_member() is None


def test_a_promote_during_an_apiserver_outage_is_not_read_as_not_a_member(
    monkeypatch,
) -> None:
    """REGRESSION. Persisting a False would put the #593 bug on disk: a node
    promoted while its apiserver happens to be unreachable would probe None,
    recall "not a member", pass the guard, and firewall its own raft port shut.

    The local cluster-member signal answers without the network, so the promote
    is seen even mid-outage."""
    # It was a plain agent: a confirmed False, so nothing is persisted.
    monkeypatch.setattr(fpa, "_etcd_membership_uncached", lambda: False)
    assert fpa.local_node_is_etcd_member() is False
    assert not fpa._ETCD_MEMBER_SIDECAR.exists()

    # Now it is promoted (host runner reports the join ready) AND the apiserver
    # is unreachable.
    fpa._reset_etcd_member_cache()
    monkeypatch.setattr(fpa, "_etcd_membership_uncached", lambda: None)
    monkeypatch.setattr(fpa, "_local_cluster_member_signal", lambda: True)

    assert fpa.local_node_is_etcd_member() is True
    assert fpa.would_self_partition(AGENT_BODY, is_etcd_member=True) is True


def test_the_local_signal_reads_only_host_state(monkeypatch) -> None:
    """It must answer during the very partition that defeats the kube probe, so
    it may not touch the network. Same two signals _is_control_plane_member uses."""
    from spatium_supervisor import appliance_state

    monkeypatch.setattr(appliance_state, "detect_appliance_variant", lambda: "application")
    monkeypatch.setattr(appliance_state, "read_cluster_join_state", lambda: ("ready", None))
    assert _REAL_LOCAL_SIGNAL() is True

    monkeypatch.setattr(appliance_state, "read_cluster_join_state", lambda: (None, None))
    assert _REAL_LOCAL_SIGNAL() is False

    monkeypatch.setattr(
        appliance_state, "detect_appliance_variant", lambda: "control-plane"
    )
    assert _REAL_LOCAL_SIGNAL() is True


def test_the_local_signal_never_raises(monkeypatch) -> None:
    """A best-effort fallback that raised would take the firewall path with it."""
    from spatium_supervisor import appliance_state

    def boom():
        raise RuntimeError("host state unreadable")

    monkeypatch.setattr(appliance_state, "detect_appliance_variant", boom)
    assert _REAL_LOCAL_SIGNAL() is False


def test_an_unwritable_sidecar_never_breaks_the_probe(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(fpa, "_ETCD_MEMBER_SIDECAR", tmp_path / "nope" / "x" / "member")
    monkeypatch.setattr(tmp_path.__class__, "mkdir", _raise_oserror, raising=False)
    monkeypatch.setattr(fpa, "_etcd_membership_uncached", lambda: True)
    assert fpa.local_node_is_etcd_member() is True


def _raise_oserror(*_a, **_k):
    raise OSError("read-only")


# ── observed_peer_cidrs ─────────────────────────────────────────────────────


def test_peer_recovery_excludes_self_and_emits_host_routes(monkeypatch) -> None:
    monkeypatch.setattr(
        fpa,
        "list_control_plane_node_ips",
        lambda: ["192.168.0.199", "192.168.0.133", "192.168.0.125"],
    )
    assert fpa.observed_peer_cidrs(["192.168.0.133"]) == [
        "192.168.0.125/32",
        "192.168.0.199/32",
    ]


def test_peer_recovery_handles_ipv6_prefix_length(monkeypatch) -> None:
    monkeypatch.setattr(fpa, "list_control_plane_node_ips", lambda: ["fd00::2"])
    assert fpa.observed_peer_cidrs([]) == ["fd00::2/128"]


def test_peer_recovery_is_none_when_membership_is_unreadable(monkeypatch) -> None:
    """None, not a guess — the refuse-to-apply guard protects us then. (Not
    []: an empty list now means "readable, sole member", which the guard must
    let through — conflating the two pinned every fresh single-node seed on
    the bootstrap firewall, found live 2026-07-10.)"""
    monkeypatch.setattr(fpa, "list_control_plane_node_ips", lambda: None)
    assert fpa.observed_peer_cidrs(["192.168.0.133"]) is None


def test_peer_recovery_is_empty_for_a_readable_sole_member(monkeypatch) -> None:
    monkeypatch.setattr(
        fpa, "list_control_plane_node_ips", lambda: ["192.168.0.133"]
    )
    assert fpa.observed_peer_cidrs(["192.168.0.133"]) == []


def test_a_missing_ca_file_degrades_to_none_rather_than_raising(monkeypatch) -> None:
    """k8s_api._request builds its HTTPSConnection (reading the CA via
    _ssl_context) OUTSIDE the try that converts transport errors to
    RuntimeError, so a missing ca.crt raises OSError straight through."""

    def boom(method: str, path: str, timeout: float | None = None):
        raise OSError("ca.crt: No such file or directory")

    monkeypatch.setattr(fpa.k8s_api, "_request", boom)
    assert fpa.list_control_plane_node_ips() is None


# ── the real dispatch paths ─────────────────────────────────────────────────
#
# The unit tests above pin the predicates. These drive the functions that
# actually write the trigger file the host runner consumes, because that write
# is what partitioned ddi2.


def _wire(monkeypatch, tmp_path, *, is_member, live_members):
    from spatium_supervisor import appliance_state, heartbeat

    trigger = tmp_path / "firewall-pending"
    monkeypatch.setattr(heartbeat, "_NFT_TRIGGER_PATH", trigger)
    monkeypatch.setattr(heartbeat, "_NFT_APPLIED_HASH_PATH", tmp_path / "applied-hash")
    monkeypatch.setattr(
        appliance_state, "_FIREWALL_REFUSAL_SIDECAR", tmp_path / "firewall-refused"
    )
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(appliance_state, "read_node_ips", lambda: ["192.168.0.133"])
    monkeypatch.setattr(fpa, "_etcd_membership_uncached", lambda: is_member)
    monkeypatch.setattr(fpa, "list_control_plane_node_ips", lambda: live_members)
    monkeypatch.setattr(fpa, "warn_on_peer_drift", lambda *a, **k: None)
    return heartbeat, appliance_state, trigger


def test_a_live_etcd_member_never_writes_a_partitioning_trigger(
    monkeypatch, tmp_path
) -> None:
    """THE #593 scenario. Row says agent (no peers), the cluster is unreadable
    so recovery finds nothing, and the body has no peer rule. Nothing is
    written; the last-good ruleset stands."""
    import structlog

    heartbeat, appliance_state, trigger = _wire(
        monkeypatch, tmp_path, is_member=True, live_members=None
    )
    heartbeat._maybe_apply_firewall(
        {"roles": ["dns_bind9"]}, structlog.get_logger("t"), []
    )
    assert not trigger.exists(), "wrote a drop-in that would partition this member"
    state = appliance_state.read_firewall_state()
    assert state and state["state"] == "refused_self_partition"


def test_peer_recovery_rescues_the_render_when_membership_is_readable(
    monkeypatch, tmp_path
) -> None:
    """Row still says agent, but the cluster can be read: recover the peer set,
    re-render, and write a body that keeps this node in raft."""
    import structlog

    heartbeat, appliance_state, trigger = _wire(
        monkeypatch,
        tmp_path,
        is_member=True,
        live_members=["192.168.0.199", "192.168.0.133", "192.168.0.125"],
    )
    heartbeat._maybe_apply_firewall(
        {"roles": ["dns_bind9"]}, structlog.get_logger("t"), []
    )
    assert trigger.exists()
    body = trigger.read_text()
    assert fpa.body_opens_etcd_peers(body)
    assert "192.168.0.199" in body and "192.168.0.125" in body
    assert appliance_state.read_firewall_state() is None, "healed node still flagged"


def test_a_fresh_single_node_seed_applies_its_firewall(monkeypatch, tmp_path) -> None:
    """THE 2026-07-10 regression (caught by ddi-pg dev rigs, reproduced 2x
    including the 2026.07.09-1 release-prep build): a fresh single-node seed
    is a live etcd member with ZERO peers, so its correct body has no peer
    rule. The guard refused it every heartbeat, pinning the k3s-bootstrap
    profile forever — 80/443 web-ui accepts never applied, API/UI dead from
    off-box while /health/* stayed 200 on localhost."""
    import structlog

    heartbeat, appliance_state, trigger = _wire(
        monkeypatch,
        tmp_path,
        is_member=True,
        live_members=["192.168.0.133"],  # readable — and only THIS node
    )
    heartbeat._maybe_apply_firewall(
        {"roles": ["dns_bind9"]}, structlog.get_logger("t"), []
    )
    assert trigger.exists(), "a sole member's firewall must apply"
    assert appliance_state.read_firewall_state() is None


def test_a_real_agent_node_still_gets_its_firewall(monkeypatch, tmp_path) -> None:
    """Counter-property. A DNS agent appliance is not an etcd member, so the
    peer-less body is correct and must be applied. Failing closed here would
    freeze the firewall on every non-etcd appliance."""
    import structlog

    heartbeat, appliance_state, trigger = _wire(
        monkeypatch, tmp_path, is_member=False, live_members=None
    )
    heartbeat._maybe_apply_firewall(
        {"roles": ["dns_bind9"]}, structlog.get_logger("t"), []
    )
    assert trigger.exists()
    assert not fpa.body_opens_etcd_peers(trigger.read_text())
    assert appliance_state.read_firewall_state() is None


def test_a_healthy_cp_node_never_probes_the_apiserver(monkeypatch, tmp_path) -> None:
    """Efficiency + blast radius: a body that already opens 2380 needs no
    membership read, so the steady-state control-plane heartbeat costs nothing."""
    import structlog

    heartbeat, _as, trigger = _wire(
        monkeypatch, tmp_path, is_member=True, live_members=None
    )
    calls = {"n": 0}

    def counted():
        calls["n"] += 1
        return True

    monkeypatch.setattr(fpa, "_etcd_membership_uncached", counted)
    heartbeat._maybe_apply_firewall(
        {"roles": []},
        structlog.get_logger("t"),
        ["192.168.0.199/32"],
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=["10.43.0.0/16"],
    )
    assert trigger.exists()
    assert fpa.body_opens_etcd_peers(trigger.read_text())
    assert calls["n"] == 0, "probed the apiserver for a body that already opens 2380"


def test_the_refusal_marker_clears_once_a_good_body_applies(
    monkeypatch, tmp_path
) -> None:
    """A node that heals must stop reporting a divergence it no longer has."""
    import structlog

    heartbeat, appliance_state, _t = _wire(
        monkeypatch, tmp_path, is_member=True, live_members=None
    )
    heartbeat._maybe_apply_firewall(
        {"roles": ["dns_bind9"]}, structlog.get_logger("t"), []
    )
    assert appliance_state.read_firewall_state() is not None

    monkeypatch.setattr(
        fpa,
        "list_control_plane_node_ips",
        lambda: ["192.168.0.199", "192.168.0.133"],
    )
    heartbeat._maybe_apply_firewall(
        {"roles": ["dns_bind9"]}, structlog.get_logger("t"), []
    )
    assert appliance_state.read_firewall_state() is None


# ── bundle-first dispatch: a refusal must FALL THROUGH, not just skip ───────


def _bundle(conf: str) -> dict:
    return {"config_hash": "abc123", "firewall_conf": conf}


def test_bundle_is_used_when_its_body_opens_the_peer_port(monkeypatch, tmp_path) -> None:
    import structlog

    heartbeat, _as, _t = _wire(monkeypatch, tmp_path, is_member=True, live_members=None)
    assert (
        heartbeat._server_firewall_body_is_usable(
            _bundle(CP_BODY), structlog.get_logger("t")
        )
        is True
    )


def test_bundle_is_used_on_a_plain_agent_node(monkeypatch, tmp_path) -> None:
    """A peer-less body is correct there; refusing would freeze its firewall."""
    import structlog

    heartbeat, _as, _t = _wire(monkeypatch, tmp_path, is_member=False, live_members=None)
    assert (
        heartbeat._server_firewall_body_is_usable(
            _bundle(AGENT_BODY), structlog.get_logger("t")
        )
        is True
    )


def test_bundle_is_refused_and_falls_through_on_a_live_etcd_member(
    monkeypatch, tmp_path
) -> None:
    """REGRESSION (#593 review finding 5). Refusing the server body must return
    False so heartbeat_once runs the IN-POD renderer, which can recover peers.
    Merely declining to write would strand the member forever, because the
    control plane re-renders the same wrong body from the same stale row."""
    import structlog

    heartbeat, appliance_state, _t = _wire(
        monkeypatch, tmp_path, is_member=True, live_members=None
    )
    assert (
        heartbeat._server_firewall_body_is_usable(
            _bundle(AGENT_BODY), structlog.get_logger("t")
        )
        is False
    )
    state = appliance_state.read_firewall_state()
    assert state and state["source"] == "control-plane"


def test_no_server_authority_means_no_bundle(monkeypatch, tmp_path) -> None:
    import structlog

    heartbeat, _as, _t = _wire(monkeypatch, tmp_path, is_member=True, live_members=None)
    log = structlog.get_logger("t")
    assert heartbeat._server_firewall_body_is_usable(None, log) is False
    assert heartbeat._server_firewall_body_is_usable({}, log) is False
    assert heartbeat._server_firewall_body_is_usable({"config_hash": ""}, log) is False


def test_a_healthy_cp_bundle_never_probes_the_apiserver(monkeypatch, tmp_path) -> None:
    import structlog

    heartbeat, _as, _t = _wire(monkeypatch, tmp_path, is_member=True, live_members=None)
    calls = {"n": 0}

    def counted():
        calls["n"] += 1
        return True

    monkeypatch.setattr(fpa, "_etcd_membership_uncached", counted)
    heartbeat._server_firewall_body_is_usable(_bundle(CP_BODY), structlog.get_logger("t"))
    assert calls["n"] == 0


# ── #2774 — the control-plane path uses the same predicate as the in-pod one ──
#
# A one-node install IS a live etcd member and has no peers, so the server's
# correct body has no 2380 rule. The bundle guard refused it on every heartbeat
# (it never got #610's sole-member exemption), the dispatch fell back to the
# in-pod render, which carries no fleet-policy rules — so with enforcement on, a
# fleet rule never reached the host and the Firewall view showed drift forever.

# A server-rendered one-node body carrying an enforced fleet rule.
FLEET_BODY = AGENT_BODY + 'tcp dport 47771 accept comment "fleet:allow-47771"\n'


def _wire_bundle(monkeypatch, tmp_path, *, is_member, live_members):
    heartbeat, appliance_state, trigger = _wire(
        monkeypatch, tmp_path, is_member=is_member, live_members=live_members
    )
    # The server path writes the SAME host trigger file through appliance_state.
    monkeypatch.setattr(appliance_state, "_FIREWALL_TRIGGER_FILE", trigger)
    monkeypatch.setattr(
        appliance_state, "_FIREWALL_APPLIED_HASH_SIDECAR", tmp_path / "applied-hash"
    )
    monkeypatch.setattr(
        appliance_state, "_FIREWALL_APPLIED_STATUS_SIDECAR", tmp_path / "applied-status"
    )
    return heartbeat, appliance_state, trigger


def _dispatch(heartbeat, conf, cluster_peer_cidrs=None):
    import structlog

    heartbeat._dispatch_firewall(
        {"config_hash": "fleet-hash-1", "firewall_conf": conf},
        {"roles": ["dns_bind9"]},
        structlog.get_logger("t"),
        cluster_peer_cidrs or [],
    )


def test_a_sole_member_uses_the_server_body_without_a_peer_rule(
    monkeypatch, tmp_path
) -> None:
    import structlog

    heartbeat, appliance_state, _t = _wire_bundle(
        monkeypatch, tmp_path, is_member=True, live_members=["192.168.0.133"]
    )
    assert (
        heartbeat._server_firewall_body_is_usable(
            _bundle(FLEET_BODY), structlog.get_logger("t")
        )
        is True
    )
    assert appliance_state.read_firewall_state() is None


def test_a_sole_member_applies_the_enforced_fleet_rule(monkeypatch, tmp_path) -> None:
    """End to end through the dispatch: the trigger the host runner consumes is
    the SERVER body, fleet rule included — not the in-pod render."""
    heartbeat, appliance_state, trigger = _wire_bundle(
        monkeypatch, tmp_path, is_member=True, live_members=["192.168.0.133"]
    )
    _dispatch(heartbeat, FLEET_BODY)
    assert trigger.exists(), "nothing was handed to the host runner"
    text = trigger.read_text()
    assert text.startswith("fleet-hash-1\n"), "fell back to the in-pod render"
    assert "fleet:allow-47771" in text
    assert appliance_state.read_firewall_state() is None


def test_a_stale_refusal_marker_clears_once_the_server_body_is_used(
    monkeypatch, tmp_path
) -> None:
    """A one-node install refused before the fix carries a control-plane
    refusal marker; using the server body must clear it, or Fleet keeps
    showing a divergence that no longer exists."""
    import structlog

    heartbeat, appliance_state, _t = _wire_bundle(
        monkeypatch, tmp_path, is_member=True, live_members=["192.168.0.133"]
    )
    appliance_state.record_firewall_refusal("control-plane", "old")
    heartbeat._server_firewall_body_is_usable(
        _bundle(FLEET_BODY), structlog.get_logger("t")
    )
    assert appliance_state.read_firewall_state() is None


def test_a_three_node_member_still_refuses_a_body_missing_its_peers(
    monkeypatch, tmp_path
) -> None:
    """The guard is unchanged where the danger is real: live peers, no rule."""
    import structlog

    heartbeat, appliance_state, _t = _wire_bundle(
        monkeypatch,
        tmp_path,
        is_member=True,
        live_members=["192.168.0.199", "192.168.0.133", "192.168.0.125"],
    )
    assert (
        heartbeat._server_firewall_body_is_usable(
            _bundle(FLEET_BODY), structlog.get_logger("t")
        )
        is False
    )
    state = appliance_state.read_firewall_state()
    assert state and state["source"] == "control-plane"


def test_a_refused_body_falls_back_to_a_render_that_admits_the_peers(
    monkeypatch, tmp_path
) -> None:
    """The refusal must still converge: the in-pod fallback recovers the live
    peer set and writes a body that keeps this node in raft."""
    heartbeat, _as, trigger = _wire_bundle(
        monkeypatch,
        tmp_path,
        is_member=True,
        live_members=["192.168.0.199", "192.168.0.133", "192.168.0.125"],
    )
    _dispatch(heartbeat, FLEET_BODY)
    assert trigger.exists(), "a refusal left the node with nothing to apply"
    text = trigger.read_text()
    assert not text.startswith("fleet-hash-1\n"), "the refused server body was used"
    assert fpa.body_opens_etcd_peers(text)
    assert "192.168.0.199" in text and "192.168.0.125" in text


def test_a_three_node_body_that_admits_the_peers_is_used(monkeypatch, tmp_path) -> None:
    heartbeat, _as, trigger = _wire_bundle(
        monkeypatch,
        tmp_path,
        is_member=True,
        live_members=["192.168.0.199", "192.168.0.133", "192.168.0.125"],
    )
    _dispatch(heartbeat, CP_BODY)
    assert trigger.read_text().startswith("fleet-hash-1\n")


def test_unreadable_membership_still_refuses_a_peerless_body(
    monkeypatch, tmp_path
) -> None:
    """A member whose peer set cannot be read stays conservative — the same
    answer the in-pod path gives (``would_self_partition`` with None)."""
    import structlog

    heartbeat, _as, _t = _wire_bundle(
        monkeypatch, tmp_path, is_member=True, live_members=None
    )
    assert (
        heartbeat._server_firewall_body_is_usable(
            _bundle(FLEET_BODY), structlog.get_logger("t")
        )
        is False
    )
