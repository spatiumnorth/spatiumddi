"""Merge-engine internals (#285 Phase 3b).

The byte-identity of the BUILTINS is proven in test_appliance_firewall_render
(the three-way triangle). Here we test the parts the builtins don't exercise:
the operator-overlay pipeline (explode → deny-wins → source-union), derived-
source resolution, render guards, family filtering — plus a drift guard tying
the in-code canonical builtins to the seed migration.
"""

from __future__ import annotations

import importlib.util
import pathlib

from app.services.appliance.firewall_merge import (
    _BUILTIN_GUARD,
    _BUILTIN_SEED,
    MergeContext,
    PolicySet,
    _Alias,
    _guard_ok,
    _Policy,
    _Rule,
    builtin_policy_set,
    compile_firewall_from_policies,
)


def _rule(seq, action, proto, ports, **kw) -> _Rule:
    return _Rule(
        seq=seq,
        action=action,
        protocol=proto,
        ports=tuple(ports),
        source_kind=kw.get("source_kind", "any"),
        source_cidrs=tuple(kw.get("source_cidrs", ())),
        source_alias=kw.get("source_alias"),
        family=kw.get("family", "both"),
        comment=kw.get("comment"),
        render_guard=kw.get("render_guard"),
        enabled=kw.get("enabled", True),
    )


def _overlay_lines(fleet_rules=(), appliance_rules=(), aliases=None) -> list[str]:
    """Render an idle (non-CP) node so only the overlay block has content,
    and return just the overlay lines."""
    ps = PolicySet(
        fleet=_Policy("fleet", None, True, tuple(fleet_rules)),
        aliases=aliases or {},
    )
    appliance_policy = (
        _Policy("appliance", None, True, tuple(appliance_rules)) if appliance_rules else None
    )
    body = compile_firewall_from_policies(
        {"roles": []},
        None,
        policy_set=ps,
        appliance_policy=appliance_policy,
    )
    lines = body.splitlines()
    if "# ── Fleet / appliance overlay ──────────────────────────" not in lines:
        return []
    i = lines.index("# ── Fleet / appliance overlay ──────────────────────────")
    return [ln for ln in lines[i + 1 :] if ln and not ln.startswith("#")]


def test_overlay_deny_wins_emits_drops_first() -> None:
    # nft is first-match-wins: a DROP authored after an ACCEPT must still emit
    # before it so it actually blocks.
    out = _overlay_lines(
        fleet_rules=[
            _rule(10, "accept", "tcp", [8080], comment="app"),
            _rule(
                20,
                "drop",
                "tcp",
                [8080],
                source_kind="cidr",
                source_cidrs=["10.0.0.0/8"],
                comment="block",
            ),  # noqa: E501
        ]
    )
    drop_idx = next(i for i, ln in enumerate(out) if " drop" in ln)
    accept_idx = next(i for i, ln in enumerate(out) if " accept" in ln)
    assert drop_idx < accept_idx, out


def test_overlay_source_union_merges_same_target() -> None:
    out = _overlay_lines(
        fleet_rules=[
            _rule(
                10,
                "accept",
                "tcp",
                [443],
                source_kind="cidr",
                source_cidrs=["10.0.0.0/8"],
                comment="https",
            ),  # noqa: E501
            _rule(
                20,
                "accept",
                "tcp",
                [443],
                source_kind="cidr",
                source_cidrs=["192.168.0.0/16"],
                comment="https",
            ),  # noqa: E501
        ]
    )
    # One unioned line, both CIDRs in a single set (deterministic sort).
    assert len(out) == 1, out
    assert "10.0.0.0/8" in out[0] and "192.168.0.0/16" in out[0]
    assert (
        out[0] == 'ip saddr { 10.0.0.0/8, 192.168.0.0/16 } tcp dport 443 accept comment "https-v4"'
    )


def test_overlay_alias_resolution() -> None:
    aliases = {"mgmt": _Alias("mgmt", ("10.1.0.0/24",), ("2001:db8::/64",), ())}
    out = _overlay_lines(
        fleet_rules=[
            _rule(
                10,
                "accept",
                "tcp",
                [22],
                source_kind="alias",
                source_alias="mgmt",
                comment="ssh-net",
            )
        ],  # noqa: E501
        aliases=aliases,
    )
    assert any("10.1.0.0/24" in ln and "ssh-net-v4" in ln for ln in out), out
    assert any("2001:db8::/64" in ln and "ssh-net-v6" in ln for ln in out), out


def test_overlay_any_source_emits_bare() -> None:
    out = _overlay_lines(fleet_rules=[_rule(10, "accept", "udp", [123], comment="ntp")])
    assert out == ['udp dport 123 accept comment "ntp"'], out


def test_overlay_family_filter() -> None:
    out = _overlay_lines(
        fleet_rules=[
            _rule(
                10,
                "accept",
                "tcp",
                [9000],
                source_kind="cidr",
                source_cidrs=["10.0.0.0/8", "2001:db8::/64"],
                family="v4",
                comment="v4only",
            ),
        ]
    )
    assert len(out) == 1 and "10.0.0.0/8" in out[0] and "2001:db8" not in out[0], out


def test_overlay_appliance_after_fleet() -> None:
    out = _overlay_lines(
        fleet_rules=[_rule(10, "accept", "udp", [100], comment="fleet")],
        appliance_rules=[_rule(10, "accept", "udp", [200], comment="appl")],
    )
    assert out == [
        'udp dport 100 accept comment "fleet"',
        'udp dport 200 accept comment "appl"',
    ], out


def test_overlay_disabled_policy_skipped() -> None:
    ps = PolicySet(
        fleet=_Policy("fleet", None, False, (_rule(10, "accept", "udp", [9], comment="x"),))
    )
    body = compile_firewall_from_policies({"roles": []}, None, policy_set=ps)
    assert "overlay" not in body


def test_guard_ok_matrix() -> None:
    ctx_lo = MergeContext.build(
        {"roles": []},
        None,
        pod_cidrs=None,
        service_cidrs=None,
        cp_member_count=1,
        vip_configured=False,
    )
    ctx_hi = MergeContext.build(
        {"roles": []},
        None,
        pod_cidrs=None,
        service_cidrs=None,
        cp_member_count=3,
        vip_configured=True,
    )
    assert _guard_ok(None, ctx_lo) is True
    assert _guard_ok(_BUILTIN_GUARD, ctx_lo) is False  # 1 member, no vip
    assert _guard_ok(_BUILTIN_GUARD, ctx_hi) is True
    assert _guard_ok({"min_cp_members": 2}, ctx_hi) is True
    assert _guard_ok({"requires_vip": True}, ctx_lo) is False


def test_resolve_source_kubeapi_union() -> None:
    ctx = MergeContext.build(
        {"roles": [], "kubeapi_expose_cidrs": ["10.9.0.0/24"]},
        ["192.168.0.1/32"],
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=["10.43.0.0/16"],
        cp_member_count=3,
        vip_configured=True,
    )
    v4, v6 = ctx.resolve_source(_rule(1, "accept", "tcp", [6443], source_kind="kubeapi"))
    assert set(v4) == {"192.168.0.1/32", "10.42.0.0/16", "10.43.0.0/16", "10.9.0.0/24"}
    assert v6 == []
    # cluster_peers is the narrower set (no pod/svc/kubeapi).
    pv4, _ = ctx.resolve_source(_rule(1, "accept", "tcp", [2379], source_kind="cluster_peers"))
    assert pv4 == ["192.168.0.1/32"]


def test_unknown_alias_resolves_empty() -> None:
    ctx = MergeContext.build(
        {"roles": []},
        None,
        pod_cidrs=None,
        service_cidrs=None,
        cp_member_count=1,
        vip_configured=False,
    )
    assert ctx.resolve_source(
        _rule(1, "accept", "tcp", [22], source_kind="alias", source_alias="nope")
    ) == ([], [])


def test_builtin_set_shape() -> None:
    ps = builtin_policy_set()
    assert ps.fleet is not None and ps.fleet.rules == ()
    assert set(ps.roles) == {
        "dns-bind9",
        "dns-powerdns",
        "dns-technitium",
        "dhcp",
        "control-plane",
        "observer",
        "custom",
    }
    assert ps.roles["observer"].enabled is False
    cp = ps.roles["control-plane"]
    assert [r.seq for r in cp.rules] == [10, 20, 25, 30, 40]
    # The memberlist pair is the only guarded builtin (multi-node + VIP).
    assert cp.rules[3].render_guard == _BUILTIN_GUARD
    # #993 — the kubelet rule. Indexed by seq rather than position so a
    # future insert renumbers the assertion instead of silently re-pointing
    # it at a different rule.
    kubelet = next(r for r in cp.rules if r.seq == 25)
    assert (kubelet.protocol, kubelet.ports) == ("tcp", (10250,))
    assert kubelet.render_guard is None, "must emit on a single node, where there are no peers"
    # Not ``kubeapi``: that union carries the operator's kubeapi_expose
    # allowlist, which widens the RBAC-guarded apiserver and must never be
    # extended to the kubelet's /exec, /run and /attach.
    assert kubelet.source_kind == "kubelet"


def _load_migration_module(filename: str):
    path = pathlib.Path(__file__).resolve().parents[1] / "alembic/versions" / filename
    spec = importlib.util.spec_from_file_location(f"_fw_seed_mig_{filename}", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Every migration that seeds a builtin firewall policy row, in the order
# they apply against a fresh DB. A new DNS driver's role policy lands in
# its OWN migration (append-only — f5b8d2c91a06 already shipped), so the
# drift guard below concatenates all of them rather than assuming a single
# file holds the whole set. Add new migrations here alongside their driver.
_SEED_MIGRATION_FILES = [
    "f5b8d2c91a06_firewall_builtin_seed.py",
    "6a668dd451d5_dns_technitium_firewall_seed.py",
    "d4a9e37b2c15_kubelet_firewall_rule_seed.py",
    "e6b2f07a3c91_dhcpv6_firewall_rule_seed.py",
]


def _fold(entries):
    """(scope_kind, scope_role) -> rules, in first-seen policy order.

    A seed migration may add a whole POLICY (6a668dd451d5, Technitium) or
    just a RULE to a policy an earlier migration created (d4a9e37b2c15, the
    #993 kubelet rule on ``control-plane``). Comparing the flat concatenation
    could only ever express the first shape. What actually has to match is
    the state a fresh DB ends up in after every migration has applied, so
    fold contributions onto the policy they belong to — and sort each
    policy's rules by ``seq``, because that is what ``_policy_from_orm`` does
    when reading them back, and the byte-identity contract is on the emitted
    ORDER.
    """
    folded: dict[tuple[str, str | None], list] = {}
    enabled_by: dict[tuple[str, str | None], bool] = {}
    for scope_kind, scope_role, enabled, rules in entries:
        key = (scope_kind, scope_role)
        if key not in folded:
            folded[key] = []
            enabled_by[key] = enabled
        else:
            assert enabled_by[key] == enabled, f"{key} disagrees about ``enabled``"
        folded[key].extend(
            (seq, a, p, tuple(po), k, f, c, g) for (seq, a, p, po, k, f, c, g) in rules
        )
    return {k: (enabled_by[k], sorted(v, key=lambda r: r[0])) for k, v in folded.items()}


def test_builtin_seed_matches_migration() -> None:
    """The in-code canonical builtins (the render source on an unseeded DB)
    must match the seed migrations row-for-row, else a node renders one set
    while the DB holds another."""
    migs = [_load_migration_module(f) for f in _SEED_MIGRATION_FILES]
    for mig in migs:
        guard = getattr(mig, "_GUARD", None)
        if guard is not None:
            assert guard == _BUILTIN_GUARD

    mig_entries = [
        (sk, sr, enabled, rules)
        for mig in migs
        for (sk, sr, _name, enabled, rules) in mig._POLICIES
    ]
    assert _fold(_BUILTIN_SEED) == _fold(mig_entries)


def test_the_in_code_seed_lists_each_policy_rules_in_seq_order() -> None:
    """``builtin_policy_set`` preserves list order verbatim while
    ``_policy_from_orm`` sorts by ``seq``. So an out-of-order rule here makes
    an unseeded DB render a DIFFERENT byte sequence from a seeded one — and
    the triangle test only ever exercises one of those two paths at a time.

    _fold() sorts, so it cannot see this; assert it separately.
    """
    for scope_kind, scope_role, _enabled, rules in _BUILTIN_SEED:
        seqs = [r[0] for r in rules]
        assert seqs == sorted(seqs), f"{scope_kind}/{scope_role} rules are not in seq order"


# ── source_kind coverage — the fail-OPEN gap (#993 review) ──────────────


def test_every_accepted_source_kind_resolves_to_a_real_source() -> None:
    """A ``source_kind`` the API accepts but ``resolve_source`` does not
    handle falls into its ``else: # "any"`` branch and returns ``([], [])``
    — which both emit paths render as a rule with **no saddr at all**.

    That is not a rule that matches nothing. It is a rule that matches
    EVERYONE: an operator scoping a port to the pod CIDR would silently
    publish it to the LAN. The two lists live in different modules
    (``api/v1/appliance/firewall._SOURCE_KINDS`` and this resolver), so
    nothing but this test stops one growing without the other — which is
    exactly what happened to the frontend's copy when #993 added
    ``kubelet``.
    """
    from app.api.v1.appliance.firewall import _SOURCE_KINDS

    ctx = MergeContext.build(
        {"roles": [], "kubeapi_expose_cidrs": ["10.9.0.0/24"]},
        ["192.168.0.10/32"],
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=["10.43.0.0/16"],
        cp_member_count=3,
        vip_configured=True,
        mgmt_cidrs=["192.168.1.0/24"],
        vip_cidrs=["192.168.0.250/32"],
    )
    for kind in sorted(_SOURCE_KINDS):
        if kind == "any":
            continue  # "any" MEANS no saddr; that is the one legitimate case.
        rule = _Rule(
            seq=10,
            action="accept",
            protocol="tcp",
            ports=(9999,),
            source_kind=kind,
            # Populated so the two rule-carried kinds have something to
            # resolve; ignored by the derived ones.
            source_cidrs=("203.0.113.0/24",) if kind == "cidr" else (),
            source_alias="nope" if kind == "alias" else None,
            family="both",
            comment=None,
            render_guard=None,
            enabled=True,
        )
        v4, v6 = ctx.resolve_source(rule)
        if kind == "alias":
            # An alias naming nothing legitimately resolves empty — but it
            # logs, and the rule is the operator's own typo rather than a
            # kind the engine has never heard of. Prove the branch exists
            # by resolving a real one instead.
            continue
        assert v4 or v6, (
            f"source_kind {kind!r} is accepted by the API but resolves to no "
            "source — the renderers emit that as a rule with NO saddr, i.e. "
            "open to everyone. Add it to MergeContext.resolve_source."
        )


def test_an_unknown_source_kind_is_the_fail_open_shape_this_guards() -> None:
    """Negative control for the test above: without it, the failure is
    silent. Asserted so a future refactor that makes an unknown kind raise
    (better) or drop the rule (also better) fails here and gets read,
    rather than quietly making the guard above vacuous.
    """
    ctx = MergeContext.build(
        {"roles": []},
        None,
        pod_cidrs=["10.42.0.0/16"],
        service_cidrs=None,
        cp_member_count=1,
        vip_configured=False,
    )
    rule = _Rule(
        seq=10,
        action="accept",
        protocol="tcp",
        ports=(9999,),
        source_kind="not_a_real_kind",
        source_cidrs=(),
        source_alias=None,
        family="both",
        comment=None,
        render_guard=None,
        enabled=True,
    )
    assert ctx.resolve_source(rule) == ([], [])
