"""Declarative fleet-firewall merge engine (#285 Phase 3b).

Compiles a node's effective nftables drop-in body from the layered policy
model (``FirewallPolicy`` / ``FirewallRule`` / ``FirewallAlias``) instead of
the Phase-2 hardcoded renderer. The seeded builtin policies reproduce that
renderer BYTE-FOR-BYTE, so ``compile_firewall_from_policies`` SUBSUMES
``firewall.compile_firewall_body``:

    render_drop_in (supervisor in-pod)  ==  compile_firewall_body (frozen 2a)
                                        ==  compile_firewall_from_policies (here, fed the builtins)

A regression test (``tests/test_appliance_firewall_render.py``) asserts the
triangle across an input matrix. A one-byte divergence re-fires every node's
host trigger on the enable flip, so the builtins emit through the SAME
helpers / constants / order as the legacy renderer (the role-ports + the
control-plane block are STRUCTURAL emits — they bypass the generic
explode→deny-wins overlay pipeline, which only runs for operator-authored
fleet / appliance rules that have no byte-identity contract).

Two byte-identity traps the design flagged, handled here:

1. ``is_cp`` keys off the RAW pod/service lists being non-empty (a node with
   a syntactically-junk pod CIDR is still a CP node), while the kubeapi union
   uses the VALIDATED/split lists. ``MergeContext.build`` computes ``is_cp``
   from the raw lists before the split, so the control-plane header emits
   exactly when the legacy ``is_cp`` did.
2. ``control-plane`` is a MERGE-INTERNAL scope key resolved per-node by the
   ``is_cp`` predicate — never a node label. It is matched out of
   ``role_policies`` separately from the node's declared roles.

The merge operates on session-detached lightweight dataclasses (``_Policy`` /
``_Rule`` / ``_Alias``), so a loaded policy set is safe to cache across
requests + event loops without dragging a closed ORM session behind it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from app.services.appliance.firewall import (
    _emit_family_rule,
    _profile_name,
    _split_families,
)

if TYPE_CHECKING:
    from app.models.firewall import FirewallAlias, FirewallPolicy

log = structlog.get_logger(__name__)


# ── Session-detached policy structures ───────────────────────────────


@dataclass(frozen=True)
class _Rule:
    seq: int
    action: str
    protocol: str
    ports: tuple[int, ...]
    source_kind: str
    source_cidrs: tuple[str, ...]
    source_alias: str | None
    family: str
    comment: str | None
    render_guard: dict[str, Any] | None
    enabled: bool


@dataclass(frozen=True)
class _Policy:
    scope_kind: str
    scope_role: str | None
    enabled: bool
    rules: tuple[_Rule, ...]


@dataclass(frozen=True)
class _Alias:
    name: str
    v4_members: tuple[str, ...]
    v6_members: tuple[str, ...]
    port_members: tuple[int, ...]


@dataclass
class PolicySet:
    """A node-independent snapshot of the layered policy model (cacheable)."""

    fleet: _Policy | None = None
    roles: dict[str, _Policy] = field(default_factory=dict)
    aliases: dict[str, _Alias] = field(default_factory=dict)


# ── The mgmt floor — code, not data ──────────────────────────────────
# Management rules, emitted first and not authorable away by the policy
# surface (the no-drop-22 CHECK is the DB twin). Always OPEN, except that
# #1009 lets an operator source-scope the SSH line via ``ssh_lockdown`` —
# which is a setting, not a rule, and is why the first entry is emitted
# separately by the caller rather than taken from this tuple wholesale.
# Byte-identical to firewall.compile_firewall_body.
_MGMT_FLOOR: tuple[str, ...] = (
    'tcp dport 22 accept comment "ssh"',
    'icmp type echo-request accept comment "icmpv4 ping"',
    'icmpv6 type echo-request accept comment "icmpv6 ping"',
    'iif lo accept comment "loopback"',
)


# ── Canonical builtin seed — MIRRORS the f5b8d2c91a06 seed migration ──
# Drift between the two is caught by test_builtin_seed_matches_migration.
# rule = (seq, action, proto, ports, source_kind, family, comment, guard)
_BUILTIN_GUARD: dict[str, Any] = {"min_cp_members": 2, "requires_vip": True}
_BUILTIN_SEED: list[tuple[str, str | None, bool, list[tuple]]] = [
    ("fleet", None, True, []),
    (
        "role",
        "dns-bind9",
        True,
        [
            (10, "accept", "udp", (53,), "any", "both", None, None),
            (20, "accept", "tcp", (53,), "any", "both", None, None),
        ],
    ),
    (
        "role",
        "dns-powerdns",
        True,
        [
            (10, "accept", "udp", (53,), "any", "both", None, None),
            (20, "accept", "tcp", (53,), "any", "both", None, None),
        ],
    ),
    (
        "role",
        "dhcp",
        True,
        [
            (10, "accept", "udp", (67, 68), "any", "both", None, None),
            # DHCPv6 (#1139) — its own seed migration, e6b2f07a3c91.
            (20, "accept", "udp", (547,), "any", "both", None, None),
        ],
    ),
    (
        "role",
        "control-plane",
        True,
        [
            (10, "accept", "tcp", (2379, 2380, 10250), "cluster_peers", "both", "k3s-peer", None),
            (20, "accept", "tcp", (6443,), "kubeapi", "both", "kubeapi", None),
            # #993 — the kubelet from inside the cluster. seq 25 places it
            # between kubeapi and memberlist, which is where both hardcoded
            # renderers emit it; the byte-identity contract is on the ORDER,
            # not just the set.
            (25, "accept", "tcp", (10250,), "kubelet", "both", "kubelet", None),
            (
                30,
                "accept",
                "tcp",
                (7946,),
                "cluster_peers",
                "both",
                "metallb-memberlist-tcp",
                _BUILTIN_GUARD,
            ),  # noqa: E501
            (
                40,
                "accept",
                "udp",
                (7946,),
                "cluster_peers",
                "both",
                "metallb-memberlist-udp",
                _BUILTIN_GUARD,
            ),  # noqa: E501
        ],
    ),
    ("role", "observer", False, []),
    ("role", "custom", True, []),
    # dns-technitium ships in its own seed migration (6a668dd451d5) —
    # f5b8d2c91a06 already shipped before Technitium existed (append-only
    # migration rule) — so this entry is appended at the END to match the
    # chronological order the two migrations actually apply in against a
    # fresh DB. test_builtin_seed_matches_migration compares this list
    # against the concatenation of every seed migration's ``_POLICIES``.
    (
        "role",
        "dns-technitium",
        True,
        [
            (10, "accept", "udp", (53,), "any", "both", None, None),
            (20, "accept", "tcp", (53,), "any", "both", None, None),
        ],
    ),
]


def builtin_policy_set() -> PolicySet:
    """The builtin policies as a session-free ``PolicySet`` — the render
    source on an unseeded DB and the byte-identity test's input."""
    ps = PolicySet()
    for scope_kind, scope_role, enabled, rules in _BUILTIN_SEED:
        rule_objs = tuple(
            _Rule(
                seq=seq,
                action=action,
                protocol=proto,
                ports=tuple(ports),
                source_kind=skind,
                source_cidrs=(),
                source_alias=None,
                family=fam,
                comment=comment,
                render_guard=guard,
                enabled=True,
            )
            for (seq, action, proto, ports, skind, fam, comment, guard) in rules
        )
        pol = _Policy(
            scope_kind=scope_kind, scope_role=scope_role, enabled=enabled, rules=rule_objs
        )
        if scope_kind == "fleet":
            ps.fleet = pol
        elif scope_role is not None:
            ps.roles[scope_role] = pol
    return ps


def _policy_from_orm(p: FirewallPolicy) -> _Policy:
    rule_objs = tuple(
        _Rule(
            seq=r.seq,
            action=r.action,
            protocol=r.protocol,
            ports=tuple(int(x) for x in (r.ports or [])),
            source_kind=r.source_kind,
            source_cidrs=tuple(str(x) for x in (r.source_cidrs or [])),
            source_alias=r.source_alias,
            family=r.family,
            comment=r.comment,
            render_guard=dict(r.render_guard) if r.render_guard else None,
            enabled=r.enabled,
        )
        for r in sorted(p.rules, key=lambda r: r.seq)
    )
    return _Policy(
        scope_kind=p.scope_kind, scope_role=p.scope_role, enabled=p.enabled, rules=rule_objs
    )


def policy_set_from_orm(policies: list[FirewallPolicy], aliases: list[FirewallAlias]) -> PolicySet:
    """Detach ORM rows into a ``PolicySet`` (no lazy-load past this point)."""
    ps = PolicySet()
    for p in policies:
        pol = _policy_from_orm(p)
        if p.scope_kind == "fleet":
            ps.fleet = pol
        elif p.scope_kind == "role" and p.scope_role is not None:
            ps.roles[p.scope_role] = pol
        # appliance-scoped rows are loaded + threaded separately (per-node).
    for a in aliases:
        ps.aliases[a.name] = _Alias(
            name=a.name,
            v4_members=tuple(str(x) for x in (a.v4_members or [])),
            v6_members=tuple(str(x) for x in (a.v6_members or [])),
            port_members=tuple(int(x) for x in (a.port_members or [])),
        )
    return ps


# ── DB loader + short-TTL cache ───────────────────────────────────────
# The fleet + role policies + aliases are node-INDEPENDENT (the per-node
# bits come from the bundle args, not the cache), so one short-lived snapshot
# is shared across every heartbeat in the window. Only a non-empty DB result
# is cached — an unseeded DB renders from the in-code builtins UNcached so a
# fresh seed (or a 3c edit after reset_policy_cache) is picked up at once.
_CACHE_TTL = 5.0
_shared_cache: dict[str, Any] = {"at": -1e9, "ps": None}


def reset_policy_cache() -> None:
    """Drop the shared snapshot — called by the 3c CRUD path after any edit."""
    _shared_cache["at"] = -1e9
    _shared_cache["ps"] = None


async def load_policy_set(db: Any) -> PolicySet:
    import time

    now = time.monotonic()
    cached = _shared_cache["ps"]
    if cached is not None and (now - _shared_cache["at"]) < _CACHE_TTL:
        return cached

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models.firewall import FirewallAlias, FirewallPolicy

    rows = (
        (
            await db.execute(
                select(FirewallPolicy)
                .where(FirewallPolicy.scope_kind.in_(("fleet", "role")))
                .options(selectinload(FirewallPolicy.rules))
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return builtin_policy_set()  # unseeded — uncached
    aliases = (await db.execute(select(FirewallAlias))).scalars().all()
    ps = policy_set_from_orm(list(rows), list(aliases))
    _shared_cache["ps"] = ps
    _shared_cache["at"] = now
    return ps


async def load_appliance_policy(db: Any, appliance_id: Any) -> _Policy | None:
    """The per-appliance override policy (uncached — one indexed lookup)."""
    if appliance_id is None:
        return None
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models.firewall import FirewallPolicy

    row = (
        (
            await db.execute(
                select(FirewallPolicy)
                .where(
                    FirewallPolicy.scope_kind == "appliance",
                    FirewallPolicy.scope_appliance_id == appliance_id,
                )
                .options(selectinload(FirewallPolicy.rules))
            )
        )
        .scalars()
        .first()
    )
    return _policy_from_orm(row) if row is not None else None


# ── Merge context — the per-node derived-source resolver ──────────────


@dataclass(frozen=True)
class MergeContext:
    roles: tuple[str, ...]
    profile: str
    is_cp: bool
    cp_member_count: int
    vip_configured: bool
    # Validated + family-split derived scopes.
    peer_v4: tuple[str, ...]
    peer_v6: tuple[str, ...]
    pod_v4: tuple[str, ...]
    pod_v6: tuple[str, ...]
    svc_v4: tuple[str, ...]
    svc_v6: tuple[str, ...]
    kubeapi_v4: tuple[str, ...]
    kubeapi_v6: tuple[str, ...]
    # #993 — pod ∪ service, WITHOUT the operator's kubeapi_expose allowlist.
    # That allowlist widens the apiserver, which is RBAC-guarded on every
    # request; the kubelet API is not the same proposition and must not
    # inherit it.
    kubelet_v4: tuple[str, ...]
    kubelet_v6: tuple[str, ...]
    mgmt_v4: tuple[str, ...]
    mgmt_v6: tuple[str, ...]
    vip_v4: tuple[str, ...]
    vip_v6: tuple[str, ...]
    aliases: dict[str, _Alias]

    @classmethod
    def build(
        cls,
        role_assignment: dict[str, Any] | None,
        cluster_peer_cidrs: list[Any] | None,
        *,
        pod_cidrs: list[Any] | None,
        service_cidrs: list[Any] | None,
        cp_member_count: int,
        vip_configured: bool,
        mgmt_cidrs: list[Any] | None = None,
        vip_cidrs: list[Any] | None = None,
        aliases: dict[str, _Alias] | None = None,
    ) -> MergeContext:
        ra = role_assignment or {}
        roles = tuple(r for r in (ra.get("roles") or []) if isinstance(r, str))
        kubeapi_cidrs = ra.get("kubeapi_expose_cidrs") or []

        peer_v4, peer_v6 = _split_families(list(cluster_peer_cidrs or []))
        pod_v4, pod_v6 = _split_families(list(pod_cidrs or []))
        svc_v4, svc_v6 = _split_families(list(service_cidrs or []))
        # Trap 1: is_cp keys off the RAW lists; the union below uses split.
        raw_pod_nonempty = bool(pod_cidrs)
        raw_svc_nonempty = bool(service_cidrs)
        is_cp = bool(peer_v4 or peer_v6) or raw_pod_nonempty or raw_svc_nonempty
        # The 6443 union — exactly the legacy concat, then split.
        api_v4, api_v6 = _split_families(
            list(cluster_peer_cidrs or [])
            + list(pod_cidrs or [])
            + list(service_cidrs or [])
            + list(kubeapi_cidrs)
        )
        # #993 — pod ∪ svc only; see the note on MergeContext.kubelet_v4.
        kubelet_v4, kubelet_v6 = _split_families(list(pod_cidrs or []) + list(service_cidrs or []))
        mgmt_v4, mgmt_v6 = _split_families(list(mgmt_cidrs or []))
        vv4, vv6 = _split_families(list(vip_cidrs or []))
        return cls(
            roles=roles,
            profile=_profile_name(list(roles)),
            is_cp=is_cp,
            cp_member_count=cp_member_count,
            vip_configured=vip_configured,
            peer_v4=tuple(peer_v4),
            peer_v6=tuple(peer_v6),
            pod_v4=tuple(pod_v4),
            pod_v6=tuple(pod_v6),
            svc_v4=tuple(svc_v4),
            svc_v6=tuple(svc_v6),
            kubeapi_v4=tuple(api_v4),
            kubeapi_v6=tuple(api_v6),
            kubelet_v4=tuple(kubelet_v4),
            kubelet_v6=tuple(kubelet_v6),
            mgmt_v4=tuple(mgmt_v4),
            mgmt_v6=tuple(mgmt_v6),
            vip_v4=tuple(vv4),
            vip_v6=tuple(vv6),
            aliases=aliases or {},
        )

    def resolve_source(self, rule: _Rule) -> tuple[list[str], list[str]]:
        """Resolve a rule's source_kind to (v4, v6) saddr lists, family-filtered.

        ``any`` returns ([], []) — the caller emits a bare (no-saddr) rule.
        """
        sk = rule.source_kind
        if sk == "cluster_peers":
            v4, v6 = list(self.peer_v4), list(self.peer_v6)
        elif sk == "kubeapi":
            v4, v6 = list(self.kubeapi_v4), list(self.kubeapi_v6)
        elif sk == "kubelet":
            v4, v6 = list(self.kubelet_v4), list(self.kubelet_v6)
        elif sk == "pod_cidr":
            v4, v6 = list(self.pod_v4), list(self.pod_v6)
        elif sk == "service_cidr":
            v4, v6 = list(self.svc_v4), list(self.svc_v6)
        elif sk == "mgmt":
            v4, v6 = list(self.mgmt_v4), list(self.mgmt_v6)
        elif sk == "vip":
            v4, v6 = list(self.vip_v4), list(self.vip_v6)
        elif sk == "cidr":
            v4l, v6l = _split_families(list(rule.source_cidrs))
            v4, v6 = v4l, v6l
        elif sk == "alias":
            al = self.aliases.get(rule.source_alias or "")
            if al is None:
                log.warning("firewall.merge.unknown_alias", alias=rule.source_alias)
                v4, v6 = [], []
            else:
                v4s, v6s = _split_families(list(al.v4_members) + list(al.v6_members))
                v4, v6 = v4s, v6s
        else:  # "any"
            return [], []
        if rule.family == "v4":
            v6 = []
        elif rule.family == "v6":
            v4 = []
        return v4, v6


def _guard_ok(guard: dict[str, Any] | None, ctx: MergeContext) -> bool:
    if not guard:
        return True
    min_cp = guard.get("min_cp_members")
    if min_cp is not None and ctx.cp_member_count < int(min_cp):
        return False
    if guard.get("requires_vip") and not ctx.vip_configured:
        return False
    return True


def _portset(ports: tuple[int, ...] | list[int]) -> str:
    """``(53,)`` → ``53``; ``(2379, 2380, 10250)`` → ``{ 2379, 2380, 10250 }``.

    Order-preserving (the legacy renderer never sorts the control-plane port
    tuple; the role-ports section sorts at the set level before calling this
    per single port)."""
    ps = [int(p) for p in ports]
    if len(ps) == 1:
        return str(ps[0])
    return "{ " + ", ".join(str(p) for p in ps) + " }"


# ── The compiler ──────────────────────────────────────────────────────


def compile_firewall_from_policies(
    role_assignment: dict[str, Any] | None,
    cluster_peer_cidrs: list[Any] | None = None,
    *,
    pod_cidrs: list[Any] | None = None,
    service_cidrs: list[Any] | None = None,
    cp_member_count: int = 1,
    vip_configured: bool = False,
    policy_set: PolicySet | None = None,
    appliance_policy: _Policy | None = None,
    mgmt_cidrs: list[Any] | None = None,
    vip_cidrs: list[Any] | None = None,
    web_ui_allowed_cidrs: list[Any] | None = None,
    ssh_scope_cidrs: list[Any] | None = None,
) -> str:
    """Render the drop-in body from the policy model. Fed ``builtin_policy_set``
    + no operator overlay, this is byte-identical to ``compile_firewall_body``.
    """
    ps = policy_set or builtin_policy_set()
    ctx = MergeContext.build(
        role_assignment,
        cluster_peer_cidrs,
        pod_cidrs=pod_cidrs,
        service_cidrs=service_cidrs,
        cp_member_count=cp_member_count,
        vip_configured=vip_configured,
        mgmt_cidrs=mgmt_cidrs,
        vip_cidrs=vip_cidrs,
        aliases=ps.aliases,
    )
    ra = role_assignment or {}
    firewall_extra = ra.get("firewall_extra") or ""

    lines: list[str] = []
    # Header — byte-identical to the legacy renderer.
    lines.append(
        "# Auto-generated by spatium-supervisor — do not hand-edit. "
        "See /etc/spatiumddi/firewall-extra on the host (or the fleet UI)"
    )
    lines.append("# for the operator-override surface that lands at the end of this file.")
    lines.append(f"# profile: {ctx.profile}")
    lines.append(f"# roles: {','.join(ctx.roles) if ctx.roles else '(idle)'}")
    bootstrap_action = "retire" if ctx.cp_member_count >= 2 else "keep"
    lines.append(f"# spatium-bootstrap: {bootstrap_action}")
    # #769 — retire the baked Web-UI sentinel (00-spatium-webui.nft) once a
    # source scope is configured; its unconditional accept sorts earlier in
    # the include glob and would otherwise defeat the scoped rule below.
    # Byte-identical to compile_firewall_body + render_drop_in.
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
        lines.append(_MGMT_FLOOR[0])
    lines.extend(_MGMT_FLOOR[1:])
    # Web UI (HTTP + HTTPS) — #285 Phase 6. Open by default; source-scoped when
    # web_ui_allowed_cidrs is set (the base /etc/nftables.conf no longer opens
    # 80/443). Byte-identical to compile_firewall_body + render_drop_in.
    if web_ui_allowed_cidrs:
        web_v4, web_v6 = _split_families(list(web_ui_allowed_cidrs))
        _emit_family_rule(lines, web_v4, web_v6, "tcp dport { 80, 443 } accept", "web-ui")
    else:
        lines.append('tcp dport { 80, 443 } accept comment "web-ui"')

    # ── Per-role service ports (STRUCTURAL emit, byte-identical). ──
    # Collect the node's declared roles' "any"-source accept ports; emit one
    # bare line per port, udp then tcp, sorted — the role:{profile} comment
    # is per-node (the seeded role rules carry NULL comments by design).
    role_tcp: set[int] = set()
    role_udp: set[int] = set()
    for role in ctx.roles:
        pol = ps.roles.get(role)
        if pol is None or not pol.enabled:
            continue
        for r in pol.rules:
            if not r.enabled or r.action != "accept" or r.source_kind != "any":
                continue
            if r.protocol == "udp":
                role_udp.update(r.ports)
            elif r.protocol == "tcp":
                role_tcp.update(r.ports)
    # Issue #50 — DoT / DoH listen on operator-chosen ports, so they can't be
    # seeded as policy rules the way Do53's fixed 53 is. The control plane
    # derives them from the assigned DNS group's options and ships them on the
    # role assignment. Keep byte-identical to ``firewall.compile_firewall_body``
    # + the supervisor's ``firewall_renderer.render_drop_in``.
    if any(r in ctx.roles for r in ("dns-bind9", "dns-powerdns", "dns-technitium")):
        for raw in ra.get("dns_encrypted_tcp_ports") or []:
            try:
                port = int(raw)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                role_tcp.add(port)
        # #741 — DoQ is UDP. Same operator-chosen shape, different table:
        # adding it to role_tcp would leave the listener unreachable while
        # the rendered ruleset looked correct.
        for raw in ra.get("dns_encrypted_udp_ports") or []:
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
        lines.append(f'udp dport {port} accept comment "role:{ctx.profile}"')
    for port in sorted(role_tcp):
        lines.append(f'tcp dport {port} accept comment "role:{ctx.profile}"')

    # ── Control-plane derived (STRUCTURAL emit, byte-identical). ──
    if ctx.is_cp:
        lines.append("")
        lines.append("# ── Control-plane derived (peer-scoped, #272/#285) ─────")
        cp_pol = ps.roles.get("control-plane")
        if cp_pol is not None and cp_pol.enabled:
            for r in cp_pol.rules:
                if not r.enabled or not _guard_ok(r.render_guard, ctx):
                    continue
                v4, v6 = ctx.resolve_source(r)
                suffix = f"{r.protocol} dport {_portset(r.ports)} {r.action}"
                _emit_family_rule(lines, v4, v6, suffix, r.comment or r.source_kind)

    # ── Operator overlay (fleet + appliance) — generic pipeline. ──
    # Empty in the default fleet (preserves byte-identity); when an operator
    # authors rules they land here, between the builtins and firewall_extra.
    overlay = _compile_overlay(ps.fleet, appliance_policy, ctx)
    if overlay:
        lines.append("")
        lines.append("# ── Fleet / appliance overlay ──────────────────────────")
        lines.extend(overlay)

    # ── firewall_extra verbatim (byte-identical tail). ──
    if firewall_extra.strip():
        lines.append("")
        lines.append("# ── Operator override (firewall_extra) ─────────────────")
        lines.append(firewall_extra.rstrip("\n"))

    return "\n".join(lines) + "\n"


def _compile_overlay(
    fleet_policy: _Policy | None,
    appliance_policy: _Policy | None,
    ctx: MergeContext,
) -> list[str]:
    """Explode → deny-wins → source-union for operator-authored rules.

    nft is first-match-wins, so DROP rules emit before ACCEPT rules. Rules
    sharing (action, protocol, ports, comment) union their resolved CIDR
    sources into one nft set per family. ``any``-source rules emit bare.
    """
    collected: list[_Rule] = []
    for pol in (fleet_policy, appliance_policy):
        if pol is None or not pol.enabled:
            continue
        collected.extend(r for r in pol.rules if r.enabled)
    if not collected:
        return []

    # group key → {v4, v6, any}; preserve first-seen order, drops sorted first.
    groups: dict[tuple, dict[str, Any]] = {}
    order: list[tuple] = []
    for r in collected:
        portset = _portset(tuple(sorted(int(p) for p in r.ports))) if r.ports else ""
        key = (r.action, r.protocol, portset, r.comment or "")
        if key not in groups:
            groups[key] = {"v4": set(), "v6": set(), "any": False}
            order.append(key)
        if r.source_kind == "any":
            groups[key]["any"] = True
        else:
            v4, v6 = ctx.resolve_source(r)
            groups[key]["v4"].update(v4)
            groups[key]["v6"].update(v6)

    order.sort(key=lambda k: 0 if k[0] == "drop" else 1)  # stable → deny-wins
    lines: list[str] = []
    for key in order:
        action, proto, portset, comment = key
        g = groups[key]
        dport = f" dport {portset}" if portset else ""
        if g["any"] or (not g["v4"] and not g["v6"]):
            c = f' comment "{comment}"' if comment else ""
            lines.append(f"{proto}{dport} {action}{c}")
        else:
            _emit_family_rule(
                lines,
                sorted(g["v4"]),
                sorted(g["v6"]),
                f"{proto}{dport} {action}",
                comment or proto,
            )
    return lines


__all__ = [
    "MergeContext",
    "PolicySet",
    "builtin_policy_set",
    "compile_firewall_from_policies",
    "load_appliance_policy",
    "load_policy_set",
    "policy_set_from_orm",
    "reset_policy_cache",
]
