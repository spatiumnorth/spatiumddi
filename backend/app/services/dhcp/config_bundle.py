"""Assemble a neutral ``ConfigBundle`` for a DHCP server.

Scopes + client classes live on ``DHCPServerGroup`` — every server in
a group renders the same config. HA tuning also lives on the group;
a group with ≥ 2 Kea members emits a ``FailoverConfig`` (the first two
sorted members are the primary + secondary/standby partners, any 3rd+
members are ``backup`` peers), a single-member group is standalone and
doesn't. Peer URLs are per-server (``DHCPServer.ha_peer_url``) — Kea
uses them to reach the other peers for heartbeats + lease updates.

Mirrors ``app.services.dns.config_bundle``.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.drivers.dhcp.base import (
    ClientClassDef,
    ConfigBundle,
    DevicePolicyClassDef,
    FailoverConfig,
    MACBlockDef,
    PhoneClassDef,
    PoolDef,
    PXEClassDef,
    RAConfigDef,
    ScopeDef,
    ServerOptionsDef,
    StaticAssignmentDef,
)
from app.models.dhcp import (
    DHCPClientClass,
    DHCPMACBlock,
    DHCPPhoneProfile,
    DHCPPhoneProfileScope,
    DHCPPXEArchMatch,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
)
from app.models.dhcp_device_policy import DHCPDevicePolicy
from app.models.ipam import Subnet
from app.services.dhcp.device_policy import (
    compile_device_policy,
    load_fingerprint_snapshot,
)
from app.services.dhcp.radvd import build_ra_config, render_radvd_conf, resolve_dnssl
from app.services.e911 import effective_subnet_erls
from app.services.e911.dhcp_options import kea_option_data
from app.services.feature_modules import is_module_enabled

log = structlog.get_logger(__name__)

# #844 — log-dedupe for the duplicate-prefix drop below (see comment at the
# call site). Log suppression only — never consulted for logic.
_dup_prefix_logged: set[tuple[str, str]] = set()


async def _resolve_failover(
    db: AsyncSession, server: DHCPServer, group: DHCPServerGroup | None
) -> FailoverConfig | None:
    """Return the FailoverConfig for ``server`` if its group is an HA group.

    An HA group is a DHCPServerGroup with >= 2 Kea members. The
    ``peers`` array carries an entry for *every* Kea member regardless
    of this server's role; ``this_server_name`` tells Kea which one is
    "us". Non-Kea servers in the group (e.g. Windows DHCP read-only)
    are ignored for HA purposes — Kea HA only speaks to Kea.

    Kea's ``libdhcp_ha.so`` requires ``this-server-name`` to match an
    entry in the ``peers`` array. The first sorted Kea member plays the
    ``primary`` role, the second plays ``secondary`` (load-balancing) /
    ``standby`` (hot-standby), and every additional member (3rd, 4th, …)
    plays the ``backup`` role. Backup servers don't partner in the
    heartbeat but receive lease updates — this keeps a group's 3rd+
    member valid instead of rendering a config whose own name is absent
    from its 2-entry peers list (issue #332).

    Peer URLs come from ``DHCPServer.ha_peer_url`` on each member.
    An empty peer URL on any Kea member suppresses HA rendering for the
    whole group (the operator hasn't finished setting things up yet).
    """
    if group is None:
        return None
    kea_peers = [s for s in group.servers if s.driver == "kea"]
    if len(kea_peers) < 2:
        return None
    # Stable ordering so every member renders the same peers array
    # regardless of which server is asking for its bundle. Sort by id
    # (UUID) — the concept of "primary" in a group is not a model field
    # today; whichever Kea peer ends up first in the sort plays the
    # ``primary`` role, the second ``secondary``/``standby``, the rest
    # ``backup``.
    kea_peers.sort(key=lambda s: str(s.id))

    # Every Kea member needs a peer URL — an HA peer with no URL can't be
    # reached for heartbeats or lease updates, so the group isn't ready.
    if any(not s.ha_peer_url for s in kea_peers):
        return None

    secondary_role = "standby" if group.mode == "hot-standby" else "secondary"
    peers: list[dict] = []
    for index, peer in enumerate(kea_peers):
        if index == 0:
            role = "primary"
        elif index == 1:
            role = secondary_role
        else:
            role = "backup"
        peers.append(
            {
                "name": peer.name,
                "url": peer.ha_peer_url,
                "role": role,
                "auto-failover": group.auto_failover,
            }
        )
    return FailoverConfig(
        channel_id=str(group.id),
        channel_name=group.name,
        mode=group.mode,
        this_server_name=server.name,
        peers=tuple(peers),
        heartbeat_delay_ms=group.heartbeat_delay_ms,
        max_response_delay_ms=group.max_response_delay_ms,
        max_ack_delay_ms=group.max_ack_delay_ms,
        max_unacked_clients=group.max_unacked_clients,
    )


async def build_config_bundle(db: AsyncSession, server: DHCPServer) -> ConfigBundle:
    """Build a fully-populated ``ConfigBundle`` for the given DHCP server."""
    # Resolve the server's group. Groupless servers are allowed but render
    # an empty bundle (no scopes, no HA) — the server is registered but
    # not yet attached to a logical service.
    group: DHCPServerGroup | None = None
    if server.server_group_id is not None:
        group = (
            await db.execute(
                select(DHCPServerGroup)
                .where(DHCPServerGroup.id == server.server_group_id)
                .options(selectinload(DHCPServerGroup.servers))
            )
        ).scalar_one_or_none()

    scope_rows: list[DHCPScope] = []
    cc_rows: list[DHCPClientClass] = []
    mb_rows: list[DHCPMACBlock] = []
    if group is not None:
        scope_rows = list(
            (
                await db.execute(
                    select(DHCPScope)
                    .where(
                        DHCPScope.group_id == group.id,
                        DHCPScope.is_active.is_(True),
                    )
                    .options(
                        # Soft-deleted pools / reservations cannot reach the
                        # bundle: these are selectin-loaded, so the global
                        # deleted_at filter applies to each child statement in its
                        # own right (see the note on DHCPScope.pools, #617).
                        selectinload(DHCPScope.pools),
                        selectinload(DHCPScope.statics),
                    )
                )
            )
            .scalars()
            .all()
        )
        cc_rows = list(
            (await db.execute(select(DHCPClientClass).where(DHCPClientClass.group_id == group.id)))
            .scalars()
            .all()
        )
        # MAC blocks: group-global, enabled + not expired only. Expired
        # rows stay in the DB for history but are stripped from the
        # bundle so a re-render naturally drops them from the live
        # config — the expiry beat task just forces the re-push.
        now = datetime.now(UTC)
        mb_rows = list(
            (
                await db.execute(
                    select(DHCPMACBlock)
                    .where(
                        DHCPMACBlock.group_id == group.id,
                        DHCPMACBlock.enabled.is_(True),
                        or_(
                            DHCPMACBlock.expires_at.is_(None),
                            DHCPMACBlock.expires_at > now,
                        ),
                    )
                    .order_by(DHCPMACBlock.mac_address)
                )
            )
            .scalars()
            .all()
        )

    # Pre-fetch subnet CIDRs
    subnet_ids = [s.subnet_id for s in scope_rows]
    subnet_map: dict = {}
    if subnet_ids:
        res = await db.execute(select(Subnet).where(Subnet.id.in_(subnet_ids)))
        for s in res.scalars().all():
            subnet_map[s.id] = s

    # #844 belt-and-braces: IPAM allows the same CIDR in different IP spaces,
    # and if two such subnets both carry an active scope in this group the
    # rendered config holds two identical subnet4/subnet6 entries — Kea
    # rejects the WHOLE config at load, taking down every scope on the
    # server. Overlapping-but-unequal prefixes (a subnet resize can produce
    # them — resize has no scope-aware guard) are dropped too, so the last
    # line of defense is at least as wide as the API guard. The API refuses
    # new collisions (create/activate 409 in scopes.py); this keeps a
    # pre-existing or raced-in collision from reaching agents: ship the
    # oldest scope per overlap cluster, drop the rest, and log so the
    # operator sees which subnet isn't being served.
    kept_nets: list[tuple[DHCPScope, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    dropped: list[tuple[DHCPScope, DHCPScope]] = []
    # Oldest row wins — deterministic across rebuilds, and the newer scope
    # is the one that slipped in against the API guard.
    for sc in sorted(
        scope_rows,
        key=lambda s: (s.created_at or datetime.max.replace(tzinfo=UTC), str(s.id)),
    ):
        subnet = subnet_map.get(sc.subnet_id)
        if subnet is None or not subnet.network:
            continue
        try:
            net = ipaddress.ip_network(str(subnet.network), strict=False)
        except ValueError:
            continue
        winner = next(
            (k for k, knet in kept_nets if knet.version == net.version and knet.overlaps(net)),
            None,
        )
        if winner is None:
            kept_nets.append((sc, net))
        else:
            dropped.append((sc, winner))
    if dropped:
        for sc, winner in dropped:
            # This runs inside the agent /config long-poll loop, so an
            # unfixed pre-existing collision would emit ERROR every wake /
            # safety tick forever. Error once per pair per process, then
            # demote to debug. Log suppression only — never drives logic.
            key = (str(sc.id), str(winner.id))
            log_fn = log.debug if key in _dup_prefix_logged else log.error
            _dup_prefix_logged.add(key)
            log_fn(
                "dhcp_bundle_duplicate_prefix_dropped",
                group_id=str(group.id) if group else None,
                scope_id=str(sc.id),
                subnet_id=str(sc.subnet_id),
                prefix=str(subnet_map[sc.subnet_id].network),
                kept_scope_id=str(winner.id),
                note="duplicate/overlapping prefix would make Kea reject " "the whole config",
            )
        dropped_ids = {sc.id for sc, _ in dropped}
        scope_rows = [sc for sc in scope_rows if sc.id not in dropped_ids]

    # #972 Phase 2 — one lookup for every scope's subnet, before the loop.
    #
    # Gated on the feature module: without it, disabling `network.e911` would
    # hide every surface for inspecting bindings while the scopes kept shipping
    # the options, which is the worst of both. The RA feature in this same
    # function gates the same way.
    #
    # Batched because this runs inside the agent /config long-poll: three
    # queries per scope is 600 round trips on a 200-scope server that has no
    # ERL bindings at all.
    location_erls: dict[uuid.UUID, Any] = {}
    if await is_module_enabled(db, "network.e911"):
        try:
            location_erls = await effective_subnet_erls(
                db,
                [subnet_map[sc.subnet_id] for sc in scope_rows if sc.subnet_id in subnet_map],
            )
        except Exception as exc:  # noqa: BLE001 — a location option is never
            # worth risking the lease service for.
            log.warning("dhcp_bundle_e911_lookup_failed", error=str(exc))

    scopes: list[ScopeDef] = []
    for sc in scope_rows:
        subnet = subnet_map.get(sc.subnet_id)
        if subnet is None:
            continue
        subnet_cidr = str(subnet.network) if subnet.network else ""
        pools = tuple(
            PoolDef(
                start_ip=str(p.start_ip),
                end_ip=str(p.end_ip),
                pool_type=p.pool_type,
                name=p.name or "",
                class_restriction=p.class_restriction,
                lease_time_override=p.lease_time_override,
                options_override=p.options_override or None,
                pd_prefix=getattr(p, "pd_prefix", None),
                delegated_length=getattr(p, "delegated_length", None),
                excluded_prefix=getattr(p, "excluded_prefix", None),
            )
            for p in sc.pools
        )
        statics = tuple(
            StaticAssignmentDef(
                ip_address=str(s.ip_address),
                mac_address=str(s.mac_address),
                hostname=s.hostname or "",
                client_id=s.client_id,
                options_override=s.options_override or None,
                duid=getattr(s, "duid", None),
            )
            for s in sc.statics
        )
        scopes.append(
            ScopeDef(
                subnet_cidr=subnet_cidr,
                lease_time=sc.lease_time,
                min_lease_time=sc.min_lease_time,
                max_lease_time=sc.max_lease_time,
                options=_with_v6_domain_search(
                    _with_location_options(
                        location_erls,
                        subnet,
                        dict(sc.options or {}),
                        address_family=getattr(sc, "address_family", "ipv4") or "ipv4",
                    ),
                    subnet,
                    address_family=getattr(sc, "address_family", "ipv4") or "ipv4",
                    v6_address_mode=getattr(sc, "v6_address_mode", "stateful") or "stateful",
                ),
                pools=pools,
                statics=statics,
                ddns_enabled=sc.ddns_enabled,
                ddns_hostname_policy=sc.ddns_hostname_policy,
                is_active=sc.is_active,
                address_family=getattr(sc, "address_family", "ipv4") or "ipv4",
                v6_address_mode=getattr(sc, "v6_address_mode", "stateful") or "stateful",
                relay_addresses=tuple(getattr(sc, "relay_addresses", None) or ()),
                # #637 — per-scope lease-cache override. NULL in the DB means
                # "inherit the group", so pass None through verbatim; 0.0 is a
                # real value (caching explicitly off) and must not be coalesced.
                lease_cache_threshold=getattr(sc, "lease_cache_threshold", None),
                lease_cache_max_age=getattr(sc, "lease_cache_max_age", None),
            )
        )

    client_classes = tuple(
        ClientClassDef(
            name=c.name,
            match_expression=c.match_expression or "",
            description=c.description or "",
            options=dict(c.options or {}),
        )
        for c in cc_rows
    )

    mac_blocks = tuple(
        MACBlockDef(
            mac_address=str(m.mac_address).lower(),
            reason=m.reason or "other",
            description=m.description or "",
        )
        for m in mb_rows
    )

    pxe_classes = await _assemble_pxe_classes(db, scope_rows)
    phone_classes = await _assemble_phone_classes(db, scope_rows)
    device_policy_classes = await _assemble_device_policy_classes(db, group.id if group else None)

    # IPv6 Router Advertisements (issue #524) — one radvd stanza per
    # RA-enabled IPv6 subnet in the group. The rendered radvd.conf ships in
    # the bundle for the DHCP agent to write + run radvd. Gated on the
    # ``ipv6.router_advertisements`` feature module (non-negotiable #14): when
    # the operator toggles the module off we ship an empty ra_configs /
    # radvd_conf so the ETag shifts and the agent stops radvd (feature goes
    # dormant) rather than continuing to advertise the last-good config.
    ra_configs: list[RAConfigDef] = []
    if await is_module_enabled(db, "ipv6.router_advertisements"):
        for sc in scope_rows:
            subnet = subnet_map.get(sc.subnet_id)
            if subnet is None:
                continue
            ra = build_ra_config(sc, subnet)
            if ra is not None:
                ra_configs.append(ra)
    radvd_conf = render_radvd_conf(ra_configs)

    failover = await _resolve_failover(db, server, group)
    # Issue #365 — Kea socket type. ``direct`` (default) → ``raw`` sockets
    # so Kea hears broadcast DISCOVERs from directly-attached clients;
    # ``relay`` → ``udp`` for relay-only deployments. Groupless servers
    # render an empty bundle anyway, but default them to ``raw`` too.
    socket_mode = getattr(group, "dhcp_socket_mode", "direct") if group else "direct"
    dhcp_socket_type = "udp" if socket_mode == "relay" else "raw"

    # Issue #637 — Kea lease cache, group-wide default. 0.0 (disabled) both when
    # there is no group and when the column is unset, so the 2.6 → 3.0 jump keeps
    # the old write-through behaviour instead of inheriting Kea 3.0's 0.25.
    #
    # Note the explicit ``is None`` test rather than ``or 0.0``: 0.0 is a REAL
    # value for this column (caching deliberately off), and every other layer is
    # written to distinguish it from "unset". A truthiness coalesce happens to be
    # harmless while the column is NOT NULL, but it would silently swallow a NULL
    # into 0.0 the moment it becomes nullable — breaking the one invariant this
    # feature's tests exist to protect.
    _group_threshold = getattr(group, "lease_cache_threshold", None) if group else None
    lease_cache_threshold = 0.0 if _group_threshold is None else float(_group_threshold)
    lease_cache_max_age = getattr(group, "lease_cache_max_age", None) if group else None

    # #980 — Kea packet-worker pool size. ``is None`` rather than ``or``: 0 is
    # a real value here (it means "let Kea auto-size"), so a truthiness
    # coalesce would silently rewrite the one setting an operator uses to opt
    # back out of this change into the default they were opting out of.
    _pool = getattr(group, "kea_thread_pool_size", None) if group else None
    kea_thread_pool_size = 1 if _pool is None else int(_pool)
    _pktlog = getattr(group, "kea_packet_logging", None) if group else None
    kea_packet_logging = True if _pktlog is None else bool(_pktlog)

    bundle = ConfigBundle(
        server_id=str(server.id),
        server_name=server.name,
        driver=server.driver,
        roles=tuple(server.roles or ()),
        options=ServerOptionsDef(options={}, lease_time=86400),
        scopes=tuple(scopes),
        client_classes=client_classes,
        mac_blocks=mac_blocks,
        pxe_classes=pxe_classes,
        phone_classes=phone_classes,
        device_policy_classes=device_policy_classes,
        generated_at=datetime.now(UTC),
        failover=failover,
        dhcp_socket_type=dhcp_socket_type,
        lease_cache_threshold=lease_cache_threshold,
        lease_cache_max_age=lease_cache_max_age,
        kea_thread_pool_size=kea_thread_pool_size,
        kea_packet_logging=kea_packet_logging,
        ra_configs=tuple(ra_configs),
        radvd_conf=radvd_conf,
    )
    bundle.etag = bundle.compute_etag()
    return bundle


def _build_pxe_match_expression(
    vendor_class_match: str | None, arch_codes: list[int] | None
) -> str:
    """Compose the Kea ``test`` expression for a PXE arch-match row.

    Rules:
      * vendor-class: ``substring(option[60].hex,0,N)=='<lit>'`` —
        Kea's ``hex`` repr is the raw bytes; option 60 carries
        ``PXEClient`` / ``iPXE`` / ``HTTPClient`` as plain ASCII so
        a substring compare is the right shape.
      * arch-code: ``option[93].hex == '0007'`` — option 93 is a
        2-byte big-endian unsigned int. We zero-pad to 4 hex chars.
        A list of arch codes joins with ``or``.
      * Both null = empty string (always-match — pair with low
        priority for a fallthrough).
      * Both set = ``(vendor_test) and (arch_test)``.
    """
    parts: list[str] = []
    if vendor_class_match:
        n = len(vendor_class_match)
        # Kea's `hex` for option 60 is the literal byte string.
        parts.append(f"substring(option[60].hex,0,{n})=='{vendor_class_match}'")
    if arch_codes:
        arch_or = " or ".join(f"option[93].hex == 0x{code:04X}" for code in arch_codes)
        if len(arch_codes) > 1:
            arch_or = f"({arch_or})"
        parts.append(arch_or)
    return " and ".join(parts)


async def _assemble_pxe_classes(
    db: AsyncSession, scope_rows: list[DHCPScope]
) -> tuple[PXEClassDef, ...]:
    """Walk every scope with a bound PXE profile and emit one class
    per arch-match. Disabled profiles render no classes.

    Class names are deterministic: ``pxe-{profile_id8}-{match_id8}``
    where the suffixes are the first 8 hex chars of each UUID. Stable
    across runs, unique across profiles.

    Sorted by (priority ASC, profile_id ASC, match_id ASC) so Kea's
    declared-order evaluation puts most-specific matches first when
    the operator orders priorities right.
    """
    profile_ids = {sc.pxe_profile_id for sc in scope_rows if sc.pxe_profile_id is not None}
    if not profile_ids:
        return ()

    matches = (
        (
            await db.execute(
                select(DHCPPXEArchMatch)
                .where(DHCPPXEArchMatch.profile_id.in_(profile_ids))
                .options(selectinload(DHCPPXEArchMatch.profile))
                .order_by(
                    DHCPPXEArchMatch.priority,
                    DHCPPXEArchMatch.profile_id,
                    DHCPPXEArchMatch.id,
                )
            )
        )
        .scalars()
        .all()
    )

    out: list[PXEClassDef] = []
    seen_names: set[str] = set()
    for m in matches:
        prof = m.profile
        if prof is None or not prof.enabled:
            continue
        name = f"pxe-{str(prof.id)[:8]}-{str(m.id)[:8]}"
        if name in seen_names:
            continue
        seen_names.add(name)
        out.append(
            PXEClassDef(
                name=name,
                match_expression=_build_pxe_match_expression(m.vendor_class_match, m.arch_codes),
                next_server=str(prof.next_server),
                boot_file_name=m.boot_filename,
                is_ipxe_chain=(m.match_kind == "ipxe_chain"),
            )
        )
    return tuple(out)


async def _assemble_phone_classes(
    db: AsyncSession, scope_rows: list[DHCPScope]
) -> tuple[PhoneClassDef, ...]:
    """Walk phone profiles attached to any of the bundle's scopes and
    emit one Kea client-class per enabled profile (issue #112).

    A phone profile attached to *any* scope drives lease-time options
    for matching clients group-wide — Kea evaluates classes globally.
    Per-subnet gating is intentionally not enforced in Phase 1; vendor
    fences are the primary scoping mechanism (a Polycom phone matches
    the Polycom class regardless of which voice VLAN it landed in).

    Class name: ``voip-{profile_id[:8]}``. Stable across runs so the
    bundle ETag doesn't churn on rebuild.
    """
    if not scope_rows:
        return ()
    scope_ids = [s.id for s in scope_rows]

    profile_ids_res = await db.execute(
        select(DHCPPhoneProfileScope.profile_id)
        .where(DHCPPhoneProfileScope.scope_id.in_(scope_ids))
        .distinct()
    )
    profile_ids = [row[0] for row in profile_ids_res.all()]
    if not profile_ids:
        return ()

    profiles_res = await db.execute(
        select(DHCPPhoneProfile)
        .where(DHCPPhoneProfile.id.in_(profile_ids))
        .order_by(DHCPPhoneProfile.name)
    )
    profiles = list(profiles_res.scalars().all())

    out: list[PhoneClassDef] = []
    for prof in profiles:
        if not prof.enabled:
            continue
        match_expr = ""
        if prof.vendor_class_match:
            n = len(prof.vendor_class_match)
            match_expr = f"substring(option[60].hex,0,{n})=='{prof.vendor_class_match}'"
        # Convert option_set list-of-dicts into Kea-flavoured option-data
        # keyed by option-name. The renderer in ``drivers/dhcp/kea.py``
        # walks the dict and falls back to ``code: <int>`` form when the
        # entry has no recognised name. Trailing options with empty
        # values get dropped so the class doesn't render an empty line.
        options: dict[str, str] = {}
        for opt in prof.option_set or []:
            name = opt.get("name") if isinstance(opt, dict) else None
            value = opt.get("value") if isinstance(opt, dict) else None
            code = opt.get("code") if isinstance(opt, dict) else None
            if not value:
                continue
            key = name or (f"code:{code}" if code else None)
            if not key:
                continue
            options[str(key)] = str(value)

        out.append(
            PhoneClassDef(
                name=f"voip-{str(prof.id)[:8]}",
                match_expression=match_expr,
                options=options,
            )
        )
    return tuple(out)


async def _assemble_device_policy_classes(
    db: AsyncSession, group_id: uuid.UUID | None
) -> tuple[DevicePolicyClassDef, ...]:
    """Compile each enabled device policy into a Kea client-class (#700).

    Two properties worth stating because both are load-bearing:

    **A policy that compiles to nothing is dropped, not emitted empty.**
    A Kea client-class with no ``test`` matches every packet, so shipping
    an empty expression would apply a quarantine option-set and lease time
    to the entire network. "Compiles to nothing" is the normal state for a
    freshly-created policy whose device classes have not been observed
    yet, so this is a routine path rather than an error one.

    **The expression depends on observed fingerprints, so the bundle
    changes without an operator edit.** That is the feature — a newly
    classified device joins the policy on its next renewal — but it means
    the ETag legitimately shifts when the fingerprint store grows. It is
    bounded by *distinct signatures*, not device count, so it settles once
    the estate has been seen; a fleet of 500 identical handsets adds one
    term, not 500.
    """
    if group_id is None:
        return ()
    rows = list(
        (
            await db.execute(
                select(DHCPDevicePolicy)
                .where(DHCPDevicePolicy.group_id == group_id)
                .order_by(DHCPDevicePolicy.priority, DHCPDevicePolicy.name)
            )
        )
        .scalars()
        .all()
    )
    enabled = [p for p in rows if p.enabled]
    if not enabled:
        return ()
    # One read of the fingerprint store for the whole group. This runs on
    # every agent long-poll tick, so a per-policy scan would multiply the
    # hottest read path in the subsystem by the policy count.
    snapshot = await load_fingerprint_snapshot(db)
    out: list[DevicePolicyClassDef] = []
    for policy in enabled:
        compiled = await compile_device_policy(db, policy, snapshot=snapshot)
        if not compiled.expression:
            log.info(
                "dhcp_device_policy_no_match",
                policy_id=str(policy.id),
                policy=policy.name,
                reason=compiled.source,
            )
            continue
        out.append(
            DevicePolicyClassDef(
                name=policy.class_name,
                match_expression=compiled.expression,
                options=dict(policy.options or {}),
                lease_time=policy.lease_time,
            )
        )
    return tuple(out)


__all__ = ["ConfigBundle", "build_config_bundle"]


def _with_v6_domain_search(
    options: dict[str, Any],
    subnet: Subnet,
    *,
    address_family: str,
    v6_address_mode: str,
) -> dict[str, Any]:
    """Default a DHCPv6 scope's domain-search list (option 24) the way the
    router advertisement's DNSSL already is (#1141).

    ``radvd.resolve_dnssl`` falls back from the scope's ``domain-search`` to
    its ``domain-name`` to the subnet's ``domain_name``; DHCPv6 had only the
    first, so a v6 client using stateful or stateless DHCPv6 got no search
    list from the server while the RA on the same link carried one. Using the
    same function means the two can never disagree about what the list is.

    A scope that sets ``domain-search`` itself — under either key spelling
    the renderers accept — keeps it untouched. ``slaac`` scopes render no
    option-data at all, so nothing is added there (and the bundle stays
    byte-identical for them).
    """
    if address_family != "ipv6" or v6_address_mode == "slaac":
        return options
    if options.get("domain-search") or options.get("domain_search"):
        return options
    search = resolve_dnssl(options, getattr(subnet, "domain_name", None))
    if not search:
        return options
    return {**options, "domain-search": search}


def _with_location_options(
    location_erls: dict[uuid.UUID, Any],
    subnet: Subnet,
    options: dict[str, Any],
    *,
    address_family: str,
) -> dict[str, Any]:
    """Merge the #972 DHCP location options into a scope's option mapping.

    A phone that supports RFC 4776 / RFC 6225 learns its own civic address at
    lease time, with no HELD exchange and no LLDP-MED. Rendered per SCOPE,
    which is the floor-level answer — DHCP cannot know the room.

    **IPv4 only, and that is a correctness gate rather than a limitation.**
    Options 99 and 123 are DHCPv4 codes in the ``dhcp4`` option space; the v6
    equivalents are 36 and 63 and are not implemented. Emitting these into a
    ``Dhcp6`` scope is not a harmless no-op — the agent's v6 renderer passes
    the raw passthrough through verbatim and kea-dhcp6 then rejects the WHOLE
    config, which is the "DHCP stops for every client" outcome this feature is
    otherwise careful to avoid. An ERL reached by a ``vlan`` or
    ``site_default`` binding applies to both families, so that case is real
    rather than hypothetical.

    Otherwise: additive and append-only (phone profiles and the importers use
    the same raw passthrough, so this never displaces an operator's option),
    and silent when there is nothing to say, so the rendered config stays
    byte-identical to one without the feature and an unchanged bundle never
    triggers a spurious Kea reload.
    """
    if address_family != "ipv4":
        return options
    erl = location_erls.get(subnet.id)
    if erl is None:
        return options
    entries = kea_option_data(erl)
    if not entries:
        return options
    existing = options.get("option_data")
    merged = list(existing) if isinstance(existing, list) else []
    merged.extend(entries)
    return {**options, "option_data": merged}
