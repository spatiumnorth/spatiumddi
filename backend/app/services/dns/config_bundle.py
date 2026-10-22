"""Assemble a neutral ``ConfigBundle`` for a DNS server.

The bundle is the canonical, driver-agnostic projection of DB state that the
agent long-poll endpoint returns. Drivers consume it for rendering.

The bundle type is re-exported from ``app.drivers.dns.base`` so both this
module and the driver layer share the exact same definition. See
``docs/deployment/DNS_AGENT.md`` §3 and CLAUDE.md non-negotiables #5 and #10.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.drivers.dns.base import (
    AclData,
    BlocklistEntry,
    ConfigBundle,
    DNSSECPolicyData,
    EffectiveBlocklistData,
    RecordData,
    ServerOptions,
    TrustAnchorData,
    TsigKey,
    UpdateAclEntry,
    ViewData,
    ZoneData,
)
from app.models.dns import (
    DEFAULT_ALLOW_RECURSION,
    DNSAcl,
    DNSRecord,
    DNSSECPolicy,
    DNSServer,
    DNSServerOptions,
    DNSView,
    DNSZone,
    DNSZoneUpdateAcl,
)
from app.services.dns.pool_geo import (
    build_geo_steering,
    build_view_descriptors,
    records_for_view,
)
from app.services.dns_blocklist import (
    EffectiveBlocklist,
    build_effective_for_group,
    build_effective_for_view,
)


def _tuple_or_none(v: list | None) -> tuple[str, ...] | None:
    if v is None:
        return None
    return tuple(str(x) for x in v)


def _to_blocklist_data(
    eff: EffectiveBlocklist, rpz_name: str, view_name: str | None = None
) -> EffectiveBlocklistData:
    return EffectiveBlocklistData(
        rpz_zone_name=rpz_name,
        view_name=view_name,
        entries=tuple(
            BlocklistEntry(
                domain=e.domain,
                action=e.action,
                block_mode=e.block_mode,
                sinkhole_ip=e.sinkhole_ip,
                target=e.target,
                is_wildcard=e.is_wildcard,
            )
            for e in eff.entries
        ),
        exceptions=frozenset(eff.exceptions),
    )


async def build_config_bundle(db: AsyncSession, server: DNSServer) -> ConfigBundle:
    """Build a fully-populated ``ConfigBundle`` for the given server."""
    # Options (group-level)
    opts_row = (
        await db.execute(
            select(DNSServerOptions)
            .where(DNSServerOptions.group_id == server.group_id)
            .options(selectinload(DNSServerOptions.trust_anchors))
        )
    ).scalar_one_or_none()

    if opts_row is None:
        options = ServerOptions()
    else:
        options = ServerOptions(
            forwarders=tuple(opts_row.forwarders or ()),
            forward_policy=opts_row.forward_policy,
            recursion_enabled=opts_row.recursion_enabled,
            allow_recursion=tuple(
                DEFAULT_ALLOW_RECURSION
                if opts_row.allow_recursion is None
                else opts_row.allow_recursion
            ),
            dnssec_validation=opts_row.dnssec_validation,
            notify_enabled=opts_row.notify_enabled,
            also_notify=tuple(opts_row.also_notify or ()),
            allow_notify=tuple(opts_row.allow_notify or ()),
            allow_query=tuple(opts_row.allow_query or ("any",)),
            allow_query_cache=tuple(opts_row.allow_query_cache or ("localhost", "localnets")),
            allow_transfer=tuple(opts_row.allow_transfer or ("none",)),
            blackhole=tuple(opts_row.blackhole or ()),
            query_log_enabled=opts_row.query_log_enabled,
            response_log_enabled=opts_row.response_log_enabled,
            query_log_channel=opts_row.query_log_channel,
            query_log_file=opts_row.query_log_file,
            query_log_severity=opts_row.query_log_severity,
            query_log_print_category=opts_row.query_log_print_category,
            query_log_print_severity=opts_row.query_log_print_severity,
            query_log_print_time=opts_row.query_log_print_time,
            rrl_enabled=opts_row.rrl_enabled,
            rrl_responses_per_second=opts_row.rrl_responses_per_second,
            rrl_window=opts_row.rrl_window,
            rrl_slip=opts_row.rrl_slip,
            rrl_qps_scale=opts_row.rrl_qps_scale,
            rrl_exempt_clients=tuple(opts_row.rrl_exempt_clients or ()),
            rrl_log_only=opts_row.rrl_log_only,
            minimal_responses=opts_row.minimal_responses,
            tcp_clients=opts_row.tcp_clients,
            clients_per_query=opts_row.clients_per_query,
            max_clients_per_query=opts_row.max_clients_per_query,
            dnsdist_enabled=opts_row.dnsdist_enabled,
            dnsdist_max_qps_per_client=opts_row.dnsdist_max_qps_per_client,
            dnsdist_action=opts_row.dnsdist_action,
            dnsdist_dynblock_qps=opts_row.dnsdist_dynblock_qps,
            dnsdist_dynblock_seconds=opts_row.dnsdist_dynblock_seconds,
            dot_enabled=opts_row.dot_enabled,
            dot_port=opts_row.dot_port,
            doh_enabled=opts_row.doh_enabled,
            doh_port=opts_row.doh_port,
            doh_path=opts_row.doh_path,
            forward_transport=opts_row.forward_transport,
            forward_tls_hostname=opts_row.forward_tls_hostname,
            forward_tls_verify=opts_row.forward_tls_verify,
            trust_anchors=tuple(
                TrustAnchorData(
                    zone_name=ta.zone_name,
                    algorithm=ta.algorithm,
                    key_tag=ta.key_tag,
                    public_key=ta.public_key,
                    is_initial_key=ta.is_initial_key,
                )
                for ta in (opts_row.trust_anchors or ())
            ),
        )

    # ACLs
    acls_rows = (
        (
            await db.execute(
                select(DNSAcl)
                .where(DNSAcl.group_id == server.group_id)
                .options(selectinload(DNSAcl.entries))
            )
        )
        .scalars()
        .all()
    )
    acls = tuple(
        AclData(
            name=a.name,
            entries=tuple(
                (e.value, bool(e.negate)) for e in sorted(a.entries, key=lambda x: x.order)
            ),
        )
        for a in acls_rows
    )

    # Views
    view_rows = (
        (await db.execute(select(DNSView).where(DNSView.group_id == server.group_id)))
        .scalars()
        .all()
    )
    # Geo / topology-aware steering (issue #530). Synthesized geo views
    # render BEFORE operator split-horizon views, with a catch-all last
    # (see ``build_view_descriptors``). Build the unified descriptor list
    # once and derive both the ViewData tuple (for the named.conf ``view``
    # blocks) and the per-view zone record scoping from it.
    ordered_view_rows = sorted(view_rows, key=lambda v: (v.order, v.name))
    geo = await build_geo_steering(db, server.group_id)
    view_descs = build_view_descriptors(ordered_view_rows, geo)
    views = tuple(
        ViewData(
            name=vd["name"],
            match_clients=tuple(vd["match_clients"]),
            match_destinations=tuple(vd["match_destinations"]),
            recursion=vd["recursion"],
            order=vd["order"],
        )
        for vd in view_descs
    )

    # Zones + records
    zone_rows = (
        (
            await db.execute(
                select(DNSZone)
                .where(DNSZone.group_id == server.group_id)
                .options(
                    selectinload(DNSZone.records),
                    selectinload(DNSZone.update_acl_entries).selectinload(
                        DNSZoneUpdateAcl.tsig_key
                    ),
                )
            )
        )
        .scalars()
        .all()
    )

    # Views mode is on when the group has operator split-horizon views OR
    # any synthesized geo view (issue #530).
    has_views = bool(view_rows) or geo.active

    def _record_data(r: DNSRecord) -> RecordData:
        return RecordData(
            name=r.name,
            record_type=r.record_type,
            value=r.value,
            ttl=r.ttl,
            priority=r.priority,
            weight=r.weight,
            port=r.port,
        )

    # DNSSEC policies (issue #49) — resolve each signed zone's policy name
    # and ship the referenced custom policy definitions so the agent can
    # render the matching ``dnssec-policy { ... }`` blocks. The built-in
    # "default" needs no block (BIND ships it), so it's never collected.
    policies_by_id = {p.id: p for p in (await db.execute(select(DNSSECPolicy))).scalars().all()}

    def _zone_policy_name(z: DNSZone) -> str | None:
        if not z.dnssec_enabled or z.dnssec_policy_id is None:
            return None
        pol = policies_by_id.get(z.dnssec_policy_id)
        return pol.name if pol is not None else None

    def _update_acl(z: DNSZone) -> tuple[UpdateAclEntry, ...]:
        # Neutral projection of the zone's dynamic-update ACL rows (issue
        # #641). TSIG entries carry the key NAME only — the secret ships
        # separately in the bundle's ``tsig_keys`` block and never here.
        return tuple(
            UpdateAclEntry(
                match_kind=e.match_kind,
                action=e.action,
                ip_cidr=e.ip_cidr,
                tsig_key_name=(e.tsig_key.name if e.tsig_key is not None else None),
                name_scope=e.name_scope,
                name_pattern=e.name_pattern,
                record_types=tuple(e.record_types) if e.record_types else None,
            )
            for e in z.update_acl_entries
        )

    def _zone_data(z: DNSZone, records: tuple[RecordData, ...], view_name: str | None) -> ZoneData:
        return ZoneData(
            name=z.name,
            zone_type=z.zone_type,
            kind=z.kind,
            ttl=z.ttl,
            refresh=z.refresh,
            retry=z.retry,
            expire=z.expire,
            minimum=z.minimum,
            primary_ns=z.primary_ns or "",
            admin_email=z.admin_email or "",
            serial=z.last_serial or 0,
            records=records,
            allow_query=_tuple_or_none(z.allow_query),
            allow_transfer=_tuple_or_none(z.allow_transfer),
            also_notify=_tuple_or_none(z.also_notify),
            notify_enabled=z.notify_enabled,
            view_name=view_name,
            forwarders=tuple(z.forwarders or ()),
            forward_only=bool(z.forward_only),
            forward_transport=z.forward_transport or "do53",
            forward_tls_hostname=z.forward_tls_hostname,
            masters=tuple(z.masters or ()),
            dnssec_enabled=bool(z.dnssec_enabled),
            dnssec_policy_name=_zone_policy_name(z),
            dynamic_update_enabled=bool(z.dynamic_update_enabled),
            update_acl=_update_acl(z),
        )

    zones: list[ZoneData] = []
    for z in zone_rows:
        all_records = list(z.records)

        if not has_views:
            # No views in the group — flat render with every record
            # (the historical behaviour, byte-for-byte).
            # A member scoped to a site with no subnets serves nobody (#2292).
            flat = (r for r in all_records if str(r.pool_member_id) not in geo.unreachable_members)
            zones.append(_zone_data(z, tuple(_record_data(r) for r in flat), None))
            continue

        # Split-horizon (issue #24) composed with geo steering (#530).
        # Operator views: the zone materialises in each view referenced by
        # a scoped record PLUS its own pinned ``view_id``; with no explicit
        # scoping it's a "global" zone rendered into every operator view.
        # Geo + catch-all views always render the zone (like a global one)
        # so the catch-all serves the default member set. Per-view record
        # filtering (operator scope ∪ shared/default, geo-member isolation)
        # is delegated to ``records_for_view``.
        record_view_ids = {r.view_id for r in all_records if r.view_id is not None}
        zone_view_ids = {z.view_id} if z.view_id is not None else set()
        operator_target_ids = record_view_ids | zone_view_ids

        for vd in view_descs:
            if (
                vd["kind"] == "operator"
                and operator_target_ids
                and vd["id"] not in operator_target_ids
            ):
                continue
            recs = tuple(_record_data(r) for r in records_for_view(all_records, vd, geo))
            zones.append(_zone_data(z, recs, vd["name"]))

    # Blocklists: one RPZ zone per view if views present, plus group-level.
    blocklists: list[EffectiveBlocklistData] = []
    if view_rows:
        for v in view_rows:
            eff = await build_effective_for_view(db, v.id)
            if eff.entries:
                blocklists.append(
                    _to_blocklist_data(eff, f"spatium-blocklist-{v.name}.rpz.", view_name=v.name)
                )
    else:
        eff = await build_effective_for_group(db, server.group_id)
        if eff.entries:
            blocklists.append(_to_blocklist_data(eff, "spatium-blocklist.rpz."))

    # TSIG keys are modelled on DNSServerGroup (not DNSServer) and are delivered
    # to agents by the live ``agent_config.build_config_bundle`` path. This
    # (vestigial) builder never populated them — the old getattr(server, ...)
    # shims were always None since DNSServer has no tsig_key_* columns (#483).
    tsig_keys: tuple[TsigKey, ...] = ()

    # Collect the custom (non-"default") policies referenced by signed zones
    # so the agent has a ``dnssec-policy { ... }`` block to render for each.
    referenced_policy_ids = {
        z.dnssec_policy_id for z in zone_rows if z.dnssec_enabled and z.dnssec_policy_id is not None
    }
    dnssec_policies = tuple(
        DNSSECPolicyData(
            name=p.name,
            algorithm=p.algorithm,
            ksk_lifetime_days=p.ksk_lifetime_days,
            zsk_lifetime_days=p.zsk_lifetime_days,
            nsec3=p.nsec3,
            nsec3_iterations=p.nsec3_iterations,
            nsec3_salt_length=p.nsec3_salt_length,
            nsec3_optout=p.nsec3_optout,
        )
        for pid in referenced_policy_ids
        if (p := policies_by_id.get(pid)) is not None and p.name != "default"
    )

    bundle = ConfigBundle(
        server_id=str(server.id),
        server_name=server.name,
        driver=server.driver,
        roles=tuple(server.roles or ()),
        options=options,
        acls=acls,
        views=views,
        zones=tuple(zones),
        tsig_keys=tsig_keys,
        blocklists=tuple(blocklists),
        generated_at=datetime.now(UTC),
        dnssec_policies=dnssec_policies,
    )
    bundle.etag = bundle.compute_etag()
    return bundle


__all__ = ["ConfigBundle", "build_config_bundle"]
