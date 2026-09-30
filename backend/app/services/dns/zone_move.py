"""Move a DNS zone from one server group to another (issue #935).

The sibling of the #934 server move, and a much sharper tool. A server
carries state ABOUT a group; a zone carries references INTO one. Every
one of these is group-scoped, so a bare ``group_id`` reassignment leaves
cross-group dangling references: ``DNSView``, ``DNSTSIGKey``, ``DNSAcl``,
``DNSServerOptions``, ``DNSPool``.

**The load-bearing property is that clearing a view widens exposure.**

Under split-horizon (#24) a record with ``view_id IS NOT NULL`` renders in
exactly that view; a record with ``view_id IS NULL`` is *shared* and
renders in EVERY view (``pool_geo.records_for_view``, and the zone-level
equivalent in ``agent_config``). So dropping a view reference that cannot
be resolved in the target is not a neutral tidy-up — it takes a zone or a
record that answered only on the internal view and starts answering on the
external one. That is a data-exposure change with no operator-visible
symptom, which is why it is surfaced as its own acknowledgement rather
than folded into a generic warning list.

Preview → commit, like the IPAM block move, because none of this is
guessable from the request: the operator has to see which views remap by
name, which do not, what happens to their dynamic-update grants, and that
a signed zone changes groups by ROLLING ITS KEYS rather than by moving
them.
"""

from __future__ import annotations

import uuid
import zlib
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select, text
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import collect_wake, dns_group_channel
from app.models.acme import ACMEAccount
from app.models.dns import (
    DNSAcl,
    DNSKey,
    DNSPool,
    DNSRecord,
    DNSServer,
    DNSServerGroup,
    DNSServerZoneState,
    DNSTSIGKey,
    DNSView,
    DNSZone,
    DNSZoneUpdateAcl,
)
from app.services.dns.named_conf_validation import is_name_reference, key_reference
from app.services.dns.pool_geo import build_geo_steering
from app.services.dns.record_ops import (
    clear_dnssec_key_state,
    count_queued_zone_ops,
    sweep_zone_ops,
)
from app.services.dns.tsig import ensure_group_tsig_key, group_key_names

logger = structlog.get_logger(__name__)

#: Advisory-lock namespace for zone moves. Distinct from the IPAM block
#: move's namespace so the two never contend on a colliding CRC.
_LOCK_NS_ZONE_MOVE = 0x5A4D  # "ZM"

#: Acknowledgement keys. Each names a consequence the operator has to
#: accept explicitly, because none of them is reversible by re-running
#: the move in the other direction.
ACK_VIEW_WIDENING = "view_widening"
ACK_DNSSEC_ROLLOVER = "dnssec_rollover"
ACK_LOST_UPDATE_GRANTS = "lost_update_grants"

#: Drivers whose agents can actually sign a zone. Mirrors the router's
#: ``_DRIVER_GATED_OPERATIONS["dnssec_sign"]`` gate, which every other
#: path into a signed zone goes through — a move that skipped it would
#: leave the row saying ``dnssec_enabled`` while the zone is served
#: unsigned, indefinitely and with nothing to notice it.
DNSSEC_SIGN_DRIVERS = frozenset({"bind9", "powerdns"})


class ZoneMoveError(Exception):
    """A move the control plane refuses, carrying the HTTP status the
    router should answer with."""

    def __init__(self, detail: str, status_code: int = 409) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


@dataclass
class ZoneMovePlan:
    """Everything the preview reports and the commit re-derives.

    Assembled by ``assemble_move_plan`` and re-assembled INSIDE the
    commit's advisory lock, so a view created (or deleted) between
    preview and commit changes the answer rather than being applied
    against a stale reading.
    """

    zone_id: uuid.UUID
    zone_name: str
    source_group_id: uuid.UUID
    source_group_name: str
    target_group_id: uuid.UUID
    target_group_name: str

    # Split-horizon posture of each side. ``has_views`` is true when the
    # group renders inside ``view { … }`` blocks at all — which geo
    # steering (#530) forces on even for a group with no operator views.
    source_has_views: bool = False
    target_has_views: bool = False

    # What happens to the zone's own pinned view.
    #   kept_none        — it had none; nothing to do
    #   remapped         — the target has a view of the same name
    #   cleared_widening — no name match AND the target renders in views
    #                      mode, so the zone goes from one view to all
    #   cleared_inert    — no name match and the target has no views, so
    #                      the reference was going to be ignored anyway
    zone_view_action: str = "kept_none"
    zone_view_from: str | None = None
    zone_view_to_id: uuid.UUID | None = None

    # Per-record view scoping, same three outcomes.
    records_total: int = 0
    records_remapped: int = 0
    records_widened: int = 0
    records_cleared_inert: int = 0
    #: view name → count, for the operator to see WHICH scoping is lost.
    records_widened_by_view: dict[str, int] = field(default_factory=dict)

    # Dynamic-update (#641) grants. A ``tsig_key`` ACL row cannot simply
    # be cleared: ``num_nonnulls(tsig_key_id, ip_cidr) = 1`` forbids a row
    # with neither. So it is remapped by key name, or DELETED.
    acl_rows_remapped: int = 0
    acl_keys_lost: list[str] = field(default_factory=list)

    # Pools follow their zone (they are attached by ``zone_id``, and their
    # health checks run from the control plane rather than the group's
    # agents, so nothing about them is bound to the old group).
    pools_repointed: int = 0

    # Purged: both refer to the OLD group's servers.
    zone_state_rows: int = 0
    pending_ops: int = 0

    # DNSSEC. The private keys live on the old group's servers and do not
    # travel; the target re-signs from scratch under its own policy.
    dnssec_signed: bool = False
    dnssec_key_count: int = 0

    # ACME DNS-01 delegations (#28) pointing at this zone. The provider
    # writes TXT through ``enqueue_record_op``, which resolves the primary
    # from ``zone.group_id`` at call time — so after the move those writes
    # land on the target's servers while the NS delegation at the
    # registrar still points at the old group's hosts.
    acme_accounts: int = 0

    source_drivers: list[str] = field(default_factory=list)
    target_drivers: list[str] = field(default_factory=list)

    name_collision: bool = False
    target_tsig_key_generated: bool = False
    #: Target drivers that cannot sign, when the zone is signed. A move
    #: onto one is refused rather than warned: the row keeps saying
    #: ``dnssec_enabled`` while the zone is served unsigned forever.
    dnssec_unsupported_drivers: list[str] = field(default_factory=list)
    #: Named ACLs cited in the zone's own address-match lists
    #: (``allow_query`` / ``allow_transfer`` / ``also_notify``). ``DNSAcl``
    #: is group-scoped, so a name that exists in the source and not the
    #: target becomes an undefined symbol in the target's named.conf —
    #: which BIND rejects WHOLE, so the agent declines the entire bundle
    #: and the group stops converging (the #882 / #899 failure).
    acl_names_remapped: list[str] = field(default_factory=list)
    acl_names_lost: list[str] = field(default_factory=list)
    #: TSIG keys cited as ``key <name>`` in those same lists (#1316). A
    #: ``key {}`` is group-scoped too, so a key the target does not define
    #: is the same undefined symbol and the same whole-group failure.
    key_names_lost: list[str] = field(default_factory=list)

    warnings: list[str] = field(default_factory=list)
    #: Acknowledgement keys the commit will demand.
    required_acknowledgements: list[str] = field(default_factory=list)


def _advisory_lock_key(zone_id: uuid.UUID) -> tuple[int, int]:
    key = zlib.crc32(str(zone_id).encode("utf-8"))
    if key >= 2**31:
        key -= 2**32
    return (_LOCK_NS_ZONE_MOVE, key)


async def _try_advisory_lock(db: AsyncSession, zone_id: uuid.UUID) -> bool:
    ns, key = _advisory_lock_key(zone_id)
    return bool(
        (
            await db.execute(
                text("SELECT pg_try_advisory_xact_lock(:ns, :key)"),
                {"ns": ns, "key": key},
            )
        ).scalar_one()
    )


async def _group_has_views(db: AsyncSession, group_id: uuid.UUID) -> bool:
    """True when this group renders inside ``view { … }`` blocks.

    Operator views (#24) OR synthesized geo views (#530) — the second is
    easy to forget and matters here, because a group with geo steering and
    no operator views still renders in views mode, so a cleared reference
    still widens.
    """
    has_operator = (
        await db.execute(select(DNSView.id).where(DNSView.group_id == group_id).limit(1))
    ).first() is not None
    if has_operator:
        return True
    return bool((await build_geo_steering(db, group_id)).active)


async def _drivers_of(db: AsyncSession, group_id: uuid.UUID) -> list[str]:
    rows = (
        (
            await db.execute(
                select(DNSServer.driver).where(DNSServer.group_id == group_id).distinct()
            )
        )
        .scalars()
        .all()
    )
    return sorted(d for d in rows if d)


async def assemble_move_plan(
    db: AsyncSession, zone: DNSZone, target_group: DNSServerGroup
) -> ZoneMovePlan:
    """Work out exactly what moving ``zone`` into ``target_group`` does.

    Pure read — nothing here mutates. Called for the preview AND again
    inside the commit's lock so the applied plan is never a stale one.
    """
    source_group = await db.get(DNSServerGroup, zone.group_id)
    plan = ZoneMovePlan(
        zone_id=zone.id,
        zone_name=zone.name,
        source_group_id=zone.group_id,
        source_group_name=source_group.name if source_group else "(deleted)",
        target_group_id=target_group.id,
        target_group_name=target_group.name,
    )

    plan.source_has_views = await _group_has_views(db, zone.group_id)
    plan.target_has_views = await _group_has_views(db, target_group.id)
    plan.source_drivers = await _drivers_of(db, zone.group_id)
    plan.target_drivers = await _drivers_of(db, target_group.id)

    # ── Views, by NAME ────────────────────────────────────────────────
    # Name is the only stable identity across groups: ids are per-group
    # rows and a "internal" view in each group is the operator's own
    # statement that the two mean the same thing.
    target_views = {
        v.name: v.id
        for v in (await db.execute(select(DNSView).where(DNSView.group_id == target_group.id)))
        .scalars()
        .all()
    }
    source_views = {
        v.id: v.name
        for v in (await db.execute(select(DNSView).where(DNSView.group_id == zone.group_id)))
        .scalars()
        .all()
    }

    def _resolve(view_id: uuid.UUID | None) -> tuple[str, uuid.UUID | None, str | None]:
        """(action, new_view_id, old_view_name) for one view reference."""
        if view_id is None:
            return ("kept_none", None, None)
        old_name = source_views.get(view_id)
        if old_name is not None and old_name in target_views:
            return ("remapped", target_views[old_name], old_name)
        if plan.target_has_views:
            return ("cleared_widening", None, old_name)
        return ("cleared_inert", None, old_name)

    plan.zone_view_action, plan.zone_view_to_id, plan.zone_view_from = _resolve(zone.view_id)

    # ``records_total`` is what the operator is moving, so it counts LIVE
    # rows only. The view scan below deliberately does not — see there.
    plan.records_total = (
        await db.execute(
            select(func.count()).select_from(DNSRecord).where(DNSRecord.zone_id == zone.id)
        )
    ).scalar_one()

    # Only view-scoped rows need looking at, and only their ``view_id`` —
    # so this selects two columns rather than hydrating every DNSRecord in
    # the zone, which the modal would otherwise do on every dropdown change.
    #
    # ``include_deleted=True`` is load-bearing: DNSRecord is soft-deleted,
    # so the default filter would leave a deleted row pointing at a
    # SOURCE-group view. Restoring it later resurrects a dangling reference
    # into a group the zone has left — and under split-horizon that row
    # then renders into no operator view at all rather than into one.
    scoped = (
        await db.execute(
            select(DNSRecord.id, DNSRecord.view_id)
            .where(DNSRecord.zone_id == zone.id, DNSRecord.view_id.isnot(None))
            .execution_options(include_deleted=True)
        )
    ).all()
    for _rid, view_id in scoped:
        action, _new_id, old_name = _resolve(view_id)
        if action == "remapped":
            plan.records_remapped += 1
        elif action == "cleared_widening":
            plan.records_widened += 1
            key = old_name or "(unknown view)"
            plan.records_widened_by_view[key] = plan.records_widened_by_view.get(key, 0) + 1
        elif action == "cleared_inert":
            plan.records_cleared_inert += 1

    # ── Name collision, against the RESOLVED view ─────────────────────
    # The constraint is ``(group_id, view_id, name)``, not
    # ``(group_id, name)`` — so whether this collides depends on where the
    # view resolves to. A zone whose view is cleared lands at
    # ``(target, NULL, name)``, which can collide with an unviewed zone a
    # (group_id, name) check would have missed.
    effective_view_id = plan.zone_view_to_id
    clash = await db.execute(
        select(DNSZone.id).where(
            DNSZone.group_id == target_group.id,
            DNSZone.name == zone.name,
            (
                DNSZone.view_id.is_(None)
                if effective_view_id is None
                else DNSZone.view_id == effective_view_id
            ),
            DNSZone.id != zone.id,
        )
    )
    plan.name_collision = clash.first() is not None

    # ── Dynamic-update grants ─────────────────────────────────────────
    acl_rows = (
        (
            await db.execute(
                select(DNSZoneUpdateAcl).where(
                    DNSZoneUpdateAcl.zone_id == zone.id,
                    DNSZoneUpdateAcl.tsig_key_id.isnot(None),
                )
            )
        )
        .scalars()
        .all()
    )
    if acl_rows:
        source_keys = {
            k.id: k.name
            for k in (
                await db.execute(select(DNSTSIGKey).where(DNSTSIGKey.group_id == zone.group_id))
            )
            .scalars()
            .all()
        }
        target_keys = {
            k.name
            for k in (
                await db.execute(select(DNSTSIGKey).where(DNSTSIGKey.group_id == target_group.id))
            )
            .scalars()
            .all()
        }
        for row in acl_rows:
            name = source_keys.get(row.tsig_key_id) if row.tsig_key_id else None
            if name is not None and name in target_keys:
                plan.acl_rows_remapped += 1
            else:
                plan.acl_keys_lost.append(name or "(unknown key)")

    # ── Everything else ───────────────────────────────────────────────
    source_acls = {
        a.name
        for a in (await db.execute(select(DNSAcl).where(DNSAcl.group_id == zone.group_id)))
        .scalars()
        .all()
    }
    target_acls = {
        a.name
        for a in (await db.execute(select(DNSAcl).where(DNSAcl.group_id == target_group.id)))
        .scalars()
        .all()
    }

    _scan_key_references(
        plan,
        zone,
        await group_key_names(db, zone.group_id),
        await group_key_names(db, target_group.id),
    )

    plan.pools_repointed = await _count(db, DNSPool, DNSPool.zone_id == zone.id)
    plan.zone_state_rows = await _count(
        db, DNSServerZoneState, DNSServerZoneState.zone_id == zone.id
    )
    plan.pending_ops = await _count_pending_ops(db, zone)
    plan.dnssec_key_count = await _count(db, DNSKey, DNSKey.zone_id == zone.id)
    plan.dnssec_signed = bool(zone.dnssec_enabled) or plan.dnssec_key_count > 0
    plan.acme_accounts = await _count(db, ACMEAccount, ACMEAccount.zone_id == zone.id)

    # ── DNSSEC support in the target (a refusal, not a warning) ───────
    if plan.dnssec_signed:
        allowed = DNSSEC_SIGN_DRIVERS
        plan.dnssec_unsupported_drivers = sorted(set(plan.target_drivers) - allowed)

    # ── Named ACLs cited by the zone's own address-match lists ────────
    _scan_acl_references(plan, zone, source_acls, target_acls)

    _fill_warnings(plan)
    return plan


async def _count(db: AsyncSession, model: type, *criteria: Any) -> int:
    """``SELECT count(*)`` rather than hydrating rows to call ``len()`` on.

    The preview runs on every change of the destination dropdown, so the
    difference between counting in Postgres and materialising every record,
    pool and key in the zone is the difference between a snappy modal and
    one that stalls on a large zone.
    """
    return int(
        (await db.execute(select(func.count()).select_from(model).where(*criteria))).scalar_one()
    )


def _acl_references(zone: DNSZone) -> set[str]:
    """Named ACLs the zone's own address-match lists refer to.

    ``allow_query`` / ``allow_transfer`` / ``also_notify`` are interpolated
    into the rendered zone statement, and a bare identifier in one of them
    is a reference to an ``acl "<name>" { … };`` block — which is defined
    PER GROUP (#899). ``is_name_reference`` is the same helper the bundle
    builder and the ACL ordering pass use, so the three cannot disagree
    about what counts as a reference.
    """
    names: set[str] = set()
    for values in (zone.allow_query, zone.allow_transfer, zone.also_notify):
        for element in values or []:
            name = is_name_reference(str(element))
            if name:
                names.add(name)
    return names


def _scan_acl_references(
    plan: ZoneMovePlan, zone: DNSZone, source_acls: set[str], target_acls: set[str]
) -> None:
    for name in sorted(_acl_references(zone)):
        # Only a name the SOURCE group actually defines is something the
        # move can break. An unknown name is already broken (or is a
        # built-in this helper does not classify) and is not ours to
        # report as a consequence of moving.
        if name not in source_acls:
            continue
        if name in target_acls:
            plan.acl_names_remapped.append(name)
        else:
            plan.acl_names_lost.append(name)


def _scan_key_references(
    plan: ZoneMovePlan, zone: DNSZone, source_keys: frozenset[str], target_keys: frozenset[str]
) -> None:
    cited = {
        name
        for values in (zone.allow_query, zone.allow_transfer, zone.also_notify)
        for element in values or []
        if (name := key_reference(str(element)))
    }
    # As with ACL names, only a key the SOURCE defines is something the
    # move breaks; an undefined one is already broken.
    plan.key_names_lost = sorted(n for n in cited if n in source_keys and n not in target_keys)


async def _count_pending_ops(db: AsyncSession, zone: DNSZone) -> int:
    """Live record ops queued for this zone against the OLD group's servers.

    Keyed by ``(server_id, zone_name)`` rather than by zone id — that is
    how ``DNSRecordOp`` is shaped — so it is scoped to the source group's
    servers. Within the group it is name-scoped, which under split-horizon
    also counts a sibling view's same-named zone: see
    ``record_ops.queued_zone_ops_where`` for why that is accepted (#964).
    """
    return await count_queued_zone_ops(db, zone, zone.group_id)


def _fill_warnings(plan: ZoneMovePlan) -> None:
    """Turn the measured plan into operator-readable warnings and the set
    of acknowledgements the commit will demand."""
    if plan.zone_view_action == "cleared_widening":
        plan.warnings.append(
            f"The zone is pinned to view '{plan.zone_view_from}', which does not exist in "
            f"'{plan.target_group_name}'. It will be UNPINNED — and an unpinned zone renders "
            f"into EVERY view in the target group, not none. Create a view named "
            f"'{plan.zone_view_from}' in the target first to keep the current scoping."
        )
    if plan.records_widened:
        detail = ", ".join(
            f"{n} from '{v}'" for v, n in sorted(plan.records_widened_by_view.items())
        )
        plan.warnings.append(
            f"{plan.records_widened} record(s) are scoped to views the target group does not "
            f"have ({detail}). They will become unscoped, which means they start answering in "
            f"EVERY view in the target rather than in one."
        )
    if plan.zone_view_action == "cleared_widening" or plan.records_widened:
        plan.required_acknowledgements.append(ACK_VIEW_WIDENING)

    if plan.zone_view_action == "cleared_inert":
        plan.warnings.append(
            f"The zone's view pin ('{plan.zone_view_from}') will be dropped. The target group "
            f"does not render views, so this changes nothing today — but the pin is not "
            f"recoverable by moving the zone back."
        )
    if plan.records_cleared_inert:
        plan.warnings.append(
            f"{plan.records_cleared_inert} record view-scoping(s) will be dropped. The target "
            f"group does not render views, so this changes nothing today."
        )

    if plan.dnssec_signed:
        plan.warnings.append(
            "This zone is DNSSEC-signed. The private keys live on the CURRENT group's servers "
            "and do not move — the target group signs from scratch with new keys, so this is a "
            "key rollover. The DS record at the registrar/parent will be wrong until you "
            "publish the new one, and the zone will fail validation in the interval."
        )
        plan.required_acknowledgements.append(ACK_DNSSEC_ROLLOVER)

    if plan.acl_keys_lost:
        plan.warnings.append(
            f"{len(plan.acl_keys_lost)} dynamic-update grant(s) reference TSIG keys that do not "
            f"exist in the target group ({', '.join(sorted(set(plan.acl_keys_lost)))}). Those "
            f"grants will be DELETED — the clients using them lose the ability to update this "
            f"zone. Create keys with the same names in the target first to keep them."
        )
        plan.required_acknowledgements.append(ACK_LOST_UPDATE_GRANTS)

    if plan.acl_names_lost:
        plan.warnings.append(
            f"The zone's address-match lists name ACL(s) that do not exist in the target group "
            f"({', '.join(plan.acl_names_lost)}). A named ACL is defined per group, so the "
            f"target's named.conf would carry an undefined symbol — BIND rejects the file "
            f"whole, which stops the WHOLE target group converging, not just this zone. "
            f"Create ACLs with the same names in the target first."
        )

    if plan.key_names_lost:
        plan.warnings.append(
            f"The zone's address-match lists name TSIG key(s) that do not exist in the target "
            f"group ({', '.join(plan.key_names_lost)}). A key is defined per group, so the "
            f"target's named.conf would carry an undefined symbol — BIND rejects the file "
            f"whole, which stops the WHOLE target group converging, not just this zone. "
            f"Create keys with the same names in the target first."
        )

    if plan.acme_accounts:
        plan.warnings.append(
            f"{plan.acme_accounts} ACME DNS-01 delegation account(s) use this zone. Their TXT "
            f"records will be written by the target group's servers, but the NS delegation at "
            f"your registrar still points at the current group's — certificate issuance will "
            f"fail until you repoint it."
        )

    if plan.target_drivers and plan.source_drivers and plan.target_drivers != plan.source_drivers:
        plan.warnings.append(
            f"Driver change: this zone is served by {plan.source_drivers} today and would be "
            f"served by {plan.target_drivers}. Driver-specific features (ALIAS records, "
            f"DNSSEC signing, per-driver record types) may not survive."
        )
    if not plan.target_drivers:
        plan.warnings.append(
            f"'{plan.target_group_name}' has no servers, so the zone will not be served by "
            f"anything until one is added."
        )

    if plan.pending_ops:
        plan.warnings.append(
            f"{plan.pending_ops} queued record update(s) for this zone will be discarded — they "
            f"target the current group's servers."
        )


async def preview_move(
    db: AsyncSession, zone: DNSZone, target_group: DNSServerGroup
) -> ZoneMovePlan:
    if zone.group_id == target_group.id:
        raise ZoneMoveError(
            f"Zone '{zone.name}' is already in group '{target_group.name}'.",
            status_code=422,
        )
    return await assemble_move_plan(db, zone, target_group)


async def commit_move(
    db: AsyncSession,
    zone: DNSZone,
    target_group: DNSServerGroup,
    *,
    confirmation_zone_name: str,
    acknowledgements: set[str],
) -> ZoneMovePlan:
    """Apply the move. The caller commits.

    Re-assembles the plan inside an advisory xact-lock so a view or key
    created between preview and commit is reflected, and re-checks every
    refusal against that fresh reading rather than the operator's stale
    one.
    """
    if zone.group_id == target_group.id:
        raise ZoneMoveError(
            f"Zone '{zone.name}' is already in group '{target_group.name}'.",
            status_code=422,
        )
    if confirmation_zone_name.strip().rstrip(".") != zone.name.rstrip("."):
        raise ZoneMoveError(
            f"Confirmation '{confirmation_zone_name}' does not match the zone name "
            f"'{zone.name}'.",
            status_code=422,
        )
    if not await _try_advisory_lock(db, zone.id):
        raise ZoneMoveError(
            "Another move is in progress for this zone. Try again shortly.",
            status_code=423,
        )

    plan = await assemble_move_plan(db, zone, target_group)

    # Hard refusals that no acknowledgement can waive, because none of them
    # produces a state the operator could inspect and fix afterwards.
    if plan.dnssec_unsupported_drivers:
        raise ZoneMoveError(
            f"This zone is DNSSEC-signed and '{target_group.name}' runs "
            f"{plan.dnssec_unsupported_drivers}, which cannot sign. The zone would keep "
            f"reporting as signed while being served unsigned. Unsign it first, or pick a "
            f"group running one of {sorted(DNSSEC_SIGN_DRIVERS)}.",
            status_code=422,
        )
    if plan.acl_names_lost:
        raise ZoneMoveError(
            f"The zone names ACL(s) the target group does not define "
            f"({', '.join(plan.acl_names_lost)}). Moving it would leave an undefined symbol in "
            f"the target's named.conf, which BIND rejects whole — the entire target group "
            f"would stop converging, not just this zone. Create ACLs with those names in "
            f"'{target_group.name}' first.",
            status_code=422,
        )
    if plan.key_names_lost:
        raise ZoneMoveError(
            f"The zone names TSIG key(s) the target group does not define "
            f"({', '.join(plan.key_names_lost)}). Moving it would leave an undefined symbol in "
            f"the target's named.conf, which BIND rejects whole — the entire target group "
            f"would stop converging, not just this zone. Create keys with those names in "
            f"'{target_group.name}' first.",
            status_code=422,
        )
    if plan.name_collision:
        where = f"view '{plan.zone_view_from}'" if plan.zone_view_to_id is not None else "no view"
        raise ZoneMoveError(
            f"Group '{target_group.name}' already has a zone named '{zone.name}' in {where}. "
            f"Delete or rename it first.",
            status_code=409,
        )

    missing = [a for a in plan.required_acknowledgements if a not in acknowledgements]
    if missing:
        raise ZoneMoveError(
            "This move needs explicit acknowledgement of: "
            + ", ".join(sorted(missing))
            + ". Re-run the preview to see why, then resend with those acknowledgements.",
            status_code=422,
        )

    old_group_id = zone.group_id
    source_views = {
        v.id: v.name
        for v in (await db.execute(select(DNSView).where(DNSView.group_id == old_group_id)))
        .scalars()
        .all()
    }
    target_views = {
        v.name: v.id
        for v in (await db.execute(select(DNSView).where(DNSView.group_id == target_group.id)))
        .scalars()
        .all()
    }

    def _new_view_id(view_id: uuid.UUID | None) -> uuid.UUID | None:
        if view_id is None:
            return None
        name = source_views.get(view_id)
        return target_views.get(name) if name else None

    # ── Views ─────────────────────────────────────────────────────────
    zone.view_id = _new_view_id(zone.view_id)
    # ``include_deleted=True`` for the same reason the plan scan uses it:
    # DNSRecord is soft-deleted, and a deleted row left pointing at a
    # SOURCE-group view is a dangling reference the moment someone restores
    # it. The plan counts those rows, so the commit has to actually rewrite
    # them or the preview and the outcome disagree.
    records = (
        (
            await db.execute(
                select(DNSRecord)
                .where(DNSRecord.zone_id == zone.id, DNSRecord.view_id.isnot(None))
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    for r in records:
        r.view_id = _new_view_id(r.view_id)

    # ── Dynamic-update grants ─────────────────────────────────────────
    # Remap by key name where possible; delete what cannot be expressed.
    # The CHECK constraint forbids a row with neither identity column, so
    # "clear the key" is not an option — and deleting a grant fails
    # CLOSED, which is the safe direction for an authorisation rule.
    acl_rows = (
        (
            await db.execute(
                select(DNSZoneUpdateAcl).where(
                    DNSZoneUpdateAcl.zone_id == zone.id,
                    DNSZoneUpdateAcl.tsig_key_id.isnot(None),
                )
            )
        )
        .scalars()
        .all()
    )
    if acl_rows:
        source_keys = {
            k.id: k.name
            for k in (
                await db.execute(select(DNSTSIGKey).where(DNSTSIGKey.group_id == old_group_id))
            )
            .scalars()
            .all()
        }
        target_keys = {
            k.name: k.id
            for k in (
                await db.execute(select(DNSTSIGKey).where(DNSTSIGKey.group_id == target_group.id))
            )
            .scalars()
            .all()
        }
        for row in acl_rows:
            name = source_keys.get(row.tsig_key_id) if row.tsig_key_id else None
            replacement = target_keys.get(name) if name else None
            if replacement is not None:
                row.tsig_key_id = replacement
            else:
                await db.delete(row)

    # ── Pools follow the zone ─────────────────────────────────────────
    if plan.pools_repointed:
        await db.execute(
            sa_update(DNSPool).where(DNSPool.zone_id == zone.id).values(group_id=target_group.id)
        )

    # ── Purge state belonging to the old group ────────────────────────
    await db.execute(sa_delete(DNSServerZoneState).where(DNSServerZoneState.zone_id == zone.id))
    await sweep_zone_ops(db, zone, old_group_id)
    # DNSSEC key state is a read-only mirror of what the OLD group's agents
    # reported. The target signs from scratch, so leaving it would show the
    # operator keys that no server holds — and, worse, a cached
    # ``dnssec_ds_records`` telling them to publish the OLD group's DS.
    # ``clear_dnssec_key_state`` is the one helper every other flag-off path
    # uses, and it clears both halves; deleting the DNSKey rows alone left
    # the stale DS behind.
    await clear_dnssec_key_state(db, zone)

    zone.group_id = target_group.id

    # A group created in the UI may never have been through agent
    # registration, where the legacy group TSIG key is generated. Same
    # reasoning as the #934 server move.
    plan.target_tsig_key_generated = ensure_group_tsig_key(target_group)

    collect_wake(dns_group_channel(old_group_id), dns_group_channel(target_group.id))

    logger.info(
        "dns_zone_moved_group",
        zone_id=str(zone.id),
        zone_name=zone.name,
        old_group_id=str(old_group_id),
        new_group_id=str(target_group.id),
        records_widened=plan.records_widened,
        acl_keys_lost=len(plan.acl_keys_lost),
        dnssec_signed=plan.dnssec_signed,
    )
    return plan
