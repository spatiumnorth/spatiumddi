"""Risky-operation registry for the two-person approval workflow (#62).

Each delete handler covered by the approval gate has its mutation body
factored verbatim into an :class:`Operation` ``apply()`` here, with a
``preview()`` that re-runs the same 404 / 409 / synthesised-zone guards
the original handler did inline. The REST handler delegates to
``apply()`` on the inline (no-approval) path AND the approve endpoint
replays the same ``apply()`` under the approver's identity after a
fresh ``preview()`` stale-state check — one mutation path, two callers.

THE INLINE-FIDELITY CONTRACT — ``apply()`` must be byte-identical to the
pre-#62 handler when the module is off:

* The ``apply()`` body is the original handler body, unchanged. Every
  side effect (soft-delete batch + per-row audit, permanent cascade of
  DHCP scopes / DNS records / zones, agent bundle rebuilds, ``collect_wake``
  / ``publish_wake`` of the affected channel, ``_update_block_utilization``)
  is preserved in the same order.
* ``apply()`` / ``preview()`` raise the original handler's HTTP statuses —
  ``HTTPException(404)`` for not-found, ``HTTPException(409)`` for
  not-empty / conflict, ``HTTPException(403)`` for superadmin-required —
  CONSISTENTLY across all six ops. (A bare ``ValueError`` here would
  surface as a 500 to the inline caller — fixed.)
* ``apply()`` does NOT call ``enforce_operation_permission``: the inline
  handler is already authorized by the router's permission gate, and the
  two callers that bypass that gate — the approve endpoint + the AI
  propose→apply path — enforce the permission themselves *before*
  dispatching ``apply()``. Re-checking inside ``apply()`` would 403 a
  delegate whose scoped grant the router admitted (#103 address-set
  delegate) — fidelity break.
* Superadmin parity with the ORIGINAL ROUTE (so the approve path, which
  bypasses the delete route's dependencies, enforces identically):
  subnet / block / space / ``delete_zone`` / ``delete_scope`` require
  superadmin only on the ``permanent`` branch (the zone and scope routes
  were fully ``SuperAdmin``-gated until #1861 opened their soft-delete to
  the resource's ``delete`` permission); ``delete_group`` is still fully
  ``SuperAdmin``-gated at the route, so its ``apply()`` requires superadmin
  ALWAYS. A failed check raises ``HTTPException(403)``.
* The ``permanent`` / ``force`` flags are frozen into the args model so
  the approved replay takes the *identical* branch the requester intended.
* Audit ``action`` strings stay exactly as today (``soft_delete`` on the
  default path, ``delete`` on the permanent path) — never collapsed.
* The not-found / not-empty validation is factored into one shared helper
  used by both ``preview()`` and ``apply()`` so the two never drift.

CLAUDE.md non-negotiables honoured: #2 (async throughout), #3 (server-side
permission enforcement — by the router gate inline, by the approve / AI
dispatch sites for the bypass callers), #4 (every mutation writes its audit
row before the commit inside ``apply()``).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from uuid import UUID

import structlog
from fastapi import HTTPException, status
from pydantic import BaseModel
from sqlalchemy import String, and_, any_, cast, func, literal, not_, or_, select
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.models.auth import User
from app.services.ai.operations import (
    Operation,
    PreviewResult,
    get_operation,
    register,
)
from app.services.ipam.utilization import recount_subnets_and_blocks

logger = structlog.get_logger(__name__)


# ── Blast-radius preview helper (#3a) ──────────────────────────────────────
#
# The approve path re-runs preview() and compares its preview_text against the
# frozen request-time preview_text; any drift refuses execution (#3b). For
# that drift check to actually catch a cascade that GREW between request and
# approval, every delete op's preview_text must embed the CURRENT blast radius
# (counts that move when the cascade changes), not just a static label.


async def _soft_delete_cascade_summary(db: AsyncSession, root: Any) -> str:
    """Render the soft-delete cascade blast radius for ``root`` as a stable,
    count-bearing string (#3a).

    Uses the SAME ``collect_soft_delete_batch`` walk ``apply()`` will use, plus
    the reverse zones a subnet, block or space delete then retires into that
    batch, chosen by the apply's own rule, with the records still in them when
    it stamps the batch, and the records of the batch's addresses it retracts
    into the batch from zones that stay, so the preview reflects exactly what
    would be soft-deleted right now. Counts are grouped by resource type and
    rendered in a fixed order so the string is deterministic for a given set
    of rows (the approve-time drift compare is a plain string equality, so
    ordering must not jitter). The root row itself is excluded from the
    cascade counts (it's the target, not collateral)."""
    # Local import — keep the soft_delete dependency off module load.
    from app.services.dns.record_ops import (  # noqa: PLC0415
        count_held_records_deleted_first,
        count_records_to_retract,
    )
    from app.services.dns.reverse_zone import add_retiring_reverse_zones  # noqa: PLC0415
    from app.services.soft_delete import (  # noqa: PLC0415
        _resource_type,
        collect_soft_delete_batch,
    )

    batch = await collect_soft_delete_batch(db, root)
    # The apply adds the reverse zones the batch's subnets auto-created, with
    # their records (#1066, #2734); counted here as it will trash them (#3511).
    # A batch with no subnet in it (a zone's, a scope's) gains nothing.
    await add_retiring_reverse_zones(db, batch)
    # ``counts()`` includes the set-based children (a zone's records, #1231),
    # which are never loaded as rows. The root is the target, not collateral.
    counts = batch.counts()
    root_rt = _resource_type(root)
    counts[root_rt] = counts.get(root_rt, 0) - 1
    # Before its stamp the apply deletes the DHCP mirrors of the batch's
    # subnets, with their records (#3536). It never trashes their records in
    # the zones above, so they come off the zones' count, and a lease granted
    # or expiring in between leaves the preview as it was (#3511). The apply
    # then retracts into the batch the records of its subnets' other addresses
    # in zones that stay (#1906), counted with the batch's records, as the
    # trash holds them.
    torn_down_first = _mirrors_torn_down_first(root, batch)
    counts["dns_record"] = (
        counts.get("dns_record", 0)
        - await count_held_records_deleted_first(db, batch, torn_down_first)
        + await count_records_to_retract(db, batch, not_(torn_down_first))
    )
    labels = {
        "ip_block": "child block",
        "subnet": "subnet",
        "dhcp_scope": "DHCP scope",
        "dhcp_pool": "DHCP pool",
        "dhcp_static_assignment": "DHCP reservation",
        "dns_zone": "DNS zone",
        "dns_record": "DNS record",
    }
    order = [
        "ip_block",
        "subnet",
        "dhcp_scope",
        "dhcp_pool",
        "dhcp_static_assignment",
        "dns_zone",
        "dns_record",
    ]
    parts = []
    for rt in order:
        n = counts.get(rt, 0)
        if n:
            noun = labels[rt]
            parts.append(f"{n} {noun}" + ("s" if n != 1 else ""))
    # Include the leftover types deterministically (sorted) in case the walk
    # grows to cover a type not in ``order`` — never silently drop a count.
    for rt in sorted(counts):
        if rt not in order and counts[rt]:
            parts.append(f"{counts[rt]} {rt}")
    if not parts:
        return "cascades nothing (empty)"
    return "cascades " + ", ".join(parts)


def _mirrors_torn_down_first(root: Any, batch: Any) -> Any:
    """The addresses a soft delete of ``root`` deletes before its stamp, as a
    condition on ``IPAddress``: for each scope ``batch`` holds
    (``_purge_leases_for_scope_batch``), its lease mirrors on its subnet, and
    its reservations' mirrors whatever subnet they sit in, as
    ``remove_ipam_for_scope_statics`` finds them by the reservation alone; and
    for a subnet its every lease mirror (``_revoke_subnet_lease_mirrors``).
    Their records go with them, so the retraction never sees them, and neither
    does the preview's count of it (spatiumddi#3536); nor does the stamp of a
    reverse zone the delete trashes, so the preview's count of that zone's
    records leaves them out too (spatiumddi#3511)."""
    from app.models.dhcp import DHCPLease, DHCPScope, DHCPStaticAssignment  # noqa: PLC0415
    from app.models.ipam import IPAddress, Subnet  # noqa: PLC0415

    # Uncorrelated, so Postgres builds each set once per statement and probes
    # it per address (a hashed SubPlan), and costs it that way. A correlated
    # EXISTS was costed as a scan of dhcp_lease per lease mirror (no index of
    # dhcp_lease serves a lookup by scope and address), and ran so past the
    # hash memory; the inflated cost also made Postgres JIT-compile the
    # preview's counts.
    mirror = aliased(IPAddress)
    own_scope = and_(DHCPScope.subnet_id == mirror.subnet_id, DHCPScope.deleted_at.is_(None))
    lease_mirrors = (
        select(mirror.id)
        .join(DHCPScope, own_scope)
        .join(
            DHCPLease,
            and_(DHCPLease.scope_id == DHCPScope.id, DHCPLease.ip_address == mirror.address),
        )
        .where(mirror.auto_from_lease.is_(True))
    )
    # The batch's scopes as one array parameter: a space's worth of them as an
    # IN list, beside the count's own list of subnets, could pass asyncpg's
    # bind-parameter limit.
    scope_ids = [row.obj.id for row in batch.rows if isinstance(row.obj, DHCPScope)]
    reservations = (
        select(cast(DHCPStaticAssignment.id, String)).where(
            DHCPStaticAssignment.scope_id == any_(literal(scope_ids, ARRAY(PG_UUID(as_uuid=True))))
        )
        # Trashed reservations too, as ``remove_ipam_for_scope_statics`` reads them.
        .execution_options(include_deleted=True)
    )
    # The column tests first: they spare every other address the lookups.
    # The back-link's also makes an address with none read false, not NULL,
    # so the NOT of the retraction's count keeps it.
    torn = [
        and_(IPAddress.auto_from_lease.is_(True), IPAddress.id.in_(lease_mirrors)),
        and_(
            IPAddress.static_assignment_id.is_not(None),
            IPAddress.static_assignment_id.in_(reservations),
        ),
    ]
    if isinstance(root, Subnet):
        torn.insert(0, and_(IPAddress.subnet_id == root.id, IPAddress.auto_from_lease.is_(True)))
    return or_(*torn)


async def _push_agentless_scope_deletes(db: AsyncSession, batch: Any) -> set[UUID]:
    """Remove every DHCP scope in a soft-delete batch from its agentless members.

    Soft-delete means "stop serving", and that has to hold on every backend.
    Agent-based (Kea) members converge on their own — a stamped scope drops
    straight out of the rendered ConfigBundle — but agentless members (Windows
    DHCP today, and any future agentless driver) only converge on an explicit
    push (#616).

    EVERY delete whose cascade can reach a DHCPScope owes this call: scope,
    subnet, block, and space. Driving it off the batch rather than a hand-rolled
    per-handler query is deliberate — the batch is the one thing that already
    knows exactly which scopes are being trashed, so a new ancestor type added to
    ``_collect_descendants`` cannot silently skip the write-through.

    ORDER IS LOAD-BEARING: call this BEFORE ``apply_soft_delete``. The push
    resolves each scope's CIDR through ``db.get(Subnet, ...)``; once the subnet
    row is stamped, the global soft-delete filter hides it and the push would
    raise ``WindowsPushError("subnet is missing from IPAM")``.

    Returns the group ids whose agents should be woken after the commit.
    """
    from app.models.dhcp import DHCPScope  # noqa: PLC0415
    from app.services.dhcp.windows_writethrough import push_scope_delete  # noqa: PLC0415

    group_ids: set[UUID] = set()
    for row in batch.rows:
        if isinstance(row.obj, DHCPScope):
            await push_scope_delete(db, row.obj)
            group_ids.add(row.obj.group_id)
    return group_ids


async def _gate_batch_scopes(db: AsyncSession, batch: Any) -> None:
    """#3748: the gates of the live scopes a subnet / block / space delete will
    trash, exclusive, before the transaction's first row lock (step 0 of
    ``app.services.lock_order``). :func:`_lock_scope_batch_rows` takes those
    scope rows ``FOR UPDATE``, which an HA pair's overlapping lease-events
    batches (each holding the scope ``FOR KEY SHARE``) starved past the command
    timeout, as they did the scope delete; the gate queues new batches behind
    this delete instead. The batch is collected with plain reads, so no row
    lock is held here."""
    from app.services.lock_order import lock_scope_gates  # noqa: PLC0415

    await lock_scope_gates(db, _batch_scope_ids(batch), exclusive=True)


async def _lock_scope_batch_rows(db: AsyncSession, batch: Any) -> None:
    """#3617: lock what a subnet / block / space delete's cascade will write,
    in the scope → mirror → zone order every lease-path writer takes
    (``app.services.lock_order``): the batch's scope rows, the lease mirrors
    of its subnets, then the zones its subnets publish into or are linked to.
    Call before the first of them is written: the reverse-zone retirement
    writes zones.

    The scope rows are taken ``FOR UPDATE``, ascending id, as the scope delete
    takes its own (#3733): a lease-events batch holds the scopes its events
    resolve to ``FOR KEY SHARE`` from its re-read until its commit, and the
    stamp's plain UPDATE (``FOR NO KEY UPDATE``) does not wait for that. So a
    batch that read a scope as live could write a lease, a mirror and a DDNS
    record into it after this delete committed and its teardown had passed
    (#3744). The batch's scopes' lease rows are not taken: their teardown runs
    after the commit, in committed batches that take them in that order
    themselves (#3744)."""
    from app.models.dhcp import DHCPScope  # noqa: PLC0415
    from app.models.ipam import IPAddress, Subnet  # noqa: PLC0415
    from app.services.lock_order import lock_zones_for_subnets  # noqa: PLC0415

    scope_ids = _batch_scope_ids(batch)
    if scope_ids:
        await db.execute(
            select(DHCPScope.id)
            .where(DHCPScope.id.in_(scope_ids))
            .order_by(DHCPScope.id)
            .with_for_update()
            .execution_options(include_deleted=True)
        )
    subnet_ids = sorted(row.obj.id for row in batch.rows if isinstance(row.obj, Subnet))
    if subnet_ids:
        await db.execute(
            select(IPAddress.id)
            .where(IPAddress.subnet_id.in_(subnet_ids), IPAddress.auto_from_lease.is_(True))
            .order_by(IPAddress.id)
            .with_for_update()
        )
        await lock_zones_for_subnets(db, subnet_ids)


async def _purge_leases_for_scope_batch(
    db: AsyncSession, batch: Any, touched_subnets: set[UUID]
) -> None:
    """Tear down each batched scope's reservation mirrors before the soft-delete stamp.

    A scope owns two kinds of derived row that the soft-delete batch does NOT
    cover: dynamic ``DHCPLease`` rows (only a nullable ``ON DELETE SET NULL``
    backlink to the scope, so they'd survive) and their + the reservations'
    IPAM mirror ``ip_address`` rows (``status="dhcp"`` / ``static_dhcp``), which
    otherwise linger visibly in the subnet table and keep counting toward
    utilization after the scope is gone. The reservations' mirrors are deleted
    here, in the delete's own transaction. The leases and their mirrors are
    not: their teardown is 100 ms a lease with DDNS on, and held to this
    commit it kept every lease-events batch renewing one of them waiting. They
    go after the commit, in committed batches (``_tear_down_trashed_scopes_leases``,
    #3744), once the scopes are in the Trash and take no event.

    MUST run BEFORE ``apply_soft_delete`` (same constraint as
    ``_push_agentless_scope_deletes``): once the scope/subnet is stamped the
    global filter hides it. Drives off ``batch.rows`` so every ancestor whose
    cascade reaches a scope — scope, subnet, block, space — is covered from one
    place.

    Does not recount: the subnets whose mirrors it freed land in
    ``touched_subnets``, and the caller recounts them once, last, just before
    its commit (#3354). The recount holds the audit-chain lock and subnet /
    block row locks to commit, so it must follow the agentless DNS retraction
    rather than hold them through it, and one pass keeps the locks in id order.
    """
    from app.models.dhcp import DHCPScope  # noqa: PLC0415
    from app.services.dhcp.static_ipam import remove_ipam_for_scope_statics  # noqa: PLC0415

    for row in batch.rows:
        if isinstance(row.obj, DHCPScope):
            await remove_ipam_for_scope_statics(db, row.obj.id, touched_subnets=touched_subnets)


async def _retract_lease_mirror_records(db: AsyncSession, root: Any, batch: Any) -> set[UUID]:
    """Withdraw the DNS records of the lease mirrors a soft delete's scopes
    leave to the teardown after its commit (#3744), before the stamp. The
    teardown revokes a mirror's DDNS one lease at a time (100 ms a lease), so
    it cannot run inside the delete; but a record left live at the stamp rides
    the batch (into a reverse zone it trashes, or retracted from one that
    stays), and a restore would bring it back for a mirror that is gone. Set
    based, as the permanent delete's retraction is. Returns the DNS groups to
    wake."""
    from app.services.dns.record_ops import retract_records_of_addresses  # noqa: PLC0415

    _count, wake = await retract_records_of_addresses(db, _mirrors_torn_down_first(root, batch))
    return wake


# ── delete_subnet ──────────────────────────────────────────────────────────


class DeleteSubnetArgs(BaseModel):
    subnet_id: UUID
    force: bool = False
    permanent: bool = False


async def _subnet_not_empty_detail(db: AsyncSession, subnet_id: UUID) -> str | None:
    """Shared non-empty check for subnet permanent-delete (#17).

    Returns the 409 detail string when the subnet still holds user IPs or
    DHCP scopes, else ``None``. Both ``preview()`` and ``apply()`` call this
    so the two can never drift. Mirrors the inline handler's count query.
    """
    from app.models.dhcp import DHCPScope
    from app.models.ipam import IPAddress, Subnet
    from app.services.ipam.subnet_placeholders import untouched_gateway_row

    # The rows the subnet's own create added (network / broadcast / the
    # untouched Gateway row, #3042) are not contents.
    user_ip_count = (
        await db.execute(
            select(func.count(IPAddress.id))
            .join(Subnet, Subnet.id == IPAddress.subnet_id)
            .where(
                IPAddress.subnet_id == subnet_id,
                not_(untouched_gateway_row()),
                IPAddress.status.notin_(["network", "broadcast", "orphan"]),
                IPAddress.auto_from_lease.is_(False),
            )
        )
    ).scalar_one()
    scope_count = (
        await db.execute(select(func.count(DHCPScope.id)).where(DHCPScope.subnet_id == subnet_id))
    ).scalar_one()
    if not (user_ip_count or scope_count):
        return None
    parts = []
    if user_ip_count:
        parts.append(f"{user_ip_count} allocated IP address" + ("es" if user_ip_count != 1 else ""))
    if scope_count:
        parts.append(f"{scope_count} DHCP scope" + ("s" if scope_count != 1 else ""))
    return (
        f"Subnet is not empty: {', '.join(parts)}. "
        "Delete the contents first, or retry with force=true to cascade."
    )


async def _preview_delete_subnet(
    db: AsyncSession, user: User, args: DeleteSubnetArgs
) -> PreviewResult:
    from app.api.v1.ipam.router import _enforce_subnet_token_scope
    from app.models.dhcp import DHCPScope
    from app.models.ipam import IPAddress, Subnet

    subnet = await db.get(Subnet, args.subnet_id)
    if subnet is None:
        return PreviewResult(ok=False, detail="Subnet not found")
    # Per-row API-token binding — mirrors the inline handler.
    _enforce_subnet_token_scope(user, args.subnet_id)

    if args.permanent and not args.force:
        # Re-run the non-empty 409 the inline permanent path raises.
        detail = await _subnet_not_empty_detail(db, args.subnet_id)
        if detail is not None:
            return PreviewResult(ok=False, detail=detail)

    mode = "Permanently delete" if args.permanent else "Soft-delete"
    parts = [f"{mode} subnet `{subnet.network}`" + (f" ({subnet.name})" if subnet.name else "")]
    if args.permanent:
        # #3a: counts move as the cascade grows → the approve-time drift check
        # catches a subnet that gained IPs/scopes since it was requested.
        scope_count = (
            await db.execute(
                select(func.count(DHCPScope.id)).where(DHCPScope.subnet_id == args.subnet_id)
            )
        ).scalar_one()
        ip_count = (
            await db.execute(
                select(func.count(IPAddress.id)).where(IPAddress.subnet_id == args.subnet_id)
            )
        ).scalar_one()
        parts.append(
            f"cascades {scope_count} DHCP scope(s) + {ip_count} IP row(s) + auto DNS cleanup"
        )
        if args.force:
            parts.append("force=true (skip non-empty check)")
    else:
        # #3a: the soft-delete cascade summary embeds the current blast radius
        # (DHCP scopes the subnet holds) so a grown cascade is detectable.
        parts.append(await _soft_delete_cascade_summary(db, subnet))
        parts.append("restorable from /admin/trash")
    return PreviewResult(ok=True, detail="ready", preview_text="; ".join(parts))


async def _apply_delete_subnet(
    db: AsyncSession, user: User, args: DeleteSubnetArgs
) -> dict[str, Any]:
    """Body factored verbatim from ipam/router.py:delete_subnet."""

    from app.api.deps import ensure_superadmin
    from app.api.v1.ipam.router import (
        _audit,
        _enforce_subnet_token_scope,
        _revoke_subnet_lease_mirrors,
        _update_block_utilization,
    )
    from app.drivers.dhcp import is_agentless
    from app.models.dhcp import DHCPConfigOp, DHCPScope, DHCPServer
    from app.models.ipam import Subnet
    from app.services.dhcp.config_bundle import build_config_bundle
    from app.services.dhcp.lease_cleanup import delete_leases_for_scope
    from app.services.dhcp.windows_writethrough import push_scope_delete
    from app.services.dns.record_ops import retract_trashed_subnet_records
    from app.services.soft_delete import apply_soft_delete, collect_soft_delete_batch

    subnet = await db.get(Subnet, args.subnet_id)
    if subnet is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subnet not found")
    _enforce_subnet_token_scope(user, args.subnet_id)

    if not args.permanent:
        # #3744: no lease row, mirror or DDNS record of the scopes' leases is
        # taken here. Their teardown (100 ms a lease with DDNS on) held to this
        # commit kept every lease-events batch renewing one of them waiting, 503
        # at 30 s, and ran the delete into the proxy's 60 s. The subnet and its
        # scopes go to the Trash and commit first, where the lease-events handler
        # takes no event for them, and the leases go after, in committed batches.
        subnet_id = subnet.id
        # Wake DHCP agents for groups whose scopes are being trashed: soft-delete
        # stamps the scopes deleted, changing rendered Kea config, but without a
        # wake convergence waits for the 12s safety tick (#512). The push +
        # group-id capture both run BEFORE apply_soft_delete stamps the batch —
        # see _push_agentless_scope_deletes.
        from app.core.agent_wake import (  # noqa: PLC0415
            collect_wake,
            dns_group_channel,
        )
        from app.services.dns.reverse_zone import retire_auto_reverse_zones  # noqa: PLC0415

        batch = await collect_soft_delete_batch(db, subnet)
        await _gate_batch_scopes(db, batch)  # #3748: before any row lock
        await _lock_scope_batch_rows(db, batch)  # #3617: scopes, mirrors, then zones
        # spatiumddi#1066 — the reverse zone this subnet auto-created rides
        # the same batch (restore brings both back) unless a sibling subnet
        # still lives in it, in which case it is re-linked and stays.
        _retired, _relinked, dns_wake_group_ids = await retire_auto_reverse_zones(
            db, subnet, batch=batch
        )
        wake_group_ids = await _push_agentless_scope_deletes(db, batch)
        touched: set[UUID] = set()  # recounted last, before commit (#3354)
        await _purge_leases_for_scope_batch(db, batch, touched)
        scope_ids = _batch_scope_ids(batch)
        cleanup_audit = await _lease_teardown_counts(db, scope_ids)
        dns_wake_group_ids |= await _retract_lease_mirror_records(db, subnet, batch)
        deleted_at = await apply_soft_delete(db, batch, user.id)
        await db.flush()
        # spatiumddi#1906 — the subnet's own A / PTR / gateway PTR in zones that
        # STAY (a reverse zone kept for a sibling, the forward zone) are
        # retracted and ride the batch; restore re-asserts them.
        records_retracted, record_wake_ids = await retract_trashed_subnet_records(
            db, batch, deleted_at, user.id
        )
        dns_wake_group_ids |= record_wake_ids
        for row in batch.rows:
            old_value = {**batch.audit_old_value(row), **cleanup_audit.get(row.obj.id, {})}
            if row.obj is subnet and records_retracted:
                old_value["dns_records_retracted"] = records_retracted
            db.add(
                _audit(
                    user,
                    "soft_delete",
                    row.resource_type,
                    str(row.obj.id),
                    row.display,
                    old_value=old_value,
                )
            )
        # Last, after the audit rows are staged and the agentless retraction is
        # done, so the audit-chain and subnet / block locks are held only to
        # commit: the scopes' freed mirrors (#3354), and the parent block's
        # rollup, which must stop counting the trashed subnet (#2412).
        await recount_subnets_and_blocks(db, touched, include_deleted=True)
        await _update_block_utilization(db, subnet.block_id)
        await db.commit()
        for gid in dns_wake_group_ids:
            collect_wake(dns_group_channel(gid))
        if await _wake_then_tear_down_leases(db, wake_group_ids, scope_ids):
            # What the teardown left: mirrors with no lease behind them, and their records.
            await _revoke_residual_subnet_mirrors(db, subnet_id, _revoke_subnet_lease_mirrors)
        return {"subnet_id": str(args.subnet_id), "mode": "soft_delete"}

    ensure_superadmin(user)

    if not args.force:
        detail = await _subnet_not_empty_detail(db, args.subnet_id)
        if detail is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

    block_id = subnet.block_id

    scope_rows = (
        (await db.execute(select(DHCPScope).where(DHCPScope.subnet_id == args.subnet_id)))
        .scalars()
        .all()
    )
    agent_servers_to_refresh: dict[uuid.UUID, DHCPServer] = {}
    # Recounted with the block below, never per scope: a recount holds its
    # locks to commit, through the next scope's push (#3354).
    touched: set[UUID] = set()
    # #3617: every scope's lease rows before the first teardown. Each one
    # locks the subnet's lease mirrors, so a subnet served by two groups had
    # its second scope's leases locked after the first's mirrors.
    if scope_rows:
        from app.models.dhcp import DHCPLease  # noqa: PLC0415
        from app.services.lock_order import lock_lease_rows, lock_scope_gates  # noqa: PLC0415

        # #3748: the scopes' gates, exclusive, before the first row lock — the
        # cascade below deletes the scope rows, which an HA pair's lease-events
        # batches (each holding a scope ``FOR KEY SHARE``) would otherwise starve.
        await lock_scope_gates(db, [s.id for s in scope_rows], exclusive=True)
        await lock_lease_rows(db, DHCPLease.scope_id.in_([s.id for s in scope_rows]))
    for scope in scope_rows:
        await push_scope_delete(db, scope)
        # Leases have a nullable ON DELETE SET NULL backlink to the scope, so the
        # subnet cascade would leave them scopeless survivors — purge them (and
        # their mirrors + DDNS) here, before db.delete(subnet). Static mirrors go
        # with the subnet's ip_address cascade below.
        await delete_leases_for_scope(db, scope.id, touched_subnets=touched)
        group_servers = (
            (
                await db.execute(
                    select(DHCPServer).where(DHCPServer.server_group_id == scope.group_id)
                )
            )
            .scalars()
            .all()
        )
        for srv in group_servers:
            if not is_agentless(srv.driver):
                agent_servers_to_refresh[srv.id] = srv

    # Withdraw the DNS records IPAM published for the subnet's addresses BEFORE
    # the cascade drops the addresses — dns_record.ip_address_id is SET NULL, so
    # a record left to the database stays served, ownerless. Through the
    # record-ops chokepoint: an agentless (Windows DNS) primary is only
    # retracted by an explicit op (#512), and in a no-views group neither is an
    # agent. spatiumddi#1151: every auto-generated record of every address — this
    # used to take only the primary A ``ip.dns_record_id`` names, leaving PTRs
    # in a hand-made or shared reverse zone, extra-zone A / AAAA and aliases.
    from app.services.dns.record_ops import retract_address_records  # noqa: PLC0415

    _records_retracted, dns_wake_group_ids = await retract_address_records(db, [subnet.id])

    # spatiumddi#1066 — the subnet's auto-created reverse zone: re-linked to
    # a sibling that still lives in it, else deleted the way the zone-delete
    # operation does it (agentless servers told, queued ops swept, records
    # deleted set-based, the group woken) instead of a bare row DELETE.
    from app.core.agent_wake import collect_wake, dns_group_channel  # noqa: PLC0415
    from app.services.dns.reverse_zone import retire_auto_reverse_zones  # noqa: PLC0415

    _retired, _relinked, zone_wake_group_ids = await retire_auto_reverse_zones(db, subnet)
    dns_wake_group_ids |= zone_wake_group_ids

    db.add(
        _audit(
            user,
            "delete",
            "subnet",
            str(subnet.id),
            f"{subnet.network} ({subnet.name})",
            old_value={"network": str(subnet.network), "name": subnet.name},
        )
    )
    await db.delete(subnet)
    await db.flush()
    await recount_subnets_and_blocks(db, touched)
    await _update_block_utilization(db, block_id)

    for server in agent_servers_to_refresh.values():
        bundle = await build_config_bundle(db, server)
        server.config_etag = bundle.etag
        existing = (
            await db.execute(
                select(DHCPConfigOp).where(
                    DHCPConfigOp.server_id == server.id,
                    DHCPConfigOp.op_type == "apply_config",
                    DHCPConfigOp.status == "pending",
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                DHCPConfigOp(
                    server_id=server.id,
                    op_type="apply_config",
                    payload={"etag": bundle.etag},
                    status="pending",
                )
            )

    await db.commit()
    for gid in dns_wake_group_ids:
        collect_wake(dns_group_channel(gid))
    return {"subnet_id": str(args.subnet_id), "mode": "delete"}


_OP_DELETE_SUBNET = Operation(
    name="delete_subnet",
    description="Delete a subnet (soft-delete batch, or permanent cascade of DHCP scopes + auto DNS).",
    args_model=DeleteSubnetArgs,
    preview=_preview_delete_subnet,
    apply=_apply_delete_subnet,
    category="ipam",
    required_permission=("delete", "subnet"),
)
register(_OP_DELETE_SUBNET)


# ── delete_block ───────────────────────────────────────────────────────────


class DeleteBlockArgs(BaseModel):
    block_id: UUID
    permanent: bool = False


async def _block_not_empty_detail(db: AsyncSession, block_id: UUID, network: Any) -> str | None:
    """Shared non-empty check for block permanent-delete (#17)."""
    from app.models.ipam import IPBlock, Subnet

    subnet_count = (
        await db.execute(
            select(func.count()).select_from(Subnet).where(Subnet.block_id == block_id)
        )
    ).scalar_one()
    child_block_count = (
        await db.execute(
            select(func.count()).select_from(IPBlock).where(IPBlock.parent_block_id == block_id)
        )
    ).scalar_one()
    if not (subnet_count or child_block_count):
        return None
    parts = []
    if child_block_count:
        parts.append(f"{child_block_count} child block(s)")
    if subnet_count:
        parts.append(f"{subnet_count} subnet(s)")
    return (
        f"Block {network} still contains {' and '.join(parts)}. "
        "Delete or move them before deleting the block."
    )


async def _preview_delete_block(
    db: AsyncSession, user: User, args: DeleteBlockArgs
) -> PreviewResult:
    from app.models.ipam import IPBlock

    block = await db.get(IPBlock, args.block_id)
    if block is None:
        return PreviewResult(ok=False, detail="IP block not found")

    if args.permanent:
        detail = await _block_not_empty_detail(db, args.block_id, block.network)
        if detail is not None:
            return PreviewResult(ok=False, detail=detail)
        return PreviewResult(
            ok=True,
            detail="ready",
            preview_text=f"Permanently delete empty block `{block.network}` ({block.name})",
        )

    # #3a: embed the current cascade counts so the approve-time drift check
    # catches new child blocks / subnets added since the request.
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            f"Soft-delete block `{block.network}` ({block.name}) — "
            f"{await _soft_delete_cascade_summary(db, block)}; "
            "restorable from /admin/trash"
        ),
    )


async def _apply_delete_block(
    db: AsyncSession, user: User, args: DeleteBlockArgs
) -> dict[str, Any]:
    """Body factored verbatim from ipam/router.py:delete_block."""
    from app.api.deps import ensure_superadmin
    from app.api.v1.ipam.router import _audit, _update_block_utilization
    from app.models.ipam import IPBlock
    from app.services.soft_delete import apply_soft_delete, collect_soft_delete_batch

    block = await db.get(IPBlock, args.block_id)
    if block is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP block not found")

    if args.permanent:
        ensure_superadmin(user)
        detail = await _block_not_empty_detail(db, args.block_id, block.network)
        if detail is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

        db.add(
            _audit(
                user,
                "delete",
                "ip_block",
                str(block.id),
                f"{block.network} ({block.name})",
                old_value={"network": str(block.network)},
            )
        )
        await db.delete(block)
        await db.commit()
        return {"block_id": str(args.block_id), "mode": "delete"}

    from app.core.agent_wake import collect_wake  # noqa: PLC0415

    batch = await collect_soft_delete_batch(db, block)
    # A block cascade reaches DHCP scopes (via its subnets), so it owes the same
    # agentless write-through the scope + subnet paths do (#616). Before the stamp.
    # spatiumddi#2734 — the reverse zones its subnets auto-created ride the
    # batch, as they do on a lone subnet delete (#1066).
    from app.services.dns.reverse_zone import (  # noqa: PLC0415
        retire_auto_reverse_zones_for_batch,
    )

    await _gate_batch_scopes(db, batch)  # #3748: before any row lock
    await _lock_scope_batch_rows(db, batch)  # #3617
    zone_wake_group_ids = await retire_auto_reverse_zones_for_batch(db, batch)
    wake_group_ids = await _push_agentless_scope_deletes(db, batch)
    touched: set[UUID] = set()  # recounted last, before commit (#3354)
    await _purge_leases_for_scope_batch(db, batch, touched)
    scope_ids = _batch_scope_ids(batch)
    cleanup_audit = await _lease_teardown_counts(db, scope_ids)
    zone_wake_group_ids |= await _retract_lease_mirror_records(db, block, batch)
    deleted_at = await apply_soft_delete(db, batch, user.id)
    # spatiumddi#1906 — every trashed subnet's DNS records are retracted with it.
    from app.core.agent_wake import dns_group_channel  # noqa: PLC0415
    from app.services.dns.record_ops import retract_trashed_subnet_records  # noqa: PLC0415

    _retracted, dns_wake_group_ids = await retract_trashed_subnet_records(
        db, batch, deleted_at, user.id
    )
    dns_wake_group_ids |= zone_wake_group_ids
    for row in batch.rows:
        db.add(
            _audit(
                user,
                "soft_delete",
                row.resource_type,
                str(row.obj.id),
                row.display,
                old_value={**batch.audit_old_value(row), **cleanup_audit.get(row.obj.id, {})},
            )
        )
    # Last, after the audit rows and the retraction, so the audit-chain and
    # subnet / block locks are held only to commit (#3354): the scopes' freed
    # mirrors, then the ancestors' rollups, which stop counting the trashed
    # subtree (#2412).
    await recount_subnets_and_blocks(db, touched, include_deleted=True)
    if block.parent_block_id is not None:
        await db.flush()
        await _update_block_utilization(db, block.parent_block_id)
    await db.commit()
    for gid in dns_wake_group_ids:
        collect_wake(dns_group_channel(gid))
    await _wake_then_tear_down_leases(db, wake_group_ids, scope_ids)  # #3744
    return {"block_id": str(args.block_id), "mode": "soft_delete"}


_OP_DELETE_BLOCK = Operation(
    name="delete_block",
    description="Delete an IP block (soft-delete cascade, or permanent if empty).",
    args_model=DeleteBlockArgs,
    preview=_preview_delete_block,
    apply=_apply_delete_block,
    category="ipam",
    required_permission=("delete", "ip_block"),
)
register(_OP_DELETE_BLOCK)


# ── delete_space ───────────────────────────────────────────────────────────


class DeleteSpaceArgs(BaseModel):
    space_id: UUID
    permanent: bool = False


async def _space_not_empty_detail(db: AsyncSession, space_id: UUID, name: str) -> str | None:
    """Shared non-empty check for space permanent-delete (#17)."""
    from app.models.ipam import IPBlock, Subnet

    subnet_count = (
        await db.execute(
            select(func.count()).select_from(Subnet).where(Subnet.space_id == space_id)
        )
    ).scalar_one()
    block_count = (
        await db.execute(
            select(func.count()).select_from(IPBlock).where(IPBlock.space_id == space_id)
        )
    ).scalar_one()
    if not (subnet_count or block_count):
        return None
    parts = []
    if block_count:
        parts.append(f"{block_count} block(s)")
    if subnet_count:
        parts.append(f"{subnet_count} subnet(s)")
    return (
        f"IP space {name!r} still contains {' and '.join(parts)}. "
        "Delete or move them before deleting the space."
    )


async def _preview_delete_space(
    db: AsyncSession, user: User, args: DeleteSpaceArgs
) -> PreviewResult:
    from app.models.ipam import IPSpace

    space = await db.get(IPSpace, args.space_id)
    if space is None:
        return PreviewResult(ok=False, detail="IP space not found")

    if args.permanent:
        detail = await _space_not_empty_detail(db, args.space_id, space.name)
        if detail is not None:
            return PreviewResult(ok=False, detail=detail)
        return PreviewResult(
            ok=True,
            detail="ready",
            preview_text=f"Permanently delete empty IP space `{space.name}`",
        )

    # #3a: embed the current cascade counts so the approve-time drift check
    # catches new blocks / subnets / scopes added since the request.
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            f"Soft-delete IP space `{space.name}` — "
            f"{await _soft_delete_cascade_summary(db, space)}; "
            "restorable from /admin/trash"
        ),
    )


async def _apply_delete_space(
    db: AsyncSession, user: User, args: DeleteSpaceArgs
) -> dict[str, Any]:
    """Body factored verbatim from ipam/router.py:delete_space."""
    from app.api.deps import ensure_superadmin
    from app.api.v1.ipam.router import _audit
    from app.models.ipam import IPSpace
    from app.services.soft_delete import apply_soft_delete, collect_soft_delete_batch

    space = await db.get(IPSpace, args.space_id)
    if space is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP space not found")

    if args.permanent:
        ensure_superadmin(user)
        detail = await _space_not_empty_detail(db, args.space_id, space.name)
        if detail is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

        db.add(
            _audit(
                user,
                "delete",
                "ip_space",
                str(space.id),
                space.name,
                old_value={"name": space.name},
            )
        )
        await db.delete(space)
        await db.commit()
        return {"space_id": str(args.space_id), "mode": "delete"}

    from app.core.agent_wake import collect_wake  # noqa: PLC0415

    batch = await collect_soft_delete_batch(db, space)
    # A space cascade reaches DHCP scopes (via its subnets), so it owes the same
    # agentless write-through the scope + subnet paths do (#616). Before the stamp.
    # spatiumddi#2734 — the reverse zones its subnets auto-created ride the
    # batch, as they do on a lone subnet delete (#1066).
    from app.services.dns.reverse_zone import (  # noqa: PLC0415
        retire_auto_reverse_zones_for_batch,
    )

    await _gate_batch_scopes(db, batch)  # #3748: before any row lock
    await _lock_scope_batch_rows(db, batch)  # #3617
    zone_wake_group_ids = await retire_auto_reverse_zones_for_batch(db, batch)
    wake_group_ids = await _push_agentless_scope_deletes(db, batch)
    touched: set[UUID] = set()  # recounted last, before commit (#3354)
    await _purge_leases_for_scope_batch(db, batch, touched)
    scope_ids = _batch_scope_ids(batch)
    cleanup_audit = await _lease_teardown_counts(db, scope_ids)
    zone_wake_group_ids |= await _retract_lease_mirror_records(db, space, batch)
    deleted_at = await apply_soft_delete(db, batch, user.id)
    # spatiumddi#1906 — every trashed subnet's DNS records are retracted with it.
    from app.core.agent_wake import dns_group_channel  # noqa: PLC0415
    from app.services.dns.record_ops import retract_trashed_subnet_records  # noqa: PLC0415

    _retracted, dns_wake_group_ids = await retract_trashed_subnet_records(
        db, batch, deleted_at, user.id
    )
    dns_wake_group_ids |= zone_wake_group_ids
    for row in batch.rows:
        db.add(
            _audit(
                user,
                "soft_delete",
                row.resource_type,
                str(row.obj.id),
                row.display,
                old_value={**batch.audit_old_value(row), **cleanup_audit.get(row.obj.id, {})},
            )
        )
    await recount_subnets_and_blocks(db, touched, include_deleted=True)  # last (#3354)
    await db.commit()
    for gid in dns_wake_group_ids:
        collect_wake(dns_group_channel(gid))
    await _wake_then_tear_down_leases(db, wake_group_ids, scope_ids)  # #3744
    return {"space_id": str(args.space_id), "mode": "soft_delete"}


_OP_DELETE_SPACE = Operation(
    name="delete_space",
    description="Delete an IP space (soft-delete subtree, or permanent if empty).",
    args_model=DeleteSpaceArgs,
    preview=_preview_delete_space,
    apply=_apply_delete_space,
    category="ipam",
    required_permission=("delete", "ip_space"),
)
register(_OP_DELETE_SPACE)


# ── delete_zone ────────────────────────────────────────────────────────────


class DeleteZoneArgs(BaseModel):
    group_id: UUID
    zone_id: UUID
    permanent: bool = False


async def _preview_delete_zone(db: AsyncSession, user: User, args: DeleteZoneArgs) -> PreviewResult:
    from app.api.v1.dns.router import _reject_if_synthesised_zone, _require_zone

    try:
        zone = await _require_zone(args.group_id, args.zone_id, db)
        _reject_if_synthesised_zone(zone, "delete")
    except HTTPException as exc:
        return PreviewResult(ok=False, detail=str(exc.detail))

    mode = "Permanently delete" if args.permanent else "Soft-delete"
    if args.permanent:
        # #3a: count the records this zone holds so a permanent delete of a
        # zone that grew records since request is caught by the drift check.
        from app.models.dns import DNSRecord  # noqa: PLC0415

        rec_count = (
            await db.execute(
                select(func.count(DNSRecord.id)).where(DNSRecord.zone_id == args.zone_id)
            )
        ).scalar_one()
        suffix = (
            f" — cascades {rec_count} DNS record(s)"
            " (pushes a remove-zone write-through to agentless servers first)"
        )
    else:
        # #3a: the soft-delete cascade summary embeds the current record count.
        suffix = (
            f" — {await _soft_delete_cascade_summary(db, zone)};"
            " the zone + its records are restorable from /admin/trash"
        )
    return PreviewResult(
        ok=True, detail="ready", preview_text=f"{mode} DNS zone `{zone.name}`{suffix}"
    )


async def _apply_delete_zone(db: AsyncSession, user: User, args: DeleteZoneArgs) -> dict[str, Any]:
    """Body factored verbatim from dns/router.py:delete_zone."""
    from app.api.deps import ensure_superadmin
    from app.api.v1.dns.router import (
        _push_zone_to_agentless_servers,
        _reject_if_synthesised_zone,
        _require_zone,
    )
    from app.core.agent_wake import collect_wake, dns_group_channel
    from app.models.audit import AuditLog
    from app.services.soft_delete import apply_soft_delete, collect_soft_delete_batch

    # Parity with the route (#8): ``delete`` on ``dns_zone`` admits the
    # default soft-delete (#1861), and only the permanent branch takes a
    # superadmin, as on the IPAM deletes. The approve path bypasses the route's
    # dependencies, so this is where it is enforced for it. Checked before any
    # side effect; ensure_superadmin raises HTTPException(403).
    if args.permanent:
        ensure_superadmin(user)

    zone = await _require_zone(args.group_id, args.zone_id, db)  # raises 404 if absent
    _reject_if_synthesised_zone(zone, "delete")

    if not args.permanent:
        # #3535: the zone row before its records, as every writer of them takes
        # it (``_require_zone``). The stamp below writes the zone row first
        # anyway (its autoflush); this lock makes that order this branch's own.
        zone = await _require_zone(args.group_id, args.zone_id, db, lock="write")
        # Soft-delete is the moment the zone leaves the bundle, so it is the
        # moment its queued ops become unapplyable: left behind, each one is
        # shipped up to five times against a zone the agent no longer serves,
        # then parks as ``failed`` forever (review of #964). Sweep here — the
        # trash purge and permanent-delete-from-trash only ever see rows that
        # came through this path.
        # And only once the zone row is held (#3535): a record write that held
        # it first queued its op before it let go. A sweep before the lock
        # could not see that op, and it stayed queued against the trashed zone.
        from app.services.dns.record_ops import sweep_zone_ops  # noqa: PLC0415

        await sweep_zone_ops(db, zone, zone.group_id)
        batch = await collect_soft_delete_batch(db, zone)
        await apply_soft_delete(db, batch, user.id)
        for row in batch.rows:
            db.add(
                AuditLog(
                    user_id=user.id,
                    user_display_name=user.display_name,
                    auth_source=user.auth_source,
                    action="soft_delete",
                    resource_type=row.resource_type,
                    resource_id=str(row.obj.id),
                    resource_display=row.display,
                    old_value=batch.audit_old_value(row),
                    result="success",
                )
            )
        collect_wake(dns_group_channel(args.group_id))
        await db.commit()
        return {"zone_id": str(args.zone_id), "mode": "soft_delete"}

    collect_wake(dns_group_channel(args.group_id))
    # Set-based first, ORM second. ``db.delete(zone)`` alone cascades through
    # the ORM: every record row is loaded, tracked and DELETEd one by one
    # inside the request. On a 250k-1M record zone that is minutes of a
    # single transaction on the request loop — the api's liveness probes
    # timed out and the pod was killed mid-delete (appliance sizing
    # campaign, 2026-09-02). ``dns_record.zone_id`` already cascades at the
    # FK, so delete the records in one statement and let the ORM cascade
    # find nothing left to load. The zone's queued record ops go with it
    # (``sweep_zone_ops``, shared with zone_move): a ``pending``/``in_flight``
    # op for a zone that no longer exists would only fail on the agent and
    # surface as a zombie on the next resync.
    from sqlalchemy import delete as sa_delete

    from app.models.dns import DNSRecord
    from app.services.dns.record_ops import sweep_zone_ops
    from app.services.ipam.zone_binding import prune_zone_ids

    # #3535: the zone row before its records, FOR UPDATE (the lock its DELETE
    # takes), as every writer of them takes the zone row first
    # (``_require_zone``). A record write that came first finishes, and its
    # record goes with the rest; one that comes second waits, then reads no
    # zone (404). With the records deleted first, a writer could take the zone
    # row at its serial bump and wait on its record: a deadlock with this.
    # #3691: the ``ip_address`` rows the delete will null out (the zone's
    # records' mirrors, forward / reverse links) come before the zone row, the
    # global order (``app.services.lock_order``): a lease batch holds a mirror
    # and waits for the zone.
    from app.services.lock_order import (
        address_ids_of_zones,
        lock_addresses_before,
        lock_zone_gate,
    )

    # #3724: the zone's sync gate, exclusive, before any row: the next batch of
    # an auto-sync run queues behind this delete rather than ahead of it.
    await lock_zone_gate(db, [args.zone_id], exclusive=True)
    zone = await lock_addresses_before(
        db,
        lambda: address_ids_of_zones(db, [args.zone_id]),
        lambda: _require_zone(args.group_id, args.zone_id, db, lock="delete"),
    )
    # The queued ops once the zone row is held, as on the soft branch: a record
    # write that held the row first has committed its op by now. Swept before
    # the lock, that op outlived the zone with a NULL ``zone_id``.
    await sweep_zone_ops(db, zone, zone.group_id)
    # The agentless servers drop the zone only now, still before the rows go.
    # Pushed before the lock, the removal reached them while a record write
    # that held the zone row was still under way, and that write's record
    # then went to a server that had just lost the zone.
    kept: list[str] = []
    await _push_zone_to_agentless_servers(db, zone, "delete", kept_notes=kept)
    await db.execute(sa_delete(DNSRecord).where(DNSRecord.zone_id == zone.id))
    await db.delete(zone)
    # IPAM names zones in text / JSONB columns with no foreign key (#3443).
    await prune_zone_ids(db, [zone.id])
    # #3503: audited after the zone row is deleted. The audit row's flush
    # takes the audit-chain lock; deleting the zone after it waited for a
    # record create holding the zone row, which waits for that lock.
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="delete",
            resource_type="dns_zone",
            resource_id=str(zone.id),
            resource_display=zone.name,
            # #3812: provider copies left in place because another group's live
            # zone of the same name shares them.
            new_value={"provider_copies_kept": kept} if kept else None,
            result="success",
        )
    )
    await db.commit()
    out: dict[str, Any] = {"zone_id": str(args.zone_id), "mode": "delete"}
    if kept:
        out["provider_copies_kept"] = kept
    return out


_OP_DELETE_ZONE = Operation(
    name="delete_zone",
    description="Delete a DNS zone (soft-delete batch, or permanent with agentless write-through).",
    args_model=DeleteZoneArgs,
    preview=_preview_delete_zone,
    apply=_apply_delete_zone,
    category="dns",
    required_permission=("delete", "dns_zone"),
)
register(_OP_DELETE_ZONE)


# ── delete_scope ───────────────────────────────────────────────────────────


class DeleteScopeArgs(BaseModel):
    scope_id: UUID
    permanent: bool = False


async def _preview_delete_scope(
    db: AsyncSession, user: User, args: DeleteScopeArgs
) -> PreviewResult:
    from app.api.v1.dhcp.phone_profiles import refuse_scope_removal_orphaning_classes
    from app.models.dhcp import DHCPLease, DHCPScope

    scope = await db.get(DHCPScope, args.scope_id)
    if scope is None:
        return PreviewResult(ok=False, detail="Scope not found")
    # #3388 — the apply refuses this; say so before an approval is queued.
    try:
        await refuse_scope_removal_orphaning_classes(db, scope, "delete this scope")
    except HTTPException as exc:
        return PreviewResult(ok=False, detail=str(exc.detail))
    mode = "Permanently delete" if args.permanent else "Soft-delete"
    # A scope carries its pools + reservations into the batch (#617), so both
    # modes report a real blast radius. This used to claim a scope was a cascade
    # leaf, which made the approval preview read as "nothing else affected" for
    # a scope holding hundreds of reservations.
    cascade = await _soft_delete_cascade_summary(db, scope)
    # Dynamic leases aren't in the soft-delete batch (they're server-owned), but
    # scope deletion now clears them too (#623) — surface the count so the
    # preview / approval doesn't under-report the blast radius.
    lease_count = (
        await db.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.scope_id == scope.id)
        )
    ).scalar_one()
    if lease_count:
        cascade += f" + {lease_count} dynamic lease" + ("s" if lease_count != 1 else "")
    if args.permanent:
        suffix = (
            f" — {cascade} (unrecoverable; pushes a remove-scope write-through "
            "to Windows members first)"
        )
    else:
        suffix = f" — {cascade}; restorable from /admin/trash"
    return PreviewResult(
        ok=True, detail="ready", preview_text=f"{mode} DHCP scope `{scope.id}`{suffix}"
    )


async def _tear_down_trashed_scopes_leases(db: AsyncSession, scope_ids: list[UUID]) -> bool:
    """The leases of scopes a delete just put in the Trash, after its commit
    (#3733, #3744). Returns whether every one of them is torn down.

    Inside the delete's transaction their teardown held every one of the
    scopes' lease rows to the commit, about 100 ms a lease with DDNS on, so
    each lease-events batch renewing one of them waited for the whole of it
    (the API cut those waits at 30 s), and a delete of 1,000 leases ran past
    the proxy's 60 s while it carried on. Now the scopes are in the Trash first,
    where the lease-events handler takes no event for them, and the leases go
    in committed batches (``tear_down_scope_leases``) under one time bound for
    the request (the server delete's, #2290). What is left when it runs out
    is handed to the background task, scope by scope; a lost enqueue is picked
    up by the lease sweep. A group delete, which takes the scopes themselves
    away, is refused until that has finished.
    """
    import time  # noqa: PLC0415

    from app.services.dhcp.lease_cleanup import (  # noqa: PLC0415
        SCOPE_DELETE_INLINE_DEADLINE_S,
        tear_down_scope_leases,
    )

    deadline = time.monotonic() + SCOPE_DELETE_INLINE_DEADLINE_S
    left: list[UUID] = []
    for sid in scope_ids:
        try:
            removed, _mirrors, done = await tear_down_scope_leases(
                db, sid, deadline_s=max(0.0, deadline - time.monotonic())
            )
        except Exception as exc:  # noqa: BLE001 — #3748: the delete committed above; a
            # failed batch (a statement timeout, say) must not answer 500 for it. Not
            # BaseException: cancellation still propagates. The batches already
            # committed stay; the task tears down the rest.
            logger.warning(
                "dhcp_scope_delete_lease_teardown_failed", scope=str(sid), error=str(exc)
            )
            await db.rollback()
            removed, done = 0, False
        if not done:
            logger.info(
                "dhcp_scope_delete_lease_teardown_handed_on", scope=str(sid), torn_down=removed
            )
            left.append(sid)
    if left:
        try:
            from app.tasks.dhcp_lease_cleanup import tear_down_trashed_scope_leases

            for sid in left:
                tear_down_trashed_scope_leases.delay(str(sid))
        except Exception as exc:  # noqa: BLE001 — broker unavailable: a lost enqueue is safe,
            # the lease sweep tears down the leases of any scope in the Trash every 300 s.
            logger.warning("dhcp_scope_delete_lease_teardown_enqueue_failed", error=str(exc))
    return not left


async def _tear_down_trashed_scope_leases(db: AsyncSession, scope_id: UUID) -> None:
    """One scope's leases after its delete commits (``_tear_down_trashed_scopes_leases``)."""
    await _tear_down_trashed_scopes_leases(db, [scope_id])


def _batch_scope_ids(batch: Any) -> list[UUID]:
    """The ids of the scopes a soft-delete batch holds, ascending."""
    from app.models.dhcp import DHCPScope  # noqa: PLC0415

    return sorted(row.obj.id for row in batch.rows if isinstance(row.obj, DHCPScope))


async def _lease_teardown_counts(
    db: AsyncSession, scope_ids: list[UUID]
) -> dict[UUID, dict[str, int]]:
    """Per scope, the leases and lease mirrors the teardown after the commit
    will remove, for its audit row, which is written before the response
    (non-negotiable #4); read before the stamp."""
    from app.services.dhcp.lease_cleanup import scope_lease_counts  # noqa: PLC0415

    out: dict[UUID, dict[str, int]] = {}
    for sid in scope_ids:
        leases, mirrors = await scope_lease_counts(db, sid)
        out[sid] = {"leases_removed": leases, "lease_mirrors_removed": mirrors}
    return out


async def _wake_then_tear_down_leases(
    db: AsyncSession, group_ids: set[UUID], scope_ids: list[UUID]
) -> bool:
    """Wake the DHCP groups of a delete's scopes, then tear their leases down
    (#3744). The router publishes ``collect_wake`` only after the handler
    returns, i.e. after the teardown, so Kea would go on serving the trashed
    scopes for up to its 20 s (#3748). Still collected too: a duplicate wake
    only re-reads the same state. Returns whether every lease is torn down."""
    from app.core.agent_wake import (  # noqa: PLC0415
        collect_wake,
        dhcp_group_channel,
        publish_wake,
    )

    channels = [dhcp_group_channel(gid) for gid in group_ids]
    collect_wake(*channels)
    if channels:
        await publish_wake(*channels)
    return await _tear_down_trashed_scopes_leases(db, scope_ids) if scope_ids else True


async def _revoke_residual_subnet_mirrors(db: AsyncSession, subnet_id: UUID, revoke: Any) -> None:
    """The lease mirrors a trashed subnet still holds once its scopes' leases
    are gone (an address with no lease behind it), with their DDNS records
    (#428, #3744). Committed in its own transaction, after the delete's; a
    failure leaves them for a restore to find, and must not answer 500 for a
    delete that happened."""
    from app.models.ipam import Subnet  # noqa: PLC0415

    try:
        subnet = (
            await db.execute(
                select(Subnet).where(Subnet.id == subnet_id).execution_options(include_deleted=True)
            )
        ).scalar_one_or_none()
        if subnet is not None:
            await revoke(db, subnet)
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — see above; not BaseException
        logger.warning(
            "subnet_delete_residual_mirror_teardown_failed", subnet=str(subnet_id), error=str(exc)
        )
        await db.rollback()


async def _apply_delete_scope(
    db: AsyncSession, user: User, args: DeleteScopeArgs
) -> dict[str, Any]:
    """Body factored verbatim from dhcp/scopes.py:delete_scope."""
    from app.api.deps import ensure_superadmin
    from app.api.v1.dhcp._audit import write_audit
    from app.api.v1.dhcp.phone_profiles import refuse_scope_removal_orphaning_classes
    from app.core.agent_wake import collect_wake, dhcp_group_channel, publish_wake
    from app.models.dhcp import DHCPScope
    from app.services.dhcp.lease_cleanup import delete_leases_for_scope, scope_lease_counts
    from app.services.dhcp.static_ipam import remove_ipam_for_scope_statics
    from app.services.dhcp.windows_writethrough import push_scope_delete
    from app.services.soft_delete import apply_soft_delete, collect_soft_delete_batch

    # Parity with the route (#8): soft-delete on ``delete`` on ``dhcp_scope``
    # (#1861), the permanent branch superadmin-only, checked before any side
    # effect.
    if args.permanent:
        ensure_superadmin(user)

    # #3748 — the scope's gate, exclusive, before any row lock: lease-events
    # batches from both members of an HA pair hold the scope ``FOR KEY SHARE``
    # in overlapping turns, which starves the ``FOR UPDATE`` below; the gate
    # queues them behind this delete instead.
    from app.services.lock_order import lock_scope_gates  # noqa: PLC0415

    await lock_scope_gates(db, [args.scope_id], exclusive=True)
    scope = await db.get(DHCPScope, args.scope_id)
    if scope is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")
    # #3388 — refused before any side effect: a phone class this scope keeps
    # rendering may be named by another scope's pool.
    await refuse_scope_removal_orphaning_classes(db, scope, "delete this scope")
    if not args.permanent:
        # #3733 — the scope row first, before anything this delete writes. A
        # lease-events batch holds it ``FOR KEY SHARE`` from the moment it
        # finds the scope live until it commits (``agent_lease_events``), so
        # the stamp below waits for the batches that already took the scope's
        # events, and every later batch waits for the stamp and then finds
        # the scope in the Trash. A delete that waited here for another one
        # finds the scope gone.
        locked = (
            await db.execute(select(DHCPScope.id).where(DHCPScope.id == scope.id).with_for_update())
        ).scalar_one_or_none()
        if locked is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")
    group_id = scope.group_id  # read before anything can expire ``scope``
    collect_wake(dhcp_group_channel(group_id))

    # Deleted means deleted on every backend (#616). Agent-based (Kea) members
    # converge by themselves — the soft-deleted scope drops straight out of the
    # rendered ConfigBundle — but agentless members (Windows DHCP today, and any
    # future agentless driver) only converge on an explicit push. This used to
    # fire on the permanent path only, and since the UI never sends
    # ``permanent=true``, a scope deleted from the UI stayed live on the Windows
    # box forever: not removed by the trash permanent-delete (which skips the
    # write-through hooks) nor by the purge sweep (a Core DELETE that runs no
    # Python). Fire it on both paths.
    await push_scope_delete(db, scope)

    # Tear down the scope's DHCP-derived rows that the soft-delete batch / FK
    # CASCADE do NOT cover: dynamic leases (only a nullable ON DELETE SET NULL
    # backlink, so they'd survive) + their and the reservations' IPAM mirror
    # rows (which otherwise linger visibly in the subnet table and keep counting
    # toward utilization). Delete both — leases are ephemeral polled state
    # (re-populated from the next poll on restore), and freeing the IPs to a
    # deleted row folds them back into free gaps. The permanent path tears the
    # leases down here, before the CASCADE, so the scope + subnet are still
    # resolvable; the soft path after its stamp commits (#3733, below) and
    # counts them here for the audit row. The reservations' mirrors go here
    # on both. The freed mirrors are recounted once, last, before the commit
    # (#3354).
    touched: set[UUID] = set()
    if args.permanent:
        leases_removed, lease_mirrors = await delete_leases_for_scope(
            db, scope.id, touched_subnets=touched
        )
    else:
        leases_removed, lease_mirrors = await scope_lease_counts(db, scope.id)
    statics_released = await remove_ipam_for_scope_statics(db, scope.id, touched_subnets=touched)
    cleanup_audit = {
        "leases_removed": leases_removed,
        "lease_mirrors_removed": lease_mirrors,
        "static_mirrors_removed": statics_released,
    }

    if not args.permanent:
        batch = await collect_soft_delete_batch(db, scope)
        await apply_soft_delete(db, batch, user.id)
        for row in batch.rows:
            write_audit(
                db,
                user=user,
                action="soft_delete",
                resource_type=row.resource_type,
                resource_id=str(row.obj.id),
                resource_display=row.display,
                old_value={**batch.audit_old_value(row), **cleanup_audit},
            )
        await recount_subnets_and_blocks(db, touched)
        await db.commit()
        # #3748 — Kea stops serving the trashed scope now, not after the teardown.
        # Still collected above too, so the router's flush publishes it a second
        # time: wakes are advisory and a duplicate only re-reads the same state.
        await publish_wake(dhcp_group_channel(group_id))
        await _tear_down_trashed_scope_leases(db, args.scope_id)
        return {"scope_id": str(args.scope_id), "mode": "soft_delete"}

    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_scope",
        resource_id=str(scope.id),
        resource_display=str(scope.id),
        old_value=cleanup_audit,
    )
    await db.delete(scope)
    await recount_subnets_and_blocks(db, touched)
    await db.commit()
    return {"scope_id": str(args.scope_id), "mode": "delete"}


_OP_DELETE_SCOPE = Operation(
    name="delete_scope",
    description="Delete a DHCP scope (soft-delete, or permanent with Windows write-through).",
    args_model=DeleteScopeArgs,
    preview=_preview_delete_scope,
    apply=_apply_delete_scope,
    category="dhcp",
    required_permission=("delete", "dhcp_scope"),
)
register(_OP_DELETE_SCOPE)


# ── delete_group ───────────────────────────────────────────────────────────


class DeleteGroupArgs(BaseModel):
    group_id: UUID


async def _group_scope_counts(db: AsyncSession, group_id: UUID) -> tuple[int, int]:
    """``(live, in_trash)``: the scopes a DHCP server group holds (#1399).

    The default soft-delete filter hides the scopes in Trash, so the live count
    is a plain count and the total opts out of the filter.
    """
    from app.models.dhcp import DHCPScope  # noqa: PLC0415

    stmt = select(func.count()).select_from(DHCPScope).where(DHCPScope.group_id == group_id)
    live = (await db.execute(stmt)).scalar_one()
    total = (await db.execute(stmt.execution_options(include_deleted=True))).scalar_one()
    return live, total - live


def _group_holds_scopes(name: str, live: int) -> str:
    """Why a group holding live scopes is refused (#1399)."""
    return (
        f"DHCP server group {name!r} still holds {live} scope(s). Delete its "
        "scopes first, then the group. A deleted scope goes to Trash; deleting "
        "the group then deletes its scopes in Trash for good, with their pools "
        "and reservations."
    )


async def _preview_delete_group(
    db: AsyncSession, user: User, args: DeleteGroupArgs
) -> PreviewResult:
    from app.models.dhcp import DHCPServer, DHCPServerGroup

    g = await db.get(DHCPServerGroup, args.group_id)
    if g is None:
        return PreviewResult(ok=False, detail="Server group not found")
    server_count = (
        await db.execute(
            select(func.count())
            .select_from(DHCPServer)
            .where(DHCPServer.server_group_id == args.group_id)
        )
    ).scalar_one()
    if server_count:
        return PreviewResult(
            ok=False,
            detail=(
                f"DHCP server group {g.name!r} still contains "
                f"{server_count} server(s). Move them to another group "
                "(or standalone) before deleting the group."
            ),
        )
    live, in_trash = await _group_scope_counts(db, args.group_id)
    if live:
        return PreviewResult(ok=False, detail=_group_holds_scopes(g.name, live))
    if in_trash:
        return PreviewResult(
            ok=True,
            detail="ready",
            preview_text=(
                f"Delete DHCP server group `{g.name}` and, for good, its "
                f"{in_trash} scope(s) in Trash with their pools and reservations"
            ),
        )
    return PreviewResult(
        ok=True, detail="ready", preview_text=f"Delete empty DHCP server group `{g.name}`"
    )


async def _apply_delete_group(
    db: AsyncSession, user: User, args: DeleteGroupArgs
) -> dict[str, Any]:
    """Body factored verbatim from dhcp/server_groups.py:delete_group."""
    from app.api.deps import ensure_superadmin
    from app.api.v1.dhcp._audit import write_audit
    from app.models.dhcp import DHCPServer, DHCPServerGroup

    # The original DELETE route was fully SuperAdmin-gated (#8).
    ensure_superadmin(user)

    g = await db.get(DHCPServerGroup, args.group_id)
    if g is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server group not found")

    server_count = (
        await db.execute(
            select(func.count())
            .select_from(DHCPServer)
            .where(DHCPServer.server_group_id == args.group_id)
        )
    ).scalar_one()
    if server_count:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"DHCP server group {g.name!r} still contains "
                f"{server_count} server(s). Move them to another group "
                "(or standalone) before deleting the group."
            ),
        )

    # A group still holding a live scope is refused like one holding servers
    # (#1399): the cascade below would destroy the scope with its pools and
    # reservations, none of them into Trash. The guard counted servers only
    # since scopes moved from the server onto the group.
    live, _ = await _group_scope_counts(db, args.group_id)
    if live:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=_group_holds_scopes(g.name, live)
        )

    # Only the group's scopes already in Trash reach here. Deleting the group
    # hard-deletes them, and the FK CASCADE takes their reservations with them —
    # no Python runs, so nothing would release the IPAM mirrors and the
    # addresses would be stranded at ``status="static_dhcp"`` pointing at rows
    # Postgres has dropped (#618). Delete the mirror rows (not just free them)
    # so the IPs fold back into free gaps. The scopes' dynamic leases (nullable
    # ON DELETE SET NULL backlink) would otherwise survive the group delete, so
    # tear those + their mirrors down too.
    from app.models.dhcp import DHCPLease, DHCPScope  # noqa: PLC0415
    from app.services.dhcp.lease_cleanup import delete_leases_for_scope  # noqa: PLC0415
    from app.services.dhcp.static_ipam import remove_ipam_for_scope_statics  # noqa: PLC0415

    # #3744 — the scopes are in the Trash already, so their leases go first, in
    # committed batches, and the delete below finds none. Their teardown held
    # to this transaction's commit kept every lease-events batch renewing one
    # of them waiting, and ran the delete past the proxy's 60 s. What the
    # deadline leaves is handed to the scopes' background task and the delete
    # is refused until it has finished: torn down here instead, in this
    # transaction, it would hold those leases' rows to the commit again, and
    # left to the group's FK CASCADE the leases would outlive their scopes
    # with no scope to find them by. The commit ends this transaction: read
    # what the rest needs.
    group_id = g.id
    trashed_ids = (
        (
            await db.execute(
                select(DHCPScope.id)
                .where(DHCPScope.group_id == args.group_id)
                .order_by(DHCPScope.id)
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    if trashed_ids:
        if not await _tear_down_trashed_scopes_leases(db, list(trashed_ids)):
            left = (
                await db.execute(
                    select(func.count())
                    .select_from(DHCPLease)
                    .where(DHCPLease.scope_id.in_(list(trashed_ids)))
                )
            ).scalar_one()
            await db.commit()  # ends the read
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"The DHCP server group's scopes in the Trash still hold {left} "
                    "lease(s), which are being torn down in the background. Retry "
                    "the delete in a minute."
                ),
                headers={"Retry-After": "60"},
            )
        refreshed = await db.get(DHCPServerGroup, group_id)
        if refreshed is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Server group not found"
            )
        g = refreshed

    group_scopes = (
        (
            await db.execute(
                select(DHCPScope)
                .where(DHCPScope.group_id == args.group_id)
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    released = 0
    touched: set[UUID] = set()  # recounted once, last, before commit (#3354)
    for sc in group_scopes:
        released += await remove_ipam_for_scope_statics(db, sc.id, touched_subnets=touched)
        await delete_leases_for_scope(db, sc.id, touched_subnets=touched)

    # One row per scope the group takes with it (#1957's convention, as the
    # Trash purge writes for a subnet's scopes): the scope rows go by FK
    # CASCADE, which runs no Python.
    for sc in group_scopes:
        write_audit(
            db,
            user=user,
            action="delete",
            resource_type="dhcp_scope",
            resource_id=str(sc.id),
            resource_display=sc.name,
            old_value={
                "name": sc.name,
                "address_family": sc.address_family,
                "subnet_id": str(sc.subnet_id),
                "purged_with": "dhcp_server_group",
                "group": g.name,
            },
        )

    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_server_group",
        resource_id=str(g.id),
        resource_display=g.name,
        old_value={
            "ipam_mirrors_released": released,
            "trashed_scopes_deleted": len(group_scopes),
        },
    )
    await db.delete(g)
    await recount_subnets_and_blocks(db, touched)
    await db.commit()
    return {"group_id": str(args.group_id), "mode": "delete"}


_OP_DELETE_GROUP = Operation(
    name="delete_group",
    description=(
        "Delete a DHCP server group (refused while it holds servers or scopes; "
        "its scopes already in Trash are deleted with it, for good)."
    ),
    args_model=DeleteGroupArgs,
    preview=_preview_delete_group,
    apply=_apply_delete_group,
    category="dhcp",
    # The REST route is SuperAdmin-only; this declares the granular backstop
    # the approver is checked against (a superadmin approver passes via {*,*}).
    required_permission=("delete", "dhcp_server_group"),
)
register(_OP_DELETE_GROUP)


# ── create_network_block (active block sync #601) ───────────────────────────
#
# Unlike the six deletes, this is a *create* — but it is a genuine risky op:
# a network block, once armed, pushes a real firewall/gateway block that can
# lock a device (or the operator) out of the network. Gating it through the
# same two-person workflow is the issue's explicit guardrail #6. The op body
# does the network_block upsert + audit + immediate reconcile-enqueue; the
# router delegates to it on the inline path and the approve endpoint replays
# it under the approver's identity.


class CreateNetworkBlockArgs(BaseModel):
    kind: str
    value: str
    reason: str = "quarantine"
    description: str = ""
    source: str = "manual"
    source_ref: str | None = None
    expires_at: datetime | None = None


async def _preview_create_network_block(
    db: AsyncSession, user: User, args: CreateNetworkBlockArgs
) -> PreviewResult:
    from app.models.block_sync import BLOCK_KINDS, BLOCK_SOURCES
    from app.services.block_sync.reconcile import (
        applicable_targets_for_kind,
        normalize_block_value,
    )

    if args.kind not in BLOCK_KINDS:
        return PreviewResult(ok=False, detail=f"kind must be one of {BLOCK_KINDS}")
    if args.source not in BLOCK_SOURCES:
        return PreviewResult(ok=False, detail=f"source must be one of {BLOCK_SOURCES}")
    try:
        value = normalize_block_value(args.kind, args.value)
    except ValueError as exc:
        return PreviewResult(ok=False, detail=str(exc))
    targets = await applicable_targets_for_kind(db, args.kind)
    names = ", ".join(f"{tk}:{tid}" for tk, tid in targets) or "no armed targets"
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            f"Block {args.kind} `{value}` and push to {len(targets)} armed " f"target(s) ({names})"
        ),
    )


async def _apply_create_network_block(
    db: AsyncSession, user: User, args: CreateNetworkBlockArgs
) -> dict[str, Any]:
    from app.models.audit import AuditLog
    from app.models.block_sync import NetworkBlock
    from app.services.block_sync.reconcile import (
        applicable_targets_for_kind,
        normalize_block_value,
    )

    value = normalize_block_value(args.kind, args.value)
    existing = (
        await db.execute(
            select(NetworkBlock).where(NetworkBlock.kind == args.kind, NetworkBlock.value == value)
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.enabled = True
        existing.reason = args.reason
        existing.description = args.description
        existing.source = args.source
        existing.source_ref = args.source_ref
        existing.expires_at = args.expires_at
        existing.updated_by_user_id = user.id
        block = existing
        action = "update"
    else:
        block = NetworkBlock(
            kind=args.kind,
            value=value,
            reason=args.reason,
            description=args.description,
            source=args.source,
            source_ref=args.source_ref,
            enabled=True,
            expires_at=args.expires_at,
            created_by_user_id=user.id,
            updated_by_user_id=user.id,
        )
        db.add(block)
        action = "create"
    await db.flush()

    targets = await applicable_targets_for_kind(db, args.kind)
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action=action,
            resource_type="network_block",
            resource_id=str(block.id),
            resource_display=f"{args.kind}:{value}",
            new_value={
                "kind": args.kind,
                "value": value,
                "reason": args.reason,
                "source": args.source,
                "targets": len(targets),
            },
        )
    )
    await db.commit()

    # Immediate converge on each armed target (broker-down → 60 s sweep).
    try:
        from app.tasks.block_sync import reconcile_target_now  # noqa: PLC0415

        for target_kind, target_id in targets:
            try:
                reconcile_target_now.delay(target_kind, str(target_id))
            except Exception:  # noqa: BLE001 — broker unavailable; the 60 s
                pass  # sweep converges this target, so a lost enqueue is safe
    except Exception:  # noqa: BLE001 — task import/broker issues never fail the write
        pass

    return {"block_id": str(block.id), "kind": args.kind, "value": value, "mode": action}


_OP_CREATE_NETWORK_BLOCK = Operation(
    name="create_network_block",
    description="Create/arm a network block (IP or MAC) and push it to armed OPNsense/UniFi targets.",
    args_model=CreateNetworkBlockArgs,
    preview=_preview_create_network_block,
    apply=_apply_create_network_block,
    category="security",
    required_permission=("admin", "manage_block_sync"),
)
register(_OP_CREATE_NETWORK_BLOCK)


# Registry-completeness anchor for the startup assertion (sibling slice):
# every operation name the seeded policies reference must exist here.
RISKY_OPERATION_NAMES: frozenset[str] = frozenset(
    {
        "delete_subnet",
        "delete_block",
        "delete_space",
        "delete_zone",
        "delete_scope",
        "delete_group",
        "create_network_block",
    }
)


def _assert_registered() -> None:
    """Defensive: prove all six names registered at import (catches a
    rename that desyncs the seeded policies from the registry)."""
    missing = [n for n in RISKY_OPERATION_NAMES if get_operation(n) is None]
    if missing:  # pragma: no cover — import-time invariant
        raise RuntimeError(f"risky operations not registered: {missing}")


_assert_registered()
