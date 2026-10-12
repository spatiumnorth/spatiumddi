"""Move a DNS server row from one server group to another (issue #934).

A DNS server was addressable only under its group (``/dns/groups/{gid}/
servers/{sid}``) and had no way to change groups, while the DHCP side has
carried ``server_group_id`` on its update payload since #430. Discussion
#933 hit the gap the obvious way: an auto-registered agent lands in
``default``, the operator creates the group they actually wanted, and the
server is stuck.

The move is not a column write. A DNS server accumulates group-scoped
state that becomes a lie the moment its group changes:

  * ``DNSServerZoneState`` rows are per ``(server, zone)`` against the OLD
    group's zones — left behind, the Zone Sync pill reports convergence
    for zones this server no longer serves.
  * pending ``DNSRecordOp`` rows are RFC 2136 updates queued for old-group
    zones. Shipping them after the move sends the new group's daemon
    updates for zones it has never heard of.
  * ``config_apply_status`` (#882) says whether the LIVE config is the
    SAVED one. A move changes the saved one, so a carried-over ``ok`` is
    false at the instant of commit — and NULL means UNKNOWN, never ok.
  * ``is_primary`` is per-group and load-bearing: ``resolve_primary_server``
    drops every record write for a group with no primary, and
    ``build_config_bundle`` fetches the primary with ``scalar_one_or_none``,
    so a group with TWO would 500 the agent long-poll rather than merely
    pick wrong.

So the move is a small transaction rather than an assignment, and it lives
here rather than in the router so it can be tested without HTTP.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import structlog
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import (
    appliance_channel,
    collect_wake,
    dns_group_channel,
    dns_server_channel,
)
from app.models.appliance import Appliance
from app.models.dns import (
    DNSRecordOp,
    DNSServer,
    DNSServerGroup,
    DNSServerZoneState,
)
from app.services.dns.record_ops import QUEUED_OP_STATES
from app.services.dns.tsig import ensure_group_tsig_key

logger = structlog.get_logger(__name__)


class ServerMoveError(Exception):
    """A move the control plane refuses.

    Carries the HTTP status the router should answer with, so the reason
    survives the service → router boundary instead of collapsing into one
    generic 400.
    """

    def __init__(self, detail: str, status_code: int = 409) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


@dataclass(frozen=True)
class ServerMoveResult:
    """What the move actually did — folded into the audit row so the
    trail says more than "group_id changed"."""

    old_group_id: uuid.UUID
    new_group_id: uuid.UUID
    zone_state_purged: int
    pending_ops_dropped: int
    demoted: bool
    old_group_new_primary_id: uuid.UUID | None
    elected_primary: bool
    target_tsig_key_generated: bool
    appliance_repointed_id: uuid.UUID | None

    def as_audit_value(self) -> dict[str, object]:
        return {
            "old_group_id": str(self.old_group_id),
            "new_group_id": str(self.new_group_id),
            "zone_state_purged": self.zone_state_purged,
            "pending_ops_dropped": self.pending_ops_dropped,
            "demoted_from_primary": self.demoted,
            "old_group_new_primary_id": (
                str(self.old_group_new_primary_id) if self.old_group_new_primary_id else None
            ),
            "elected_primary_in_target": self.elected_primary,
            "target_tsig_key_generated": self.target_tsig_key_generated,
            "appliance_repointed_id": (
                str(self.appliance_repointed_id) if self.appliance_repointed_id else None
            ),
        }


async def ensure_group_single_driver(
    db: AsyncSession,
    group_id: uuid.UUID,
    driver: str,
    *,
    group_name: str,
    hint: str,
    exclude_server_id: uuid.UUID | None = None,
) -> None:
    """Refuse (422) putting a ``driver`` server into a group that already
    runs a different driver (#1540).

    A group is single-driver (docs/drivers/DNS_DRIVERS.md §5.1): its
    rendered config, catalog-zone semantics and AXFR shape all assume
    one driver, record fan-out follows the primary's driver, and the
    driver-gated operations 422 on a mixed group. Shared by the move
    path (which has always checked), server create, and a driver change
    on update — the two paths that used to manufacture mixed groups
    silently. ``exclude_server_id`` is the server being changed, whose
    own current driver must not count against its new one.
    """
    conditions = [
        DNSServer.group_id == group_id,
        DNSServer.driver != driver,
    ]
    if exclude_server_id is not None:
        conditions.append(DNSServer.id != exclude_server_id)
    res = await db.execute(select(DNSServer.driver).where(*conditions).distinct())
    foreign_drivers = sorted({d for d in res.scalars().all() if d})
    if foreign_drivers:
        raise ServerMoveError(
            f"Group {group_name!r} runs {foreign_drivers}; this server runs "
            f"{driver!r}. A server group is single-driver — {hint}",
            status_code=422,
        )


async def _elect_primary(
    db: AsyncSession, group_id: uuid.UUID, *, exclude_id: uuid.UUID
) -> DNSServer | None:
    """Pick a replacement primary for a group that has just lost one.

    Prefers a server that can actually accept writes: enabled, not paused
    for maintenance (``record_ops`` excludes paused servers from
    primary cluster-math), oldest first so the choice is deterministic
    and stable across repeated moves rather than whatever the planner
    returns.

    ``exclude_id`` is load-bearing rather than defensive. The election runs
    while the departing server is still ``group_id == group_id`` in this
    session — the reassignment has not been flushed — so without it the
    query re-elects the very server being demoted. The move then silently
    does nothing: the old group's flag sits on a member that has left, and
    the target group ends up with two primaries, which is the shape that
    500s the agent long-poll rather than merely picking wrong.
    """
    base = (
        select(DNSServer)
        .where(DNSServer.group_id == group_id, DNSServer.id != exclude_id)
        .order_by(DNSServer.created_at, DNSServer.id)
        .limit(1)
    )
    candidate = (
        await db.execute(
            base.where(
                DNSServer.is_enabled.is_(True),
                DNSServer.maintenance_mode.is_(False),
            )
        )
    ).scalar_one_or_none()
    if candidate is None:
        # Every remaining server is disabled or paused. Fall back to any
        # member rather than leaving the group primary-less: a paused
        # primary still beats none, because ``resolve_primary_server``
        # returning None drops record writes SILENTLY (a log line, no
        # error to the caller), whereas a paused one is visible in the UI.
        candidate = (await db.execute(base)).scalar_one_or_none()
    if candidate is not None:
        candidate.is_primary = True
    return candidate


async def move_server_to_group(
    db: AsyncSession, server: DNSServer, target_group: DNSServerGroup
) -> ServerMoveResult | None:
    """Re-home ``server`` into ``target_group``.

    Returns ``None`` when the server is already in the target group (an
    idempotent PUT re-sending the current ``group_id`` is a no-op, not an
    error). Raises ``ServerMoveError`` when the move is refused.

    The caller commits. Nothing here flushes state the caller cannot roll
    back, so a later failure in the same handler discards the whole move.
    """
    old_group_id = server.group_id
    if old_group_id == target_group.id:
        return None

    # ── Refusals ──────────────────────────────────────────────────────
    #
    # Name collision: ``uq_dns_server_group_name`` would raise anyway, but
    # as a bare integrity error naming a constraint rather than telling the
    # operator which name clashed.
    clash = await db.execute(
        select(DNSServer.id).where(
            DNSServer.group_id == target_group.id,
            DNSServer.name == server.name,
        )
    )
    if clash.first() is not None:
        raise ServerMoveError(
            f"Group {target_group.name!r} already has a server named "
            f"{server.name!r}. Rename one of them first.",
            status_code=409,
        )

    # Driver homogeneity. A group is single-driver (docs/drivers/
    # DNS_DRIVERS.md §5.1): its rendered config, catalog-zone semantics and
    # AXFR shape all assume one driver, and the driver-gated operations
    # (DNSSEC signing, ALIAS records) 422 on a mixed group. A move is a
    # NEW operation with no existing installs to break, so it fails
    # closed here instead of manufacturing a state that breaks something
    # else afterwards. The check itself is shared with server create and
    # driver-change updates (#1540).
    await ensure_group_single_driver(
        db,
        target_group.id,
        server.driver,
        group_name=target_group.name,
        hint=f"move it to a {server.driver}-only group, or an empty one.",
    )

    # ── Purge state that belongs to the old group ─────────────────────
    zone_state_purged = (
        await db.execute(
            sa_delete(DNSServerZoneState).where(DNSServerZoneState.server_id == server.id)
        )
    ).rowcount or 0
    # ``in_flight`` as well as ``pending``: an op already shipped in a bundle
    # is not finished with. ``ack_op`` resets a NACKed one back to ``pending``
    # (fewer than 5 attempts), and that ack can arrive AFTER the move — which
    # would put an RFC 2136 update for an old-group zone back in the queue and
    # ship it to the new group's daemon, exactly what this purge exists to
    # prevent. ``build_config_bundle`` already treats the two states as one
    # live set when it retires ops for an agentless server.
    pending_ops_dropped = (
        await db.execute(
            sa_delete(DNSRecordOp).where(
                DNSRecordOp.server_id == server.id,
                DNSRecordOp.state.in_(QUEUED_OP_STATES),
            )
        )
    ).rowcount or 0

    # #882 verdict refers to a bundle from the old group. NULL = UNKNOWN.
    server.config_apply_status = None
    server.config_apply_error = None
    server.config_failed_etag = None
    server.config_apply_at = None

    # ── Primary bookkeeping, on both sides ────────────────────────────
    demoted = server.is_primary
    old_group_new_primary_id: uuid.UUID | None = None
    if demoted:
        server.is_primary = False
        replacement = await _elect_primary(db, old_group_id, exclude_id=server.id)
        old_group_new_primary_id = replacement.id if replacement else None

    server.group_id = target_group.id

    # Elect in the target only if it has none — never demote a primary the
    # operator already chose there.
    target_primaries = (
        await db.execute(
            select(func.count())
            .select_from(DNSServer)
            .where(
                DNSServer.group_id == target_group.id,
                DNSServer.is_primary.is_(True),
                DNSServer.id != server.id,
            )
        )
    ).scalar_one()
    elected_primary = target_primaries == 0
    if elected_primary:
        server.is_primary = True

    # The agent renders the group's TSIG key into ``tsig/ddns.key`` and
    # signs its loopback RFC 2136 updates with it. A group created through
    # the UI has never been through agent registration, so it may have no
    # key at all — generate one now rather than shipping a bundle whose
    # dynamic-update path cannot authenticate.
    target_tsig_key_generated = ensure_group_tsig_key(target_group)

    # ── Appliance-registered servers: repoint the parent appliance ─────
    #
    # On the #170 appliance path the DNS agent is not configured from its own
    # environment — the supervisor derives it from ``Appliance.
    # assigned_dns_group_id``. That pointer feeds ``_build_role_assignment``,
    # which hands the supervisor both the ``AGENT_GROUP`` written into
    # ``role-compose.env`` AND the #50 DoT/DoH/DoQ ports opened in the
    # per-role nftables drop-in. Leaving it on the old group means the
    # firewall keeps the OLD group's encrypted-transport ports: move into a
    # group serving DoT on 8853 and the agent listens on a port nftables
    # never opens — a silent, config-clean failure. And because the same
    # pointer supplies AGENT_GROUP, an agent whose volume is later wiped
    # would re-register into the old group as a duplicate row.
    #
    # Only repointed when it currently names the group being left: an
    # appliance deliberately assigned elsewhere is not ours to redirect.
    appliance_repointed_id: uuid.UUID | None = None
    if server.appliance_id is not None:
        appliance = await db.get(Appliance, server.appliance_id)
        if appliance is not None and appliance.assigned_dns_group_id == old_group_id:
            appliance.assigned_dns_group_id = target_group.id
            appliance_repointed_id = appliance.id
            # Per-appliance desired state changed, so wake the supervisor's
            # heartbeat long-poll rather than making it wait out its interval
            # for a firewall rule its agent already needs.
            collect_wake(appliance_channel(appliance.id))

    # Both groups' bundles change shape (a member left one and joined the
    # other), and the server's own channel is what reaches an agent already
    # parked in a long-poll — its subscription was built from the OLD group,
    # so the group wake alone would not reach it.
    collect_wake(
        dns_group_channel(old_group_id),
        dns_group_channel(target_group.id),
        dns_server_channel(server.id),
    )

    logger.info(
        "dns_server_moved_group",
        server_id=str(server.id),
        server_name=server.name,
        old_group_id=str(old_group_id),
        new_group_id=str(target_group.id),
        zone_state_purged=zone_state_purged,
        pending_ops_dropped=pending_ops_dropped,
    )

    return ServerMoveResult(
        old_group_id=old_group_id,
        new_group_id=target_group.id,
        zone_state_purged=zone_state_purged,
        pending_ops_dropped=pending_ops_dropped,
        demoted=demoted,
        old_group_new_primary_id=old_group_new_primary_id,
        elected_primary=elected_primary,
        target_tsig_key_generated=target_tsig_key_generated,
        appliance_repointed_id=appliance_repointed_id,
    )
