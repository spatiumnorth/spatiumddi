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
  * ``is_primary`` is per-group and load-bearing: it picks the server an
    agentless group writes through (a group with none used to drop every
    record write; since #2276 ``resolve_primary_server`` stands in the
    election's pick and a beat sweep re-stamps the flag), and a group with
    TWO used to 500 the agent long-poll, which is why every primary lookup
    now caps at one.

So the move is a small transaction rather than an assignment, and it lives
here rather than in the router so it can be tested without HTTP.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

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
from app.models.dns import (
    DNSRecordOp,
    DNSServer,
    DNSServerGroup,
    DNSServerOptions,
    DNSServerZoneState,
    DNSTrustAnchor,
)
from app.services.appliance.cluster_dns_group import cluster_dns_group_refusal
from app.services.appliance.ownership import owning_appliance_for_dns_server
from app.services.dns import technitium_api_scope
from app.services.dns.dnssec_signers import second_signer_refusal
from app.services.dns.record_ops import QUEUED_OP_STATES, primary_candidate
from app.services.dns.row_locks import lock_op_ids, lock_zone_state_rows
from app.services.dns.tsig import ensure_group_tsig_key
from app.services.dns.tsig_algorithms import group_key_refusal

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


# #1782 — Technitium catalog zones are broken in both roles (the producer's
# member zones inherit the catalog's transfer Deny / notify None, undoing the
# #734 grant; the consumer's SecondaryCatalog has no TSIG and stays empty).
# The real fix is #1766 (1.1.0); until then SpatiumDDI stops claiming it.
CATALOG_UNSUPPORTED_DRIVERS = frozenset({"technitium", "technitium_api"})


def catalog_unsupported_message(drivers: list[str] | set[str]) -> str:
    bad = ", ".join(sorted(set(drivers) & CATALOG_UNSUPPORTED_DRIVERS))
    return (
        f"Catalog zones are not supported on Technitium (driver {bad}): its member "
        "zones inherit the catalog zone's zone-transfer Deny and notify None, which "
        "stops zone transfers, drift checks and NOTIFY, and its consumer catalog is "
        "created without TSIG, so it stays empty. Support is tracked in #1766 (1.1.0)."
    )


async def ensure_group_catalog_compatible(
    db: AsyncSession, group: DNSServerGroup, driver: str
) -> None:
    """Refuse (422) putting a ``driver`` server into a catalog-enabled group
    when that driver cannot do catalog zones (#1782)."""
    if group.catalog_zones_enabled and driver in CATALOG_UNSUPPORTED_DRIVERS:
        raise ServerMoveError(
            f"Group {group.name!r} has catalog zones enabled. "
            + catalog_unsupported_message({driver}),
            status_code=422,
        )


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
    # #1858 — a Technitium server cannot use an hmac-sha224 key the group
    # already holds; joining would install it and fail every signed transfer.
    if refusal := await group_key_refusal(db, group_id, {driver}):
        raise ServerMoveError(f"Group {group_name!r}: {refusal}", status_code=422)
    # #2266 — only BIND9 renders DNSSEC trust anchors; a group holding some
    # would have them silently ignored (and validation weakened) by a server
    # of any other driver. Mirrors the 422 on adding an anchor.
    if driver != "bind9":
        n_anchors = (
            await db.execute(
                select(func.count(DNSTrustAnchor.id))
                .join(DNSServerOptions, DNSTrustAnchor.server_options_id == DNSServerOptions.id)
                .where(DNSServerOptions.group_id == group_id)
            )
        ).scalar_one()
        if n_anchors:
            raise ServerMoveError(
                f"Group {group_name!r} has DNSSEC trust anchors, which only BIND9 applies; "
                f"a {driver!r} server would ignore them. Remove the anchors first.",
                status_code=422,
            )
    # #1784 — the experimental agentless Technitium driver supports ONE
    # server per group. Enforced on every path that puts a server in a group
    # (create, driver change, move) because they all come through here.
    if driver == technitium_api_scope.DRIVER:
        if await technitium_api_scope.count_other_servers(db, group_id, exclude_server_id):
            raise ServerMoveError(
                technitium_api_scope.single_server_message(group_name), status_code=422
            )


async def elect_primary(
    db: AsyncSession, group_id: uuid.UUID, *, exclude_id: uuid.UUID | None
) -> DNSServer | None:
    """Pick a replacement primary for a group that has just lost one — by a
    move out of it, or by its primary being deleted (#2276).

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
    500s the agent long-poll rather than merely picking wrong. ``None`` is
    for a caller that has already flushed the departing rows away (the
    appliance revoke, which can delete several of one group's servers).
    """
    # The ordering (enabled + unpaused, oldest first, else any member) lives
    # in ``primary_candidate`` so the write path's stand-in and the beat
    # self-heal pick the same server this does (#2276).
    candidate = await primary_candidate(db, group_id, exclude_id=exclude_id)
    if candidate is not None:
        candidate.is_primary = True
    return candidate


async def lock_server_row(db: AsyncSession, server_id: Any) -> None:
    """Lock everything a group move writes, in the order ``row_locks`` sets
    (#1703, #1929), before the move's first write to any of it.

    Its zone-state rows and queued ops first, then the server row ``FOR
    UPDATE``. ``FOR UPDATE`` because the move changes ``group_id``, a column
    of the unique index ``uq_dns_server_group_name``; taken any later, after a
    weaker write to the row (the primary demotion, a plain field on the same
    PUT, the Fleet engine switch's driver), it waited for the ``FOR KEY
    SHARE`` a worker's bundle insert holds while the worker waited for that
    weaker write: 40P01 (#1703). The zone-state rows and ops come first
    because that is the order the agent's poll, heartbeat and zone-state
    report take them in; taking the server row first instead deadlocked the
    poll, which marks its ops before it writes ``last_config_etag`` (#1929's
    walk of #1923).

    Runs without autoflush, so a write the caller has already made to the
    instance is not flushed ahead of the locks. A write the caller has already
    FLUSHED holds the weaker lock already, so callers take this before their
    first flush of the row.
    """
    with db.no_autoflush:
        await lock_zone_state_rows(db, DNSServerZoneState.server_id == server_id)
        await lock_op_ids(
            db,
            DNSRecordOp.server_id == server_id,
            DNSRecordOp.state.in_(QUEUED_OP_STATES),
        )
        await db.execute(select(DNSServer.id).where(DNSServer.id == server_id).with_for_update())


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
    await lock_server_row(db, server.id)

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
    await ensure_group_catalog_compatible(db, target_group, server.driver)

    # #1762 — a server joining a group that already has one and holds signed
    # zones would sign them with its own keys. Enabled or not: a disabled
    # agent still receives and serves the bundle.
    refusal = await second_signer_refusal(db, target_group, driver=server.driver)
    if refusal is not None:
        raise ServerMoveError(refusal, status_code=422)

    # #1427 — the move repoints the owning appliance's DNS group (below), and
    # a control-plane cluster serves one: refuse a cluster member's server a
    # group the cluster's other DNS members are not in. The roles PUT, which
    # moves the appliance's own servers through here, has already refused or
    # passed the same group, so it never trips this.
    appliance = await owning_appliance_for_dns_server(db, server)
    if appliance is not None and appliance.assigned_dns_group_id == old_group_id:
        roles = list(appliance.assigned_roles or [])
        refusal = await cluster_dns_group_refusal(
            db,
            appliance,
            roles=roles,
            group_id=target_group.id,
            prev_roles=set(roles),
            prev_group_id=appliance.assigned_dns_group_id,
        )
        if refusal is not None:
            raise ServerMoveError(refusal, status_code=422)

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
        replacement = await elect_primary(db, old_group_id, exclude_id=server.id)
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
    # Found by FK, else by the same hostname rule Fleet uses (#1749): agents
    # register by hostname and never set ``appliance_id``. Looked up with the
    # refusals above.
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
