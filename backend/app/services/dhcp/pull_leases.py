"""Pull leases from a DHCP server and reconcile into SpatiumDDI's DB.

Today this path is exercised by the Windows DHCP read-only driver (Path
A — WinRM + PowerShell), but the shape is driver-agnostic: any driver
that implements ``get_leases`` can plug in.

**Semantics — set-reconcile (upsert + absence-delete):**

 * Upsert one ``DHCPLease`` row per ``(server_id, ip_address)`` seen on
   the wire. New rows are marked ``state="active"``; existing active
   rows have ``expires_at`` / ``hostname`` / ``mac_address`` refreshed
   and ``last_seen_at`` bumped to ``now()``.
 * Mirror each active lease into IPAM as an ``IPAddress`` row with
   ``status="dhcp"`` and ``auto_from_lease=True`` — but only if the
   lease IP falls within a known ``Subnet.network``. IPs outside any
   managed subnet are tracked as leases but not mirrored.
 * **Any active lease we previously tracked for this server that did
   NOT appear in the wire response is gone from the DHCP server** —
   an admin deleted it, or it was released + cleaned up on the server
   before we polled. Delete the ``DHCPLease`` row and, if we created
   the IPAM mirror (``auto_from_lease=True``), drop that too — first
   revoking any DDNS records the mirror published, so a vanished lease
   doesn't leave an orphaned A/PTR behind (#482). The driver's
   ``get_leases`` is the ground truth; absence means deleted, **except**
   for a wholly-empty wire response: an empty list is indistinguishable
   from a transient driver hiccup, so the zero-wire floor guard (#482)
   skips the absence-delete for that poll and lets the time-based
   ``dhcp_lease_cleanup`` expiry sweep reclaim genuinely-removed leases.

The time-based ``dhcp_lease_cleanup`` sweep continues to handle leases
that drift past ``expires_at`` without being polled (e.g., between
polls, or when lease pull is disabled). The two mechanisms overlap
harmlessly: expiry sweeps anything the pull missed, pull deletes
anything the sweep hasn't seen yet.

**Phase 1 — topology**, for drivers that also implement ``get_scopes``
(only ``windows_dhcp`` today): the server's scopes, pools and
reservations are reconciled the same way, by diff-merge — see
``_upsert_scope``. Reservations are matched on MAC so they keep their
row id across polls, which is what lets an ``ip_address`` mirror
back-link to one and stay valid (#620). Absence still means deleted,
under the same floor guards (``_absence_delete_ok``).

The same phase records what the server holds and its Windows failover
relationships (#1110, ``services.dhcp.windows_failover``). When more than
one Windows member of the group holds a scope, only ONE of them — the
scope's reconcile owner — imports its view of it; the others report and are
compared against it. Failover partners do not sync configuration, so two
holders routinely disagree, and each merging its own view undid the other
on every poll.

Per CLAUDE.md non-negotiable #9, the whole operation is idempotent: a
second run over the same wire state is a no-op (the dedup key is
``(server_id, ip_address)`` and all updates are set-to-observed).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import sanitize_hostname
from app.drivers.dhcp import get_driver, is_agentless
from app.models.dhcp import (
    DHCPLease,
    DHCPPool,
    DHCPScope,
    DHCPServer,
    DHCPStaticAssignment,
)
from app.models.ipam import IPAddress, Subnet
from app.services.dhcp.ipam_mirror import insert_ipam_mirror_row
from app.services.dhcp.lease_cleanup import purge_lease
from app.services.dhcp.lease_history import record_lease_history
from app.services.dhcp.normalize import norm_ip, norm_mac
from app.services.dhcp.static_ipam import remove_ipam_for_static, upsert_ipam_for_static
from app.services.dhcp.windows_failover import (
    GroupObservations,
    Verdict,
    canonical_cidr,
    classify_serving,
    load_group_observations,
    reconcile_owner,
    record_failover_observation,
    record_scope_observation,
)


def _refresh_lease_owned_row(
    row: IPAddress, lease: dict[str, Any], mac: str, now: datetime
) -> None:
    """Refresh an auto-from-lease mirror row from the wire lease."""
    row.mac_address = mac
    if lease.get("hostname"):
        row.hostname = lease.get("hostname")
    row.last_seen_at = now
    row.last_seen_method = "dhcp"


logger = structlog.get_logger(__name__)


@dataclass
class PullLeasesResult:
    server_leases: int = 0  # count returned by the driver
    imported: int = 0  # new DHCPLease rows inserted
    refreshed: int = 0  # existing DHCPLease rows updated in place
    removed: int = 0  # DHCPLease rows dropped because they vanished from the wire
    ipam_created: int = 0  # new IPAddress rows mirrored
    ipam_refreshed: int = 0  # existing auto_from_lease rows bumped
    ipam_revoked: int = 0  # auto_from_lease IPAddress rows deleted alongside removed leases
    out_of_scope: int = 0  # leases whose IP isn't in any subnet
    # Topology counters (populated when the driver supports get_scopes).
    scopes_imported: int = 0  # new DHCPScope rows added
    scopes_refreshed: int = 0  # existing DHCPScope rows updated in place
    scopes_skipped_no_subnet: int = 0  # scope CIDR not tracked in IPAM — skipped
    pools_synced: int = 0  # DHCPPool rows created or changed by the import
    statics_synced: int = 0  # DHCPStaticAssignment rows created or changed
    pools_removed: int = 0  # DHCPPool rows gone from the wire
    statics_removed: int = 0  # DHCPStaticAssignment rows gone from the wire
    # #1110 — scopes this server also holds but whose import belongs to
    # another member of the group (see ``windows_failover.reconcile_owner``).
    scopes_deferred: int = 0
    errors: list[str] = field(default_factory=list)
    # #1110 — conditions worth telling an operator that are not a failure of
    # THIS poll: two Windows members serving a scope uncoordinated, failover
    # partners whose configuration has drifted, a failover read that was
    # denied. Persistent by nature, so unlike ``errors`` they do not by
    # themselves make the scheduled pull write an audit row every tick; the
    # group and scope views show the same state from the stored observations.
    warnings: list[str] = field(default_factory=list)
    # #428 — DNS group ids whose zones received a DDNS record this pull;
    # the caller publishes an agent wake for them AFTER its commit so the
    # records converge instantly instead of on the agent's safety tick.
    dns_wake_group_ids: set[str] = field(default_factory=set)


async def pull_leases_from_server(
    db: AsyncSession,
    server: DHCPServer,
    *,
    apply: bool = True,
) -> PullLeasesResult:
    """Poll ``server`` for active leases and reconcile into the DB.

    ``apply=False`` returns the counts without writing — useful for
    dry-run previews from the UI.

    Only drivers registered as agentless participate; agent-based
    drivers (kea) already stream lease events over the agent channel
    and would double-count.
    """
    result = PullLeasesResult()

    if not is_agentless(server.driver):
        result.errors.append(
            f"driver {server.driver!r} is agent-based; lease pull is not applicable"
        )
        return result

    try:
        driver = get_driver(server.driver)
    except ValueError as exc:
        result.errors.append(str(exc))
        return result

    subnets = await _load_subnet_cache(db)

    # Phase 1 — topology (scopes + pools + reservations). Optional: only
    # runs for drivers that expose ``get_scopes``. For each scope whose
    # CIDR matches a known IPAM subnet, upsert the scope, then diff-merge
    # its pools and statics against what Windows reports. Scopes whose CIDR
    # has no matching IPAM subnet are skipped — we intentionally do not
    # auto-create subnets (that belongs in a separate workflow).
    if hasattr(driver, "get_scopes"):
        # Stamped BEFORE the wire read: everything the wire tells us is a
        # snapshot of the server as of (at latest) this instant, so a DB row an
        # operator created or edited *after* it is newer than our information
        # and the merge must not act on it (#620). The WinRM round-trip is
        # seconds long — long enough for a reservation created in the UI mid-poll
        # to be absent from the wire we're holding, and absence means delete.
        #
        # Read from the DATABASE's clock, not this process's. The guard compares
        # against ``created_at`` / ``modified_at``, which TimestampMixin fills
        # with ``func.now()`` — i.e. Postgres's clock. Comparing those to a local
        # ``datetime.now(UTC)`` is a cross-clock comparison, and on a multi-node
        # appliance (CNPG on another node, chrony drifting) a DB clock running
        # ahead by more than the poll interval would make EVERY row look newer
        # than the snapshot: every reservation skipped, every stale one spared,
        # the reconciler silently converging on nothing. ``clock_timestamp()``,
        # not ``now()`` — the latter is transaction-start time and would drift
        # earlier the longer this transaction runs.
        snapshot_at = (await db.execute(select(func.clock_timestamp()))).scalar_one()
        scopes_ok = True
        try:
            wire_scopes = await driver.get_scopes(server)
        except Exception as exc:  # noqa: BLE001
            scopes_ok = False
            result.errors.append(f"get_scopes failed: {exc}")
            logger.warning(
                "dhcp_pull_scopes_driver_failed",
                server=str(server.id),
                driver=server.driver,
                error=str(exc),
            )
            wire_scopes = []
        observations = await _observe_topology(
            db, server, driver, wire_scopes, result, apply=apply, scopes_ok=scopes_ok
        )
        for wscope in wire_scopes:
            if observations is not None and not _owns_scope(server, wscope, observations, result):
                continue
            await _upsert_scope(
                db, server, wscope, subnets, result, apply=apply, snapshot_at=snapshot_at
            )

    # Phase 2 — leases.
    try:
        wire = await driver.get_leases(server)
    except Exception as exc:  # noqa: BLE001 — surface any transport/PS error
        result.errors.append(f"get_leases failed: {exc}")
        logger.warning(
            "dhcp_pull_leases_driver_failed",
            server=str(server.id),
            driver=server.driver,
            error=str(exc),
        )
        return result

    result.server_leases = len(wire)

    # Fold each client-supplied hostname to a safe LDH form at ingress
    # (issue #597) so the raw wire value — which flows into IPAM.hostname and
    # the lease row below — can't carry spaces / control chars / a zone-file
    # newline. The DDNS path re-sanitizes idempotently. Non-raising by
    # design: a bad hostname must never abort a lease pull.
    for _lease in wire:
        _h = _lease.get("hostname")
        if _h:
            _lease["hostname"] = sanitize_hostname(_h) or None

    scope_cache = await _load_scope_cache(db, server.server_group_id)
    # Inverse map (scope_id -> subnet_id) so the absence-delete branch can
    # resolve a stale lease's owning subnet straight from its scope FK,
    # without an extra query per stale row.
    scope_subnet_ids = {scope_id: subnet_id for subnet_id, scope_id in scope_cache.items()}
    # #844 — subnet ids this server's group actually serves; hoisted out of
    # the per-lease loops (rebuilding the set per lease is O(scopes) each).
    preferred_subnet_ids = set(scope_cache)

    now = datetime.now(UTC)

    for lease in wire:
        ip = lease.get("ip_address")
        mac = lease.get("mac_address")
        if not ip or not mac:
            continue

        containing = _find_containing_subnet(ip, subnets, preferred_subnet_ids=preferred_subnet_ids)
        scope_id = scope_cache.get(containing.id) if containing else None

        existing = (
            await db.execute(
                select(DHCPLease).where(
                    DHCPLease.server_id == server.id,
                    DHCPLease.ip_address == ip,
                )
            )
        ).scalar_one_or_none()

        if existing is None:
            if apply:
                db.add(
                    DHCPLease(
                        server_id=server.id,
                        scope_id=scope_id,
                        ip_address=ip,
                        mac_address=mac,
                        hostname=lease.get("hostname"),
                        client_id=lease.get("client_id"),
                        state="active",
                        expires_at=lease.get("expires_at"),
                        last_seen_at=now,
                    )
                )
            result.imported += 1
        else:
            if apply:
                # Detect MAC supersede — same IP, new MAC. Stamp a history
                # row recording the OLD MAC's tenancy on this IP before
                # we overwrite it. Comparison is case-insensitive
                # because postgres MACADDR canonicalises to lower-case
                # but the wire format from the driver may not.
                old_mac = str(existing.mac_address) if existing.mac_address else None
                if old_mac and mac and old_mac.lower() != str(mac).lower():
                    record_lease_history(
                        db,
                        existing,
                        lease_state="superseded",
                        expired_at=now,
                        mac_override=old_mac,
                    )
                existing.mac_address = mac
                existing.hostname = lease.get("hostname") or existing.hostname
                existing.client_id = lease.get("client_id") or existing.client_id
                existing.state = "active"
                existing.expires_at = lease.get("expires_at") or existing.expires_at
                existing.last_seen_at = now
                if scope_id is not None and existing.scope_id != scope_id:
                    existing.scope_id = scope_id
            result.refreshed += 1

        if containing is None:
            result.out_of_scope += 1
            continue

        ipam_row = (
            await db.execute(
                select(IPAddress).where(
                    IPAddress.subnet_id == containing.id,
                    IPAddress.address == ip,
                )
            )
        ).scalar_one_or_none()

        if ipam_row is None:
            if apply:
                candidate = IPAddress(
                    subnet_id=containing.id,
                    address=ip,
                    status="dhcp",
                    hostname=lease.get("hostname"),
                    mac_address=mac,
                    last_seen_at=now,
                    last_seen_method="dhcp",
                    auto_from_lease=True,
                )
                # #564 — insert inside a savepoint so a concurrent Kea
                # agent lease-event / static-reservation writer racing
                # on the same (subnet_id, address) doesn't 500 the whole
                # sync on uq_ip_address_subnet_address. The helper flush
                # also assigns the PK so _sync_dns_record can reference
                # it below.
                ipam_row, created = await insert_ipam_mirror_row(db, candidate)
                if created:
                    result.ipam_created += 1
                elif ipam_row.auto_from_lease:
                    # Lost the race to a lease-owned row — refresh it
                    # like the elif path below.
                    _refresh_lease_owned_row(ipam_row, lease, mac, now)
                    result.ipam_refreshed += 1
                else:
                    # Lost the race to a manual/static row — leave it
                    # alone and skip DDNS, mirroring the manual branch.
                    continue
            else:
                result.ipam_created += 1
        elif ipam_row.auto_from_lease:
            # Only refresh rows we own. Manually-allocated rows are left
            # alone — the lease + IPAM coexist.
            if apply:
                _refresh_lease_owned_row(ipam_row, lease, mac, now)
            result.ipam_refreshed += 1
        else:
            # Manual allocation — skip DDNS entirely. Whatever hostname
            # the operator set stays put.
            continue

        # Fire DDNS off the freshly-mirrored row. Gate-keeping lives
        # inside the service (subnet.ddns_enabled, policy, static
        # override, idempotency); we just pass through and let it
        # decide. Any exception is logged but doesn't break the
        # lease-pull pass — DNS will reconcile next tick either way.
        if apply and ipam_row is not None:
            try:
                from app.services.dns.ddns import apply_ddns_for_lease  # noqa: PLC0415

                fired = await apply_ddns_for_lease(
                    db,
                    subnet=containing,
                    ipam_row=ipam_row,
                    client_hostname=lease.get("hostname"),
                )
                # #428 — record the affected DNS group(s) so the task wakes
                # the agent after commit (instead of waiting the safety tick).
                if fired:
                    from app.api.v1.ipam.router import (  # noqa: PLC0415
                        _resolve_effective_dns,
                    )

                    group_ids, _, _ = await _resolve_effective_dns(db, containing)
                    result.dns_wake_group_ids.update(str(g) for g in group_ids)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "dhcp_pull_leases_ddns_failed",
                    server=str(server.id),
                    ip=ip,
                    error=str(exc),
                )

    # Absence-delete: any active lease we have for this server that did
    # NOT appear in the wire response was removed on the DHCP server
    # (admin purge, manual release, etc). Drop the DB row and any IPAM
    # mirror we created. Manually-allocated IPAM rows (auto_from_lease
    # False) are intentionally left alone — the operator owns those.
    wire_ips = {lease.get("ip_address") for lease in wire if lease.get("ip_address")}

    # Zero-wire floor guard (#482). An empty lease response is
    # indistinguishable from a transient driver hiccup that returned [] WITHOUT
    # raising (e.g. Get-DhcpServerv4Scope momentarily reporting no scopes —
    # "empty" isn't an error, so the driver's ErrorActionPreference='Stop'
    # doesn't catch it and #426's parse-reraise doesn't fire). Rather than let
    # a single empty poll absence-delete EVERY tracked lease + IPAM mirror,
    # skip the sweep this cycle and let the time-based dhcp_lease_cleanup expiry
    # sweep reclaim genuinely-removed leases once they pass expires_at.
    # (Realistic hard failures already raise and returned above.)
    if not wire_ips:
        # The floor guard skips absence-delete on an empty wire UNLESS the empty
        # response is authoritative: it is only authoritative when the server's
        # group has no live (non-soft-deleted) scopes left to serve. In that case
        # — e.g. the group's last scope was just deleted (#623) — an empty wire is
        # expected, so we fall through and let the absence-delete below reclaim
        # any leases the scope-delete race left stranded (rather than waiting for
        # the time-based expiry sweep). If live scopes remain (or the server has
        # no group), keep the conservative skip.
        authoritative_empty = False
        if server.server_group_id is not None:
            live_scopes = (
                await db.execute(
                    select(func.count())
                    .select_from(DHCPScope)
                    .where(DHCPScope.group_id == server.server_group_id)
                )
            ).scalar_one()
            authoritative_empty = live_scopes == 0

        if not authoritative_empty:
            active_count = (
                await db.execute(
                    select(func.count())
                    .select_from(DHCPLease)
                    .where(DHCPLease.server_id == server.id, DHCPLease.state == "active")
                )
            ).scalar_one()
            if active_count:
                result.errors.append(
                    f"empty lease response with {active_count} tracked active "
                    "lease(s) — skipping absence-delete (#482); the expiry sweep "
                    "reclaims any genuinely-removed leases"
                )
                logger.warning(
                    "dhcp_pull_empty_wire_skip_absence_delete",
                    server=str(server.id),
                    driver=server.driver,
                    active=active_count,
                )
            if apply:
                server.last_sync_at = now
                await db.flush()
            return result

        # Authoritative empty — fall through. ``~DHCPLease.ip_address.in_(set())``
        # matches every active lease for this server, so the absence-delete loop
        # purges each (row + auto_from_lease mirror + DDNS) via purge_lease.
        logger.info(
            "dhcp_pull_empty_wire_authoritative",
            server=str(server.id),
            driver=server.driver,
        )

    stale_leases = list(
        (
            await db.execute(
                select(DHCPLease).where(
                    DHCPLease.server_id == server.id,
                    DHCPLease.state == "active",
                    ~DHCPLease.ip_address.in_(wire_ips),
                )
            )
        )
        .scalars()
        .all()
    )
    for stale in stale_leases:
        # Scope the mirror lookup to the lease's owning subnet — the same
        # discipline as the upsert/create branch above. The unscoped
        # address-only lookup both crashed (MultipleResultsFound) and
        # revoked unrelated mirrors when two IPSpaces/VRFs carry the same
        # private address (e.g. 10.0.0.50). Resolve the subnet via the
        # lease's scope FK when present, else longest-prefix match.
        stale_subnet_id = scope_subnet_ids.get(stale.scope_id) if stale.scope_id else None
        if stale_subnet_id is None:
            stale_containing = _find_containing_subnet(
                stale.ip_address, subnets, preferred_subnet_ids=preferred_subnet_ids
            )
            stale_subnet_id = stale_containing.id if stale_containing else None
        if apply:
            # Shared teardown: revoke DDNS (best-effort) → delete the
            # auto_from_lease mirror → stamp ``removed`` history → delete the
            # lease. Pass the subnet we already resolved so the helper keeps the
            # per-poll O(1) resolution. Same helper the delete_lease endpoint
            # and scope deletion use (DRY).
            if await purge_lease(db, stale, subnet_id=stale_subnet_id, now=now):
                result.ipam_revoked += 1
        elif stale_subnet_id is not None:
            # Dry-run (apply=False): count the mirror the purge WOULD remove,
            # without writing, so the UI preview stays accurate.
            mirror = (
                await db.execute(
                    select(IPAddress).where(
                        IPAddress.subnet_id == stale_subnet_id,
                        IPAddress.address == stale.ip_address,
                        IPAddress.auto_from_lease.is_(True),
                    )
                )
            ).scalar_one_or_none()
            if mirror is not None:
                result.ipam_revoked += 1
        result.removed += 1

    if apply:
        server.last_sync_at = now
        await db.flush()

    return result


# ── helpers ───────────────────────────────────────────────────────────


@dataclass
class _Topology:
    """What the ownership check needs: the group's observations + the clock."""

    obs: GroupObservations
    now: datetime


async def _observe_topology(
    db: AsyncSession,
    server: DHCPServer,
    driver: Any,
    wire_scopes: list[dict[str, Any]],
    result: PullLeasesResult,
    *,
    apply: bool,
    scopes_ok: bool,
) -> _Topology | None:
    """Record what this server holds and its failover relationships (#1110),
    then load the group's observations for the ownership check.

    Returns None when there is no one to share a scope with — a groupless
    server, or a group with a single Windows member — so the reconcile runs
    exactly as it always has.

    The failover read is skipped when ``get_scopes`` itself failed: the
    server is almost certainly unreachable, and a third WinRM call to it would
    only add another full timeout to the poll. Its last-known relationships
    stay in force.
    """
    now = datetime.now(UTC)
    if apply and scopes_ok:
        await record_scope_observation(db, server, wire_scopes, now=now)
    if apply and scopes_ok and hasattr(driver, "get_failover_relationships"):
        try:
            failover = await driver.get_failover_relationships(server)
        except Exception as exc:  # noqa: BLE001 — recorded, never fatal to the poll
            failover = {"ok": False, "error": str(exc), "relationships": []}
        if not failover.get("ok"):
            result.warnings.append(
                f"could not read failover relationships: {failover.get('error')} — keeping "
                f"the last ones read"
            )
            logger.warning(
                "dhcp_pull_failover_read_failed",
                server=str(server.id),
                error=str(failover.get("error")),
            )
        await record_failover_observation(db, server, failover, now=now)
    if server.server_group_id is None or not wire_scopes:
        return None
    if apply:
        await db.flush()
    obs = await load_group_observations(db, server.server_group_id)
    if len(obs.members) < 2:
        return None
    return _Topology(obs=obs, now=now)


def _owns_scope(
    server: DHCPServer, wscope: dict[str, Any], topo: _Topology, result: PullLeasesResult
) -> bool:
    """Is ``server`` the member whose view of this scope gets imported?

    With more than one Windows member holding a scope, every member's pass
    used to merge its own view — so two failover partners that disagreed
    (they do not sync configuration) undid each other on every poll, and the
    reservations and DNS records that differed were created and torn down
    each time. One member imports; the others only report (#1110).

    The owner's pass is also the one that reports how the scope is served,
    so a condition is said once per poll rather than once per holder.
    """
    cidr = canonical_cidr(wscope.get("subnet_cidr"))
    if cidr is None:
        return True
    owner = reconcile_owner(server, cidr, topo.obs, now=topo.now)
    if owner.id != server.id:
        result.scopes_deferred += 1
        return False
    holders = topo.obs.holders(cidr, now=topo.now)
    if len(holders) >= 2:
        serving = classify_serving(holders, topo.obs.members)
        if serving.verdict in (
            Verdict.UNCOORDINATED,
            Verdict.UNKNOWN,
            Verdict.SPLIT_SCOPE,
        ) or bool(serving.drift):
            result.warnings.append(f"scope {cidr}: {serving.detail}")
    return True


async def _load_subnet_cache(db: AsyncSession) -> list[tuple[Subnet, ipaddress._BaseNetwork]]:
    """Return ``[(subnet, network)]`` once per call — containment checks
    run in Python to keep the path driver-agnostic and avoid N+1 SQL.
    Cheap at any realistic subnet count.
    """
    res = await db.execute(select(Subnet))
    out: list[tuple[Subnet, ipaddress._BaseNetwork]] = []
    for s in res.scalars().all():
        try:
            net = ipaddress.ip_network(str(s.network), strict=False)
        except (ValueError, TypeError):
            continue
        out.append((s, net))
    return out


async def _load_scope_cache(db: AsyncSession, group_id: Any) -> dict[Any, Any]:
    """Map ``subnet_id -> scope_id`` for active scopes served by this
    server's group. Windows leases have no scope backlink until we
    resolve through the IPAM subnet — this lookup wires the
    ``DHCPLease.scope_id`` FK when the subnet has a scope in this group,
    and leaves it NULL otherwise.
    """
    if group_id is None:
        return {}
    # #426: do NOT filter is_active here. The Windows lease pull now
    # enumerates ALL scopes (it dropped its ``State -eq 'Active'`` scope
    # pre-filter), so a lease living in a deactivated-but-existing scope
    # would otherwise get scope_id=NULL even though its scope is right
    # here. Match the wire reads so the FK backlink wires correctly.
    res = await db.execute(
        select(DHCPScope.subnet_id, DHCPScope.id).where(
            DHCPScope.group_id == group_id,
        )
    )
    return {subnet_id: scope_id for subnet_id, scope_id in res.all()}


def _find_containing_subnet(
    ip: str,
    subnets: list[tuple[Subnet, ipaddress._BaseNetwork]],
    preferred_subnet_ids: set[Any] | None = None,
) -> Subnet | None:
    """Longest-prefix match of ``ip`` over ``subnets``.

    ``preferred_subnet_ids`` (#844) carries the subnet ids actually scoped to
    the requesting server's group. IPAM allows the same CIDR in different IP
    spaces (VRF semantics), so a bare longest-prefix over ALL subnets is
    ambiguous on an MSP install — whichever space's row came back first would
    swallow every customer's leases. A subnet the server actually serves
    outranks any equal-or-longer prefix from an unrelated space; the global
    match stays as the fallback for leases in ranges the group has no scope
    for. Remaining ties break on subnet id so resolution is at least
    deterministic across runs.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None
    best: tuple[int, int, str, Subnet] | None = None
    for subnet, net in subnets:
        if addr in net:
            rank = 1 if preferred_subnet_ids and subnet.id in preferred_subnet_ids else 0
            key = (rank, net.prefixlen, str(subnet.id))
            if best is None or key > (best[0], best[1], best[2]):
                best = (rank, net.prefixlen, str(subnet.id), subnet)
    return best[3] if best else None


async def _upsert_scope(
    db: AsyncSession,
    server: DHCPServer,
    wscope: dict[str, Any],
    subnets: list[tuple[Subnet, ipaddress._BaseNetwork]],
    result: PullLeasesResult,
    *,
    apply: bool,
    snapshot_at: datetime,
) -> None:
    """Upsert one Windows-reported scope + its pools + its reservations.

    Matching: the scope's ``subnet_cidr`` must exactly match an existing
    IPAM ``Subnet.network`` (prefix-length identical). No auto-create.

    Pools + statics are **diff-merged** against the wire, not replaced (#620).
    They used to be replaced: a Core ``DELETE`` of every pool + reservation
    under the scope, then a re-insert from the wire. That was written when
    ``windows_dhcp`` was a read-only driver and its rows were pure derived
    state. It stopped being true once write-through landed — operators create
    reservations through our UI now, and a reservation owns an ``ip_address``
    mirror that back-links to it by id. Re-inserting minted a fresh id on every
    poll, so the mirror was left pointing at a row Postgres had dropped (and a
    Core ``DELETE`` runs no per-row Python, so nothing released it): the address
    was neither allocated nor free, and deleting the reservation in the UI never
    freed it, because the lookup keyed on the *current* id and matched nothing.

    Merging keeps a reservation's id stable across polls, which is what makes
    the mirror's back-link durable. It also means an unchanged reservation is
    not written at all — so, unlike a detach/re-attach repair, this fires no DNS
    record churn on the steady state. Only real changes touch anything.
    """
    cidr = wscope.get("subnet_cidr")
    if not cidr:
        return
    try:
        target = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return

    matching_subnet: Subnet | None = None
    for subnet, net in subnets:
        if net == target:
            matching_subnet = subnet
            break
    if matching_subnet is None:
        result.scopes_skipped_no_subnet += 1
        return

    # Scope is keyed by (group_id, subnet_id) now. If the Windows server
    # has no group, skip — a groupless Windows server can't own scopes
    # in the group-centric model (migration assigns every server a
    # singleton group, but a freshly-created unpartitioned server hits
    # this branch until an operator attaches it to a group).
    if server.server_group_id is None:
        result.scopes_skipped_no_subnet += 1
        return

    # DHCPScope eager-loads ``pools`` and ``statics`` collections, so the
    # result iterator must be uniqued before calling scalar_one_or_none().
    existing_scope = (
        (
            await db.execute(
                select(DHCPScope).where(
                    DHCPScope.group_id == server.server_group_id,
                    DHCPScope.subnet_id == matching_subnet.id,
                )
            )
        )
        .unique()
        .scalar_one_or_none()
    )

    scope_fields = {
        "name": wscope.get("name") or "",
        "description": wscope.get("description") or "",
        "is_active": bool(wscope.get("is_active", True)),
        "lease_time": int(wscope.get("lease_time") or 86400),
        "options": wscope.get("options") or {},
        "address_family": "ipv4",
    }

    if existing_scope is None:
        if apply:
            existing_scope = DHCPScope(
                group_id=server.server_group_id,
                subnet_id=matching_subnet.id,
                **scope_fields,
            )
            db.add(existing_scope)
            await db.flush()
        result.scopes_imported += 1
    else:
        if apply:
            for field_name, value in scope_fields.items():
                setattr(existing_scope, field_name, value)
        result.scopes_refreshed += 1

    if not apply or existing_scope is None:
        return

    await _merge_pools(db, existing_scope, wscope, result, snapshot_at=snapshot_at)
    await _merge_statics(db, existing_scope, wscope, result, snapshot_at=snapshot_at)
    await db.flush()


def _absence_delete_ok(
    *,
    kind: str,
    cidr: str,
    wire_count: int,
    tracked_count: int,
    enumeration_ok: bool,
    result: PullLeasesResult,
) -> bool:
    """May we treat "absent from the wire" as "deleted on the server"?

    Two ways an empty/short wire list lies, and both end in us deleting rows an
    operator still has (for reservations: their IPAM mirror and DNS records too):

    * the driver told us the enumeration failed (``*_ok`` false) — see #620's
      note on ``_PS_LIST_TOPOLOGY``, whose per-list ``try/catch`` can hand back
      an empty array for a scope that is full of reservations;
    * the enumeration *claims* success but came back wholly empty while we track
      rows — the same ambiguity the lease path's zero-wire floor guard (#482)
      refuses to resolve in favour of deletion.

    Erring toward divergence over data loss: a stale row an operator can delete
    in the UI beats a reservation (and its A record) we tore down on a hiccup.
    """
    if not enumeration_ok:
        result.errors.append(
            f"scope {cidr}: the server's {kind} enumeration failed — keeping the "
            f"{tracked_count} tracked {kind} and skipping the absence-delete this pass"
        )
        return False
    if wire_count == 0 and tracked_count > 0:
        result.errors.append(
            f"scope {cidr}: wire reported 0 {kind} while {tracked_count} are tracked — "
            f"skipping the absence-delete this pass (#482). If they really were removed "
            f"on the server, delete them here to converge."
        )
        return False
    return True


async def _merge_pools(
    db: AsyncSession,
    scope: DHCPScope,
    wscope: dict[str, Any],
    result: PullLeasesResult,
    *,
    snapshot_at: datetime,
) -> None:
    """Diff-merge the scope's pools against the wire, keyed by (start, end).

    Pools carry no IPAM mirror, so churning them strands nothing — but IPAM
    *reads* them (a manual allocation inside a dynamic range is refused), so a
    pool that blinks out of existence between polls briefly opens a hole for an
    operator to allocate an address the DHCP server hands out dynamically.
    """
    wire = [p for p in (wscope.get("pools") or []) if p.get("start_ip") and p.get("end_ip")]
    existing = list(
        (await db.execute(select(DHCPPool).where(DHCPPool.scope_id == scope.id))).scalars().all()
    )
    by_range = {(norm_ip(str(p.start_ip)), norm_ip(str(p.end_ip))): p for p in existing}

    seen: set[tuple[str, str]] = set()
    for wpool in wire:
        key = (norm_ip(str(wpool["start_ip"])), norm_ip(str(wpool["end_ip"])))
        if key in seen:
            continue
        seen.add(key)
        pool_type = wpool.get("pool_type") or "dynamic"
        row = by_range.get(key)
        if row is None:
            db.add(
                DHCPPool(
                    scope_id=scope.id,
                    start_ip=wpool["start_ip"],
                    end_ip=wpool["end_ip"],
                    pool_type=pool_type,
                    name="",
                )
            )
            result.pools_synced += 1
        elif row.pool_type != pool_type:
            row.pool_type = pool_type
            result.pools_synced += 1

    stale = [
        row
        for key, row in by_range.items()
        # Same snapshot guard the reservations get: a pool an operator added
        # mid-poll (write-through pushed it to the server, but our wire read
        # predates it) is absent from a wire that simply never saw it, and
        # deleting it would take IPAM's dynamic-range protection away for a poll
        # — the exact hole this function's docstring warns about.
        if key not in seen and not (row.created_at is not None and row.created_at > snapshot_at)
    ]
    if not stale:
        return
    if not _absence_delete_ok(
        kind="pools",
        cidr=str(wscope.get("subnet_cidr") or ""),
        wire_count=len(wire),
        tracked_count=len(existing),
        enumeration_ok=bool(wscope.get("pools_ok", True)),
        result=result,
    ):
        return
    for row in stale:
        await db.delete(row)
        result.pools_removed += 1


async def _merge_statics(
    db: AsyncSession,
    scope: DHCPScope,
    wscope: dict[str, Any],
    result: PullLeasesResult,
    *,
    snapshot_at: datetime,
) -> None:
    """Diff-merge the scope's reservations against the wire, keyed by MAC.

    MAC is the key because it is what Windows keys a reservation on and what
    survives an IP change; matching on it lets a relocated reservation keep its
    id — and therefore its IPAM mirror, and therefore its DNS records.

    Every reservation on the wire gets an IPAM mirror, not just the ones created
    through our UI (#620). A reservation is an allocation whoever made it, and
    IPAM that doesn't show it is IPAM that will hand the address out twice.
    ``upsert_ipam_for_static`` is the same helper the UI create path uses, so
    both kinds of reservation produce the same row — but we only call it when
    something actually changed (or the mirror is missing/stale), because it
    re-syncs DNS, and this runs on the beat.
    """
    wire = _dedupe_wire_statics(wscope.get("statics") or [])
    existing = list(
        (
            await db.execute(
                select(DHCPStaticAssignment).where(DHCPStaticAssignment.scope_id == scope.id)
            )
        )
        .scalars()
        .all()
    )
    by_mac = {norm_mac(str(st.mac_address)): st for st in existing}
    cidr = str(wscope.get("subnet_cidr") or "")

    # ── 1. absence-delete, first — it frees addresses the wire may be reusing ──
    stale = [
        st
        for mac_key, st in by_mac.items()
        # A reservation created after the snapshot cannot be judged by it: the
        # wire we are holding predates it, so its absence proves nothing.
        if mac_key not in wire and not (st.created_at is not None and st.created_at > snapshot_at)
    ]
    if stale and _absence_delete_ok(
        kind="reservations",
        cidr=cidr,
        wire_count=len(wire),
        tracked_count=len(existing),
        enumeration_ok=bool(wscope.get("statics_ok", True)),
        result=result,
    ):
        for st in stale:
            # Gone from the server ⇒ the address is not reserved for anyone.
            # Delete the mirror rather than freeing it to ``available``: this is
            # a machine reconcile, and a persisted freed row still renders as a
            # line in the subnet table and still counts toward utilization
            # (#618). Tears the reservation's DNS records down first.
            await remove_ipam_for_static(db, st)
            await db.delete(st)
            by_mac.pop(norm_mac(str(st.mac_address)), None)
            result.statics_removed += 1
        await db.flush()

    # ── 2. classify what the wire wants against what survived ──
    creates: list[dict[str, Any]] = []
    movers: list[tuple[DHCPStaticAssignment, dict[str, Any]]] = []
    in_place: list[tuple[DHCPStaticAssignment, dict[str, Any]]] = []
    for mac_key, wstatic in wire.items():
        st = by_mac.get(mac_key)
        if st is None:
            creates.append(wstatic)
        # Never overwrite a row an operator touched after we took the wire
        # snapshot — our information is the older of the two. The write-through
        # already pushed their edit to the server, so the next poll reads it back
        # and converges on it.
        elif st.modified_at is not None and st.modified_at > snapshot_at:
            continue
        elif norm_ip(str(st.ip_address)) != norm_ip(str(wstatic["ip_address"])):
            movers.append((st, wstatic))
        else:
            in_place.append((st, wstatic))

    await _apply_moves(db, scope, movers, by_mac, result, cidr=cidr)

    # Load every in-place reservation's mirror in ONE query. The steady state is
    # this loop's whole point — it writes nothing — so a per-reservation
    # ``db.get`` here would be N round-trips per scope per poll, forever, to
    # establish that there is nothing to do.
    mirrors = await _load_mirrors(db, [st for st, _ in in_place])
    for st, wstatic in in_place:
        changed, mirrored = _apply_wire_fields(st, wstatic)
        if changed:
            result.statics_synced += 1
        # Re-mirror on a change the mirror reflects (the hostname), or when the
        # mirror is missing / points at a dead id — which is exactly the residue
        # the old replace-all left behind, so those installs repair themselves on
        # the next poll, with no operator action and no migration. A steady-state
        # poll hits neither, and so writes nothing at all.
        if mirrored or not _mirror_is_current(scope, st, mirrors.get(st.ip_address_id)):
            await upsert_ipam_for_static(db, scope, st, action="update")

    # ``by_mac`` now holds every surviving reservation at its final address, so
    # it is the occupancy map a new one has to fit into. A new reservation can
    # only be blocked by a row the absence-delete floor guard declined to remove
    # — same story as a blocked move, and the same answer: report it rather than
    # violate the index and abort the poll.
    occupied = {norm_ip(str(st.ip_address)): st for st in by_mac.values()}
    for wstatic in creates:
        ip_key = norm_ip(str(wstatic["ip_address"]))
        blocker = occupied.get(ip_key)
        if blocker is not None:
            result.errors.append(
                f"scope {cidr}: reservation {wstatic['mac_address']} cannot be added at "
                f"{wstatic['ip_address']} — {blocker.mac_address} still holds that address "
                f"here; retrying next poll"
            )
            continue
        st = DHCPStaticAssignment(
            scope_id=scope.id,
            ip_address=str(wstatic["ip_address"]),
            mac_address=str(wstatic["mac_address"]),
            client_id=wstatic.get("client_id"),
            hostname=sanitize_hostname(wstatic.get("hostname")) or "",
            description=wstatic.get("description") or "",
        )
        db.add(st)
        await db.flush()
        await upsert_ipam_for_static(db, scope, st, action="create")
        occupied[ip_key] = st
        result.statics_synced += 1


def _dedupe_wire_statics(raw: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """``{normalised mac: wire static}``, dropping unusable and duplicate rows.

    Both keys a reservation is unique on per scope — MAC and address — are
    de-duplicated, because the merge writes against unique indexes on both and a
    wire that claimed the same address twice would abort the poll.
    """
    out: dict[str, dict[str, Any]] = {}
    ips: set[str] = set()
    for wstatic in raw:
        if not wstatic.get("ip_address") or not wstatic.get("mac_address"):
            continue
        mac_key = norm_mac(str(wstatic["mac_address"]))
        ip_key = norm_ip(str(wstatic["ip_address"]))
        if not mac_key or mac_key in out or ip_key in ips:
            continue
        out[mac_key] = wstatic
        ips.add(ip_key)
    return out


def _apply_wire_fields(st: DHCPStaticAssignment, wstatic: dict[str, Any]) -> tuple[bool, bool]:
    """Copy the wire's non-address fields onto ``st``.

    Returns ``(changed, mirrored)`` — the second flag says whether the change is
    one the IPAM mirror (and the DNS records published off it) reflects. Only
    the hostname is: a description or client_id the wire taught us does not move
    a record anywhere, and ``upsert_ipam_for_static`` re-syncs DNS every time it
    runs, on a path that runs on the beat.

    Deliberately excludes the address — re-addressing has to be sequenced against
    the ``(scope, address)`` unique index (see ``_apply_moves``) — but note an
    address change is mirrored too, and its caller always upserts.
    """
    changed = mirrored = False
    hostname = sanitize_hostname(wstatic.get("hostname")) or ""
    if (st.hostname or "") != hostname:
        st.hostname = hostname
        changed = mirrored = True
    for attr, value in (
        ("description", wstatic.get("description") or ""),
        ("client_id", wstatic.get("client_id")),
    ):
        if (getattr(st, attr) or "") != (value or ""):
            setattr(st, attr, value)
            changed = True
    return changed, mirrored


async def _apply_moves(
    db: AsyncSession,
    scope: DHCPScope,
    movers: list[tuple[DHCPStaticAssignment, dict[str, Any]]],
    by_mac: dict[str, DHCPStaticAssignment],
    result: PullLeasesResult,
    *,
    cidr: str,
) -> None:
    """Re-address the reservations the wire says have moved.

    Writing the new addresses one row at a time is not safe: renumbering a scope
    on the server (``A`` takes ``B``'s address, ``B`` takes ``C``'s) hands us a
    wire whose end state is legal but whose every intermediate state is not, and
    the first row to land on an address a not-yet-moved reservation still holds
    violates ``uq_dhcp_static_scope_ip``. That aborts the poll — and the wire
    keeps reporting the same thing, so it aborts every poll after it, forever.

    That index is partial (``WHERE deleted_at IS NULL``), so lift every mover out
    of it, flush, then write the new addresses and put the rows back. The
    interim state lives and dies inside the caller's transaction; no other
    session can observe it, and a mid-flight failure rolls the whole thing back.
    """
    if not movers:
        return

    # A mover whose destination is held by a reservation that is NOT itself
    # moving cannot land, lift or no lift. That means a reservation we chose to
    # keep — the absence-delete floor guard declined to remove it — is sitting on
    # the address. Say so and leave it for a poll with better information.
    moving = {id(st) for st, _ in movers}
    held = {norm_ip(str(st.ip_address)): st for st in by_mac.values()}
    landable: list[tuple[DHCPStaticAssignment, dict[str, Any]]] = []
    for st, wstatic in movers:
        blocker = held.get(norm_ip(str(wstatic["ip_address"])))
        if blocker is not None and blocker is not st and id(blocker) not in moving:
            result.errors.append(
                f"scope {cidr}: reservation {st.mac_address} cannot move to "
                f"{wstatic['ip_address']} — {blocker.mac_address} still holds that "
                f"address here; retrying next poll"
            )
            continue
        landable.append((st, wstatic))
    if not landable:
        return

    lifted_at = datetime.now(UTC)
    for st, _ in landable:
        st.deleted_at = lifted_at
    await db.flush()

    for st, wstatic in landable:
        st.deleted_at = None
        st.ip_address = str(wstatic["ip_address"])
        _apply_wire_fields(st, wstatic)  # the address already counts as a change
        result.statics_synced += 1
    await db.flush()

    # Mirrors last, once every row is back in the index at its final address:
    # upsert_ipam_for_static re-points the mirror and re-syncs DNS, which is
    # right for a move — the record really did change address.
    for st, _ in landable:
        await upsert_ipam_for_static(db, scope, st, action="update")


async def _load_mirrors(
    db: AsyncSession, statics: list[DHCPStaticAssignment]
) -> dict[Any, IPAddress]:
    """``{ip_address_id: row}`` for every reservation that claims to have a mirror."""
    ids = [st.ip_address_id for st in statics if st.ip_address_id is not None]
    if not ids:
        return {}
    rows = (await db.execute(select(IPAddress).where(IPAddress.id.in_(ids)))).scalars().all()
    return {row.id: row for row in rows}


def _mirror_is_current(scope: DHCPScope, st: DHCPStaticAssignment, row: IPAddress | None) -> bool:
    """Is ``st``'s IPAM mirror present and pointing back at ``st``?

    False for the rows the pre-#620 replace-all stranded (mirror survives, its
    ``static_assignment_id`` names a reservation that no longer exists), and for
    a reservation whose mirror an operator deleted out from under it.
    """
    if row is None:
        return False
    return (
        row.subnet_id == scope.subnet_id
        and norm_ip(str(row.address)) == norm_ip(str(st.ip_address))
        and row.status == "static_dhcp"
        and row.static_assignment_id == str(st.id)
    )


__all__ = ["PullLeasesResult", "pull_leases_from_server"]
