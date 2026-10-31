"""Per-server DNS config-drift report (#61).

Extends the zone-serial drift surface with a full record-level diff: for
every server in the zone's group, AXFR / pull the live zone and diff it
against the SpatiumDDI DB source of truth, surfacing per server what's
**extra on the server** (records present on the wire but not in the DB —
a manual change made directly on the host) and what's **missing on the
server** (DB rows the server isn't serving). Read-only — never applies.

Reuses ``pull_from_server._key`` for the identity/normalisation so the
comparison matches the additive-sync path exactly (relative-vs-FQDN and
TTL-only differences don't register as drift). A record whose *value*
changed on a server surfaces as a missing+extra pair, since the key
includes the value.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns import get_driver
from app.drivers.dns.base import RecordData, TsigKey
from app.models.dns import DNSRecord, DNSServer, DNSServerZoneState, DNSZone
from app.services.dns.pull_from_server import (
    _key,
    targets_are_relative,
    without_agent_ns_glue,
    without_server_apex_ns,
)
from app.services.dns.pull_from_server import (
    is_apex_ns as _is_apex_ns,
)
from app.services.dns.tsig import (
    is_view_transfer_key,
    pull_zone_records_signed,
    resolve_group_transfer_key,
    resolve_transfer_vip,
    resolve_view_transfer_key,
    transfer_fallback_hosts,
    transfer_needs_tsig,
)

logger = structlog.get_logger(__name__)

# #3198 — how long a server may sit below the zone's serial before the report
# calls it behind. A save bumps the serial and wakes the agents at once (Redis
# wake, 12 s safety tick), and an apply is a render + validate + reload, so a
# server catching up is normally done well inside this. 120 s is ten safety
# ticks: past it the server has had many chances to converge and has not, which
# is a fact about the server rather than a change still in flight.
SERIAL_GRACE = timedelta(seconds=120)


def zone_state_in_sync(zone: DNSZone, current: int, target: int, driver: str) -> bool:
    """Whether a server's reported serial for ``zone`` reads as in sync.

    A primary zone is in sync when the server serves our serial
    (``last_serial``). A secondary / stub zone's serial is its primary's, not
    ours to number, so it is never compared with ``last_serial`` (0 for a
    secondary): a server that holds the zone is in sync. That is how BIND9
    secondaries have always read — the BIND9 agent reports the bundle's serial,
    0, which equals the target 0 — and it is kept for every driver that does
    not read back what it serves. PowerDNS reports the serial it serves, so a
    secondary there is in sync once it has transferred (a transferred zone
    never serves 0) and not before: at 0 it holds no data and answers REFUSED
    (#1967)."""
    if (zone.zone_type or "primary") in ("secondary", "stub"):
        if driver == "powerdns":
            return current != 0
        return current == target
    return current == target


@dataclass
class DriftRecord:
    name: str
    record_type: str
    value: str
    ttl: int | None = None
    # Structured MX / SRV fields (#1525) — carried so a priority-only
    # difference is visible in the report, not just counted.
    priority: int | None = None
    weight: int | None = None
    port: int | None = None


@dataclass
class ServerDrift:
    server_id: str
    server_name: str
    driver: str
    # "ok" — transferred, nothing missing or extra, at the target serial.
    # "behind" — transferred, but the server is not serving the zone as saved
    # (a saved record is missing, or it sits below the target serial).
    # "drift" — transferred and complete, but carries records SpatiumDDI does
    # not hold (a manual change on the host).
    # "error" / "unsupported" — the transfer failed / cannot be done; the
    # counts mean nothing. Anything else must be read as NOT ok (#3198).
    status: str
    error: str | None = None
    # What put the server in "behind" / "drift", operator-readable.
    reason: str | None = None
    # The server's reported serial (None = it has not reported) and the
    # zone's target.
    current_serial: int | None = None
    target_serial: int = 0
    in_sync: int = 0
    extra_on_server: list[DriftRecord] = field(default_factory=list)
    missing_on_server: list[DriftRecord] = field(default_factory=list)

    @property
    def drift_count(self) -> int:
        return len(self.extra_on_server) + len(self.missing_on_server)


@dataclass
class ZoneDriftReport:
    zone_id: str
    zone_name: str
    db_record_count: int
    servers: list[ServerDrift] = field(default_factory=list)
    # Conditions that make the diff below less trustworthy than it looks.
    # Rendered verbatim by the UI — keep them operator-readable.
    warnings: list[str] = field(default_factory=list)


def _renders_apex_ns(srv: DNSServer, driver: object) -> bool:
    """Whether ``srv`` serves the zone's own apex NS rows as its NS set, and
    the read can return them (#1857).

    True for an agent-managed BIND9 or Technitium: both agents write a
    zone's apex NS records as the whole NS set (#1153), and both drivers read
    over AXFR, which keeps the apex NS when asked. Elsewhere the NS set is the
    server's or the provider's, not rendered from the rows.
    """
    return srv.agent_id is not None and bool(getattr(driver, "pull_can_include_apex_ns", False))


def _compare_apex_ns(
    db_rows: list[DNSRecord], on_wire: list[RecordData], zone_name: str
) -> tuple[list[DNSRecord], list[RecordData]]:
    """The two sides of a drift diff with apex NS kept only where it means
    something (#1857).

    * The zone declares no apex NS: whatever NS set the server answers with
      is its own (an agent's ``primary_ns`` or placeholder, a provider's name
      servers), not a difference from the zone. Drop it from the wire.
    * The read carried no apex NS: an AXFR of a server that does not render
      the zone's NS rows (an operator's BIND9, Windows). Every zone has an apex
      NS set, so its absence means the read could not see it, and the stored
      rows would read "missing on server" forever. Drop them from the DB side.
    * Both sides have one: compare them like any record, so an NS set changed
      on the server, or an NS change the agent failed to apply, shows.
    """
    db_has = any(_is_apex_ns(r, zone_name) for r in db_rows)
    wire_has = any(_is_apex_ns(r, zone_name) for r in on_wire)
    if not db_has:
        on_wire = [r for r in on_wire if not _is_apex_ns(r, zone_name)]
    elif not wire_has:
        db_rows = [r for r in db_rows if not _is_apex_ns(r, zone_name)]
    return db_rows, on_wire


def _to_drift_record(r: RecordData | DNSRecord) -> DriftRecord:
    return DriftRecord(
        name=r.name or "@",
        record_type=r.record_type,
        value=r.value,
        ttl=r.ttl,
        priority=getattr(r, "priority", None),
        weight=getattr(r, "weight", None),
        port=getattr(r, "port", None),
    )


# Statuses of a server whose zone was actually read: the diff is meaningful.
TRANSFERRED = frozenset({"ok", "behind", "drift"})


async def _classify_transferred(
    db: AsyncSession,
    zone: DNSZone,
    servers: list[DNSServer],
    entries: list[ServerDrift],
) -> None:
    """Turn "the transfer worked" into "and the server is serving the zone"
    (#3198). The per-server status used to mean only the former, so a server
    that had stopped applying the zone read ``ok``.
    """
    # Re-read what this uses: the report is read-only, and a commit between
    # loading the zone and here must not leave these lazy-loading (async IO).
    await db.refresh(zone, ["last_serial", "modified_at", "zone_type"])
    target = int(zone.last_serial or 0)
    states = {
        st.server_id: st
        for st in (
            await db.execute(
                select(DNSServerZoneState).where(DNSServerZoneState.zone_id == zone.id)
            )
        )
        .scalars()
        .all()
    }
    modified = zone.modified_at
    settled = modified is None or datetime.now(UTC) - modified > SERIAL_GRACE
    by_id = {str(s.id): s for s in servers}
    for e in entries:
        if e.status != "ok":
            continue
        e.target_serial = target
        st = states.get(uuid.UUID(e.server_id))
        if st is not None:
            e.current_serial = int(st.current_serial)
        reasons: list[str] = []
        if e.missing_on_server:
            n = len(e.missing_on_server)
            reasons.append(f"{n} saved record{'' if n == 1 else 's'} not being served")
        if (
            e.current_serial is not None
            and settled
            and not zone_state_in_sync(zone, e.current_serial, target, by_id[e.server_id].driver)
        ):
            reasons.append(
                f"serving serial {e.current_serial}, below the zone's {target}"
                if e.current_serial < target
                else f"serving serial {e.current_serial}, not the zone's {target}"
            )
        if reasons:
            e.status = "behind"
            e.reason = "; ".join(reasons)
        elif e.extra_on_server:
            n = len(e.extra_on_server)
            e.status = "drift"
            e.reason = (
                f"{n} record{' is' if n == 1 else 's are'} served that SpatiumDDI does not hold"
            )


async def compute_zone_drift(
    db: AsyncSession, *, group_id: uuid.UUID, zone: DNSZone
) -> ZoneDriftReport:
    """Compute per-server record-level drift for ``zone`` across every
    server in ``group_id``. Each server is pulled independently; a pull
    failure (unreachable / paused / driver can't AXFR) is surfaced as an
    ``error`` entry rather than failing the whole report."""
    db_rows = list(
        (await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))).scalars().all()
    )

    servers = list(
        (
            await db.execute(
                select(DNSServer).where(DNSServer.group_id == group_id).order_by(DNSServer.name)
            )
        )
        .scalars()
        .all()
    )

    report = ZoneDriftReport(
        zone_id=str(zone.id), zone_name=zone.name, db_record_count=len(db_rows)
    )

    # #734 — an agent-managed BIND9 / Technitium grants transfer to the
    # group's TSIG key, not to our address, so the read has to be signed.
    # Resolve once for the whole group rather than per server: every server
    # in a group renders from the same bundle and so grants the same keys.
    # Must happen before the gather() below, which deliberately touches no
    # DB. Skipped entirely when no server needs it, so a group of Windows or
    # operator-run servers never decrypts a secret it has no use for.
    needs_tsig = any(transfer_needs_tsig(s) for s in servers)
    transfer_key = await resolve_group_transfer_key(db, group_id) if needs_tsig else None

    # #920 — under split-horizon (#24) the server answers a transfer from the
    # view the request selects, and BIND selects by ``match-clients`` before it
    # consults allow-transfer. The operator's client lists never name the
    # control plane, so a transfer signed with the group key matched no view
    # (BADKEY, "the key is unknown", for a loaded and granted key) or was
    # caught by a broad view and read that view's copy. The agent now admits
    # one derived key per view into that view alone; sign with the key of the
    # view holding this zone's copy, and keep the group key as the fallback
    # for an agent that predates the view keys.
    # #1470 — behind the appliance's DNS VIP the node address refuses :53;
    # each member is then retried at its own pod address, never the VIP.
    transfer_vip = await resolve_transfer_vip(db) if needs_tsig else ""
    view_transfer = await resolve_view_transfer_key(db, zone) if needs_tsig else None
    view_key, view_name = view_transfer if view_transfer is not None else (None, None)
    # server_id -> the transfer was addressed to the zone's own view.
    view_addressed: dict[str, bool] = {}

    async def _drift_for_server(srv: DNSServer) -> ServerDrift:
        entry = ServerDrift(
            server_id=str(srv.id),
            server_name=srv.name,
            driver=srv.driver,
            status="ok",
        )
        driver = get_driver(srv.driver)
        if not hasattr(driver, "pull_zone_records"):
            entry.status = "unsupported"
            entry.error = f"Driver {srv.driver!r} can't pull live records for drift."
            return entry
        # Fail closed, and say which thing is missing (#734). Without a key
        # the transfer is REFUSED, and the generic error sends the operator
        # to allow-transfer / the firewall — neither of which is the problem,
        # and neither of which they can reach anyway, because the agent owns
        # named.conf. Naming the missing key is the difference between a
        # fixable report and a dead end.
        keys: list[TsigKey | None]
        if transfer_needs_tsig(srv):
            if transfer_key is None:
                entry.status = "unsupported"
                entry.error = (
                    "This server's group has no TSIG key, so the zone transfer that "
                    "drift reads cannot be authenticated. Create a TSIG key on the "
                    "group (Servers → group → TSIG keys) and let the agent apply the "
                    "new config, then re-run this report."
                )
                return entry
            # Views are a BIND9 render; the other agent driver declines them.
            keys = (
                [view_key, transfer_key]
                if view_key is not None and srv.driver == "bind9"
                else [transfer_key]
            )
        else:
            # Only sign where an agent actually granted the key. Windows Path
            # A and an operator's own BIND9 both AXFR unsigned and are
            # authorised by address; handing either a key it never granted
            # turns a working pull into NOTAUTH.
            keys = [None]
        pull_kwargs: dict[str, Any] = (
            {"include_apex_ns": True} if _renders_apex_ns(srv, driver) else {}
        )
        if fallback := transfer_fallback_hosts(srv, transfer_vip):
            pull_kwargs["fallback_hosts"] = fallback
        try:
            on_wire, used = await pull_zone_records_signed(
                driver, srv, zone.name, keys, view_name=view_name, **pull_kwargs
            )
        except Exception as exc:  # noqa: BLE001 — per-server, never fail the whole report
            entry.status = "error"
            entry.error = str(exc)
            logger.warning(
                "dns.drift.pull_failed",
                zone=zone.name,
                server=str(srv.id),
                driver=srv.driver,
                error=str(exc),
            )
            return entry

        view_addressed[entry.server_id] = is_view_transfer_key(used)
        # #1794 — a dot-less name target is relative on a zone-file driver and
        # absolute on a cloud one, so the DB side is keyed per server.
        rel = targets_are_relative(srv)
        # #1857 — a stored apex NS row (an importer's copy of the source's, or
        # one an operator wrote) read "missing on server" forever, because the
        # transfer dropped the apex NS. See ``_compare_apex_ns``.
        db_rows_cmp, on_wire = _compare_apex_ns(db_rows, on_wire, zone.name)
        db_by_key = {_key(r, zone.name, relative_targets=rel): r for r in db_rows_cmp}
        on_wire = without_agent_ns_glue(on_wire, srv, zone.name, set(db_by_key))
        on_wire = without_server_apex_ns(on_wire, srv, zone.name, set(db_by_key))
        wire_by_key = {_key(r, zone.name, relative_targets=rel): r for r in on_wire}
        entry.extra_on_server = [
            _to_drift_record(r) for k, r in wire_by_key.items() if k not in db_by_key
        ]
        entry.missing_on_server = [
            _to_drift_record(r) for k, r in db_by_key.items() if k not in wire_by_key
        ]
        entry.in_sync = len(set(db_by_key) & set(wire_by_key))
        return entry

    # Pull every server concurrently — a slow/unreachable host shouldn't add
    # its full AXFR timeout serially to the request latency. Each coroutine
    # only touches the driver (network), never the shared AsyncSession, and
    # isolates its own failures, so gather() is safe. Order is preserved.
    report.servers = list(await asyncio.gather(*(_drift_for_server(s) for s in servers)))
    await _classify_transferred(db, zone, servers, report.servers)

    # Split-horizon caveats. A zone that belongs to a view has one copy per
    # view it lives in, and an AXFR names only the zone. A transfer addressed
    # to the zone's own view (#920) compares the right copy; any other one —
    # an operator-run server authorised by address, an agent that predates the
    # view keys — was answered by whichever view matches the control plane's
    # source address, which may be a different view's content. We cannot tell
    # from the wire which view answered, so name the servers it applies to
    # rather than let an operator "fix" a difference that isn't one.
    if zone.view_id is not None:
        unaddressed = [
            s.server_name
            for s in report.servers
            if s.status in TRANSFERRED and not view_addressed.get(s.server_id, False)
        ]
        if unaddressed:
            report.warnings.append(
                "This zone belongs to a DNS view, and the zone transfer from "
                f"{', '.join(unaddressed)} could not be addressed to that view, so "
                "it was answered by whichever view matches the control plane's "
                "source address. Differences below from "
                f"{'that server' if len(unaddressed) == 1 else 'those servers'} may "
                "reflect a different view rather than real drift."
            )
    elif any(r.view_id is not None for r in db_rows):
        report.warnings.append(
            "Some records in this zone are scoped to a specific DNS view and are "
            "only served to clients matching it. They may appear as missing here "
            "even when the server is correct."
        )

    return report
