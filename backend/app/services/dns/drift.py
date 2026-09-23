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

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns import get_driver
from app.drivers.dns.base import RecordData, TsigKey
from app.models.dns import DNSRecord, DNSServer, DNSZone
from app.services.dns.pull_from_server import _key
from app.services.dns.tsig import (
    is_view_transfer_key,
    pull_zone_records_signed,
    resolve_group_transfer_key,
    resolve_view_transfer_key,
    transfer_needs_tsig,
)

logger = structlog.get_logger(__name__)


@dataclass
class DriftRecord:
    name: str
    record_type: str
    value: str
    ttl: int | None = None


@dataclass
class ServerDrift:
    server_id: str
    server_name: str
    driver: str
    status: str  # "ok" | "error" | "unsupported"
    error: str | None = None
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


def _to_drift_record(r: RecordData | DNSRecord) -> DriftRecord:
    return DriftRecord(
        name=r.name or "@",
        record_type=r.record_type,
        value=r.value,
        ttl=r.ttl,
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
    db_by_key = {_key(r, zone.name): r for r in db_rows}

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
        try:
            on_wire, used = await pull_zone_records_signed(
                driver, srv, zone.name, keys, view_name=view_name
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
        wire_by_key = {_key(r, zone.name): r for r in on_wire}
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
            if s.status == "ok" and not view_addressed.get(s.server_id, False)
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
