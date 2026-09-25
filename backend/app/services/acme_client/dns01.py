"""DNS-01 challenge solver over SpatiumDDI's own managed zones.

Given a challenge FQDN (``example.com``) and the TXT value the CA
expects, write a ``_acme-challenge.<fqdn>`` TXT record into the matching
SpatiumDDI-managed zone and wait for the DNS agent to apply it before
returning. Cleanup deletes the same record after validation.

This mirrors :mod:`app.services.acme` (the ACME *provider* side) — the
TXT write goes through the exact same ``record_ops`` pipeline
(``enqueue_record_op`` + ``bump_zone_serial`` + ``wait_for_op_applied``)
so propagation timing + agent convergence behave identically. The only
difference is *who* owns the FQDN: here SpatiumDDI is the ACME client
proving control of one of its own zones, rather than serving an external
acme-dns client.

Zone resolution is longest-suffix match: a challenge for
``foo.bar.example.com`` lands in the ``example.com`` zone if that's the
most specific managed zone that's a suffix of the FQDN. The relative
record label is the FQDN minus the zone suffix.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import dns_group_channel, publish_wake
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSZone
from app.services.acme import ACME_TXT_TTL
from app.services.dns.record_ops import enqueue_record_op
from app.services.dns.serial import bump_zone_serial

logger = structlog.get_logger(__name__)

# The label every dns-01 challenge record sits under.
_ACME_CHALLENGE_PREFIX = "_acme-challenge"


class DNS01SolveError(Exception):
    """No managed zone covers the challenge FQDN, or the TXT write
    couldn't be applied by the DNS agent."""


@dataclass
class DNS01Handle:
    """Bookkeeping returned by :func:`solve`, consumed by :func:`cleanup`.

    Carries everything cleanup needs to delete the exact record we
    created without re-deriving it from scratch.
    """

    zone_id: object  # uuid.UUID — kept loose to avoid an import cycle
    record_name: str  # relative label inside the zone
    txt_value: str
    challenge_fqdn: str  # full _acme-challenge.<domain>


def _challenge_fqdn(domain: str) -> str:
    """``example.com`` → ``_acme-challenge.example.com`` (no trailing dot)."""
    return f"{_ACME_CHALLENGE_PREFIX}.{domain.rstrip('.')}"


async def _resolve_zone(db: AsyncSession, fqdn: str) -> tuple[DNSZone, str] | None:
    """Find the most specific managed zone whose name is a suffix of ``fqdn``.

    Returns ``(zone, relative_label)`` or ``None`` if no zone covers the
    name. ``relative_label`` is what goes in ``DNSRecord.name`` — the
    FQDN with the zone suffix stripped (``"_acme-challenge.foo"`` for a
    ``foo`` host in zone ``example.com`` validating
    ``_acme-challenge.foo.example.com``). An apex challenge yields the
    bare prefix (``"_acme-challenge"``).
    """
    target = fqdn.rstrip(".").lower()
    rows = (await db.execute(select(DNSZone).where(DNSZone.zone_type == "primary"))).scalars().all()
    best: DNSZone | None = None
    best_zone_name = ""
    for zone in rows:
        zone_name = zone.name.rstrip(".").lower()
        if not zone_name:
            continue
        if target == zone_name or target.endswith("." + zone_name):
            if len(zone_name) > len(best_zone_name):
                best = zone
                best_zone_name = zone_name
    if best is None:
        return None

    if target == best_zone_name:
        relative = "@"
    else:
        relative = target[: -(len(best_zone_name) + 1)]
    return best, relative


async def solve(db: AsyncSession, fqdn: str, txt_value: str) -> DNS01Handle:
    """Create the ``_acme-challenge.<fqdn>`` TXT record + wait for apply.

    Writes a ``DNSRecord`` row + enqueues a record op through the same
    pipeline the rest of DNS uses, bumps the zone serial, and blocks
    until EVERY agent in the zone's group acknowledges the op as
    ``applied`` (so the CA can't query a secondary whose copy is still
    pending). If anything fails after the record is committed, the
    record is torn back down here — the orchestrator never received the
    handle, so its finally-block cleanup can't fire for it.

    Raises :class:`DNS01SolveError` if no managed zone covers ``fqdn`` or
    if an agent failed / timed out applying the record.
    """
    from app.services.acme import (  # noqa: PLC0415 — avoid cycle
        apply_timeout_for,
        wait_for_ops_applied,
    )

    challenge_fqdn = _challenge_fqdn(fqdn)
    resolved = await _resolve_zone(db, challenge_fqdn)
    if resolved is None:
        raise DNS01SolveError(
            f"no SpatiumDDI-managed primary DNS zone covers {challenge_fqdn!r} — "
            f"the appliance can only solve DNS-01 for domains it hosts"
        )
    zone, relative = resolved

    record = DNSRecord(
        zone_id=zone.id,
        name=relative,
        fqdn=challenge_fqdn,
        record_type="TXT",
        value=txt_value,
        ttl=ACME_TXT_TTL,
        auto_generated=True,
    )
    db.add(record)
    target_serial = bump_zone_serial(zone)
    op_row = await enqueue_record_op(
        db,
        zone,
        "create",
        {"name": relative, "type": "TXT", "value": txt_value, "ttl": ACME_TXT_TTL},
        target_serial=target_serial,
    )
    await db.commit()
    # Worker context: ``enqueue_record_op``'s ``collect_wake`` is a no-op
    # outside a request, so wake every agent in the group explicitly —
    # otherwise the TXT only converges on the slow safety tick.
    await publish_wake(dns_group_channel(zone.group_id))

    handle = DNS01Handle(
        zone_id=zone.id,
        record_name=relative,
        txt_value=txt_value,
        challenge_fqdn=challenge_fqdn,
    )

    try:
        # Agent-based groups fan out one op per enabled server; the
        # singular ``enqueue_record_op`` return only covers the primary.
        # Wait on EVERY sibling op (same zone + serial) so the CA can't
        # query a secondary whose op is still pending.
        sibling_ids = list(
            (
                await db.execute(
                    select(DNSRecordOp.id).where(
                        DNSRecordOp.zone_name == zone.name,
                        DNSRecordOp.target_serial == target_serial,
                        DNSRecordOp.op == "create",
                    )
                )
            )
            .scalars()
            .all()
        )
        wait_ids = sibling_ids or ([op_row.id] if op_row is not None else [])
        if not wait_ids:
            # No enabled primary/agent server in the group — the record
            # won't propagate; fail now rather than letting the CA time out.
            raise DNS01SolveError(
                f"zone {zone.name!r} has no enabled primary DNS server — "
                f"cannot publish the DNS-01 challenge record"
            )
        # Scaled with the group's render time (#1184): at a million
        # records one render takes about 30 s, and a fixed 30 s wait
        # failed intermittently.
        timeout = await apply_timeout_for(db, wait_ids)
        states = await wait_for_ops_applied(wait_ids, timeout=timeout)
        not_applied = {str(i): s for i, s in states.items() if s != "applied"}
        if not_applied:
            raise DNS01SolveError(
                f"TXT record for {challenge_fqdn!r} was not applied by all DNS "
                f"agents within {timeout:.0f} s (op states: {not_applied})"
            )
    except DNS01SolveError:
        # Tear down the committed record so a failed solve doesn't orphan
        # a public _acme-challenge TXT (no janitor sweeps these).
        try:
            await cleanup(db, handle)
        except Exception as exc:  # noqa: BLE001 — best-effort teardown
            logger.warning(
                "acme_client_dns01_orphan_cleanup_failed",
                fqdn=challenge_fqdn,
                error=str(exc),
            )
        raise

    logger.info(
        "acme_client_dns01_solved",
        zone=zone.name,
        fqdn=challenge_fqdn,
        record_name=relative,
    )
    return handle


async def cleanup(db: AsyncSession, handle: DNS01Handle) -> None:
    """Delete the challenge TXT record created by :func:`solve`.

    Best-effort + idempotent: if the record was already removed (e.g. a
    re-run cleaned it up) we just no-op. Enqueues a delete op so the
    agent removes it from the served zone too.
    """
    from sqlalchemy import delete  # noqa: PLC0415

    zone = await db.get(DNSZone, handle.zone_id)
    if zone is None:
        return
    rows = (
        (
            await db.execute(
                select(DNSRecord).where(
                    DNSRecord.zone_id == handle.zone_id,
                    DNSRecord.name == handle.record_name,
                    DNSRecord.record_type == "TXT",
                    DNSRecord.value == handle.txt_value,
                )
            )
        )
        .scalars()
        .all()
    )
    for rec in rows:
        target_serial = bump_zone_serial(zone)
        await db.execute(delete(DNSRecord).where(DNSRecord.id == rec.id))
        await enqueue_record_op(
            db,
            zone,
            "delete",
            {
                "name": rec.name,
                "type": "TXT",
                "value": rec.value,
                "ttl": rec.ttl or ACME_TXT_TTL,
            },
            target_serial=target_serial,
        )
    await db.commit()
    if rows:
        # Worker context: wake the group so the delete is applied promptly
        # (collect_wake inside enqueue_record_op is a no-op off-request).
        await publish_wake(dns_group_channel(zone.group_id))
    logger.info(
        "acme_client_dns01_cleaned_up",
        fqdn=handle.challenge_fqdn,
        removed=len(rows),
    )


# ── Phase 3: managed-zone resolution + manual DNS-01 fallback ────────


@dataclass
class ManagedZoneMatch:
    """Result of :func:`resolve_managed` — the zone that will solve a
    domain's DNS-01 challenge, plus the backing driver for display."""

    zone_id: object  # uuid.UUID
    zone_name: str
    record_name: str  # relative label written into the zone
    driver: str | None  # bind9 / powerdns / cloudflare / route53 / ...


def challenge_fqdn(domain: str) -> str:
    """Public form of the challenge record FQDN (``_acme-challenge.<domain>``)."""
    return _challenge_fqdn(domain)


async def resolve_managed(db: AsyncSession, domain: str) -> ManagedZoneMatch | None:
    """Return the managed zone that covers ``domain``'s dns-01 challenge.

    ``None`` means SpatiumDDI manages no zone covering the name — the
    challenge can only be solved via the manual fallback. Used both by
    the ``/preview`` endpoint and the orchestrator's per-domain routing.
    The reported ``driver`` is the zone group's primary server driver
    (``cloudflare`` / ``route53`` / ``bind9`` / …) so the UI can show
    *how* the record will be published.
    """
    cfqdn = _challenge_fqdn(domain)
    resolved = await _resolve_zone(db, cfqdn)
    if resolved is None:
        return None
    zone, relative = resolved
    driver = (
        await db.execute(
            select(DNSServer.driver)
            .where(DNSServer.group_id == zone.group_id, DNSServer.is_primary.is_(True))
            .limit(1)
        )
    ).scalar_one_or_none()
    return ManagedZoneMatch(
        zone_id=zone.id, zone_name=zone.name, record_name=relative, driver=driver
    )


async def poll_public_txt(
    challenge_fqdn_: str,
    txt_value: str,
    *,
    timeout: float = 600.0,
    interval: float = 15.0,
) -> bool:
    """Poll public DNS until ``challenge_fqdn_`` serves the expected TXT.

    The gate for the manual fallback: we don't tell the CA to validate
    until the operator-added record is observable from a public
    resolver. Returns ``True`` once seen, ``False`` on timeout. dnspython
    is a hard dependency for this path (it ships in ``pyproject.toml``);
    if it can't be imported we can't verify and return ``False``.
    """
    try:
        import dns.asyncresolver  # noqa: PLC0415
    except Exception:  # noqa: BLE001 — dnspython missing / import error
        logger.warning("acme_client_dnspython_unavailable", fqdn=challenge_fqdn_)
        return False
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 10.0
            answer = await resolver.resolve(challenge_fqdn_, "TXT")
            for rdata in answer:
                for chunk in rdata.strings:
                    if chunk.decode("ascii", errors="ignore").strip('"') == txt_value:
                        return True
        except Exception:  # noqa: BLE001 — NXDOMAIN / timeout / no answer (not yet propagated)
            pass
        await asyncio.sleep(interval)
    return False


__all__ = [
    "DNS01Handle",
    "DNS01SolveError",
    "ManagedZoneMatch",
    "challenge_fqdn",
    "cleanup",
    "poll_public_txt",
    "resolve_managed",
    "solve",
]
