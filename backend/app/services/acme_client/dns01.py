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

Public zones win over internal ones (#1454): with split-horizon DNS an
internal-only ``home.example.com`` must not take the challenge for
``*.home.example.com`` away from the public ``example.com`` parent, or a
public CA never sees the TXT. A zone counts as public when its group is
``group_type == "external"`` or the group is served by a cloud DNS
driver. Internal zones are only used when no public zone covers the
name, which keeps a private ACME CA that resolves internally working.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import dns_group_channel, publish_wake
from app.drivers.dns import CLOUD_DNS_DRIVERS
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.acme import ACME_TXT_TTL
from app.services.dns.record_ops import enqueue_record_op
from app.services.dns.serial import bump_zone_serial
from app.services.integration_ownership import ACME_RECORD_TAG

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
    """``example.com`` → ``_acme-challenge.example.com`` (no trailing dot).

    A wildcard is validated at its base name (RFC 8555 §7.1.3), so
    ``*.example.com`` maps to ``_acme-challenge.example.com`` too. The
    orchestrator already passes the authorization identifier, which never
    carries the ``*.``; this matters for ``/preview``, which gets the
    names as the operator typed them.
    """
    name = domain.rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    return f"{_ACME_CHALLENGE_PREFIX}.{name}"


@dataclass
class _ResolvedZone:
    zone: DNSZone
    relative: str  # label inside the zone ("@" for the apex)
    public: bool
    # A more specific (or same-named) internal zone that also covers the
    # name and was passed over in favour of the public one.
    skipped_internal: DNSZone | None = None


async def _resolve_zone(db: AsyncSession, fqdn: str) -> _ResolvedZone | None:
    """Find the managed zone the challenge TXT for ``fqdn`` goes into.

    Longest-suffix match, but public zones are tried first: the most
    specific public zone (group type ``external`` or served by a cloud
    DNS driver) that covers ``fqdn`` wins, even when an internal zone is
    more specific. Only when no public zone covers the name does the most
    specific internal zone get it. ``None`` if no primary zone covers it.

    ``relative`` is what goes in ``DNSRecord.name`` — the FQDN with the
    zone suffix stripped (``"_acme-challenge.foo"`` for a ``foo`` host in
    zone ``example.com``). An apex name yields ``"@"``.
    """
    target = fqdn.rstrip(".").lower()
    rows = (
        await db.execute(
            select(DNSZone, DNSServerGroup.group_type)
            .join(DNSServerGroup, DNSServerGroup.id == DNSZone.group_id)
            .where(DNSZone.zone_type == "primary")
        )
    ).all()
    cloud_group_ids = set(
        (
            await db.execute(
                select(DNSServer.group_id).where(DNSServer.driver.in_(CLOUD_DNS_DRIVERS)).distinct()
            )
        )
        .scalars()
        .all()
    )

    # public? -> (name, zone) of the most specific zone covering ``target``
    best: dict[bool, tuple[str, DNSZone]] = {}
    for zone, group_type in rows:
        zone_name = zone.name.rstrip(".").lower()
        if not zone_name:
            continue
        if not (target == zone_name or target.endswith("." + zone_name)):
            continue
        public = group_type == "external" or zone.group_id in cloud_group_ids
        if public not in best or len(zone_name) > len(best[public][0]):
            best[public] = (zone_name, zone)

    skipped: DNSZone | None = None
    if True in best:
        chosen_name, chosen = best[True]
        public = True
        internal = best.get(False)
        if internal is not None and len(internal[0]) >= len(chosen_name):
            skipped = internal[1]
    elif False in best:
        chosen_name, chosen = best[False]
        public = False
    else:
        return None

    relative = "@" if target == chosen_name else target[: -(len(chosen_name) + 1)]
    return _ResolvedZone(zone=chosen, relative=relative, public=public, skipped_internal=skipped)


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
    if an agent failed / timed out applying the record. Any other
    exception after the commit (a DB error in the sibling-op query, a
    Celery soft time limit, …) also tears the record down before
    re-raising (#1530) — the teardown is keyed on the handle, which is
    built BEFORE the commit for exactly that reason.
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
    zone, relative = resolved.zone, resolved.relative
    if resolved.skipped_internal is not None:
        logger.info(
            "acme_client_dns01_internal_zone_skipped",
            fqdn=challenge_fqdn,
            zone=zone.name,
            skipped_zone=resolved.skipped_internal.name,
        )

    record = DNSRecord(
        zone_id=zone.id,
        name=relative,
        fqdn=challenge_fqdn,
        record_type="TXT",
        value=txt_value,
        ttl=ACME_TXT_TTL,
        auto_generated=True,
        # #1554: ACME records are not IPAM sync output — mark them so
        # the IPAM DNS drift sweep leaves them alone.
        tags={ACME_RECORD_TAG: True},
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
    # Build the handle BEFORE the commit (#1530): everything from the
    # commit on runs under the teardown guard below, and the teardown
    # needs the handle to find the record again.
    handle = DNS01Handle(
        zone_id=zone.id,
        record_name=relative,
        txt_value=txt_value,
        challenge_fqdn=challenge_fqdn,
    )

    try:
        await db.commit()
        # Worker context: ``enqueue_record_op``'s ``collect_wake`` is a no-op
        # outside a request, so wake every agent in the group explicitly —
        # otherwise the TXT only converges on the slow safety tick.
        await publish_wake(dns_group_channel(zone.group_id))

        # Agent-based groups fan out one op per enabled server; the
        # singular ``enqueue_record_op`` return only covers the primary.
        # Wait on EVERY sibling op (same zone + serial) so the CA can't
        # query a secondary whose op is still pending. The query is
        # scoped to servers in THIS zone's group (#1531): serials are
        # date-based (``YYYYMMDDNN``), so a same-name zone in another
        # group — e.g. the internal half of a split-horizon pair — can
        # easily hold a create op at the same serial, and waiting on it
        # would stall (or fail) a solve that had in fact applied
        # everywhere it needed to.
        group_server_ids = select(DNSServer.id).where(DNSServer.group_id == zone.group_id)
        sibling_ids = list(
            (
                await db.execute(
                    select(DNSRecordOp.id).where(
                        DNSRecordOp.zone_name == zone.name,
                        DNSRecordOp.target_serial == target_serial,
                        DNSRecordOp.op == "create",
                        DNSRecordOp.server_id.in_(group_server_ids),
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
    except Exception:
        # Tear down the committed record so a failed solve doesn't orphan
        # a public _acme-challenge TXT. This covers EVERY failure after
        # the commit (#1530), not just DNS01SolveError: a DB error in the
        # sibling query, an error inside the wait helpers, or a Celery
        # soft time limit would otherwise strand the record (the stale
        # TXT sweep in ``services/acme.py`` is only a backstop). Roll
        # back first — a DB error may have left the session unusable,
        # and the record itself was committed, so the rollback can't
        # undo it.
        try:
            await db.rollback()
        except Exception:  # noqa: BLE001 — session may already be clean
            pass
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
    public: bool = False  # zone is in an external group / on a cloud driver
    # Internal zone that also covers the name but was passed over for the
    # public one (#1454) — surfaced by ``/preview``.
    skipped_zone_name: str | None = None


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
    zone, relative = resolved.zone, resolved.relative
    driver = (
        await db.execute(
            select(DNSServer.driver)
            .where(DNSServer.group_id == zone.group_id, DNSServer.is_primary.is_(True))
            .limit(1)
        )
    ).scalar_one_or_none()
    skipped = resolved.skipped_internal
    return ManagedZoneMatch(
        zone_id=zone.id,
        zone_name=zone.name,
        record_name=relative,
        driver=driver,
        public=resolved.public,
        skipped_zone_name=skipped.name if skipped is not None else None,
    )


async def _authoritative_ns_hosts(challenge_fqdn_: str) -> list[str]:
    """Resolve the authoritative NS hostnames for ``challenge_fqdn_``'s zone.

    Walks up the label chain (``_acme-challenge.www.example.com`` →
    ``www.example.com`` → ``example.com``) asking the system resolver
    for NS records, and returns the first non-empty NS set found — that
    set is the zone's authoritative servers, i.e. exactly what a CA
    queries when validating. Returns ``[]`` when no level answers with
    NS records (zone not delegated yet / resolver failure).
    """
    import dns.asyncresolver  # noqa: PLC0415

    labels = challenge_fqdn_.rstrip(".").split(".")
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 10.0
    # Stop before the bare TLD — it is never the challenge's zone.
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        try:
            answer = await resolver.resolve(candidate, "NS")
        except Exception:  # noqa: BLE001 — no NS at this level; walk up
            continue
        hosts = [str(rdata.target).rstrip(".") for rdata in answer if str(rdata.target)]
        if hosts:
            return hosts
    return []


async def _txt_values_at(nameserver_ip: str, fqdn: str) -> set[str]:
    """TXT values for ``fqdn`` served by ONE authoritative server.

    Queries ``nameserver_ip`` directly (bypassing the system resolver's
    cache and any split-horizon view) — the certbot/lego propagation
    model. Raises on NXDOMAIN / timeout / no answer; the caller treats
    that as "not propagated yet".
    """
    import dns.asyncresolver  # noqa: PLC0415

    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [nameserver_ip]
    resolver.lifetime = 10.0
    answer = await resolver.resolve(fqdn, "TXT")
    values: set[str] = set()
    for rdata in answer:
        for chunk in rdata.strings:
            values.add(chunk.decode("ascii", errors="ignore").strip('"'))
    return values


async def _ns_host_ips(host: str) -> list[str]:
    """A/AAAA addresses for an authoritative NS hostname (system resolver)."""
    import dns.asyncresolver  # noqa: PLC0415

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 10.0
    ips: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(host, rdtype)
        except Exception:  # noqa: BLE001 — family absent is fine
            continue
        ips.extend(str(rdata) for rdata in answer)
    return ips


async def _txt_on_all_authoritative(challenge_fqdn_: str, txt_value: str) -> bool:
    """True only when EVERY authoritative NS serves ``txt_value``.

    Any gap — the NS set not resolvable yet, an NS hostname with no
    address, or one server not yet serving the record — returns False
    so the poller keeps waiting instead of signalling the CA early.
    """
    hosts = await _authoritative_ns_hosts(challenge_fqdn_)
    if not hosts:
        return False
    for host in hosts:
        ips = await _ns_host_ips(host)
        if not ips:
            return False
        for ip in ips:
            try:
                values = await _txt_values_at(ip, challenge_fqdn_)
            except Exception:  # noqa: BLE001 — not propagated to this server yet
                return False
            if txt_value not in values:
                return False
    return True


async def poll_public_txt(
    challenge_fqdn_: str,
    txt_value: str,
    *,
    timeout: float = 600.0,
    interval: float = 15.0,
) -> bool:
    """Poll until ``challenge_fqdn_`` serves the expected TXT on EVERY
    authoritative nameserver for its zone.

    The gate for the manual fallback: we don't tell the CA to validate
    until the operator-added record is observable on the servers the CA
    will actually query. This deliberately does NOT use the worker's own
    resolver for the TXT check (#1532): on a split-horizon or caching
    setup that resolver can return the record while the zone's public
    authoritative servers don't have it yet, so the CA was told "ready"
    too early and the authorization failed. Following certbot/lego, the
    zone's NS set is resolved first and each authoritative server is
    queried directly; all of them must serve the value. Returns
    ``True`` once they do, ``False`` on timeout. dnspython is a hard
    dependency for this path (it ships in ``pyproject.toml``); if it
    can't be imported we can't verify and return ``False``.
    """
    try:
        import dns.asyncresolver  # noqa: PLC0415, F401 — presence check only
    except Exception:  # noqa: BLE001 — dnspython missing / import error
        logger.warning("acme_client_dnspython_unavailable", fqdn=challenge_fqdn_)
        return False
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            if await _txt_on_all_authoritative(challenge_fqdn_, txt_value):
                return True
        except Exception:  # noqa: BLE001 — transient resolver error; keep polling
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
