"""TLS cert target auto-discovery (issue #118, Phase 1).

Projects probe targets from DNS state, so the cert inventory tracks the
hostnames SpatiumDDI already manages instead of being a parallel list the
operator maintains by hand:

* **create** — one ``tls_cert_target(source='discovered')`` per A/AAAA
  record whose parent zone has ``auto_tls_probe=True`` *or* whose own
  ``auto_tls_probe=True``. Connect host is the record's stored ``fqdn``;
  the connect tuple ``(host, 443, NULL)`` dedupes the same name surfacing
  from multiple records.
* **disable** — a discovered target whose source record was opted out or
  soft-deleted is flagged ``enabled=False`` (kept, not deleted, so its
  probe history survives and it re-enables cleanly if the record returns).
* **relink** — fill any target's empty ``dns_zone_id`` / ``domain_id`` by
  longest-suffix match of its observed SANs against managed zones +
  domains (so a manually-added external cert still shows under the right
  Domain / DNS-zone Certificates tab once probed).

Soft-deleted ``dns_record`` / ``dns_zone`` rows are excluded automatically
by the ORM soft-delete query filter (``app.db._filter_soft_deleted``).

Mirrors the no-commit contract of the probe service — the caller (the
discovery task) owns the commit.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import structlog
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSZone
from app.models.domain import Domain
from app.models.ipam import TLS_SERVING_ROLES, IPAddress
from app.models.tls_cert import SOURCE_DISCOVERED, TLSCertTarget
from app.services.ipam.host_name import current_fqdn

logger = structlog.get_logger(__name__)


def _host_for_ip(ip: IPAddress) -> str:
    """Probe host for a TLS-serving IP — prefer a name (so SNI + cert-name
    match work), fall back to the literal IP."""
    fqdn = current_fqdn(ip.hostname, ip.fqdn)
    if fqdn and fqdn.strip():
        return fqdn.rstrip(".").lower()
    if ip.hostname and ip.hostname.strip():
        return ip.hostname.rstrip(".").lower()
    return str(ip.address).split("/")[0]


def _best_suffix_match(
    names: list[str], candidates_desc: list[tuple[uuid.UUID, str]]
) -> uuid.UUID | None:
    """Longest-suffix match of any name against ``candidates_desc`` (which
    must be pre-sorted longest-name-first). The leading ``.`` guard keeps
    ``example.com.au`` from matching the zone ``example.com``."""
    for cid, cname in candidates_desc:
        for name in names:
            if name == cname or name.endswith("." + cname):
                return cid
    return None


async def _relink_by_san(db: AsyncSession) -> int:
    """Fill empty zone/domain FKs on any target from its observed SANs."""
    zones = [
        (zid, (zname or "").rstrip(".").lower())
        for zid, zname in (await db.execute(select(DNSZone.id, DNSZone.name))).all()
    ]
    domains = [
        (did, (dname or "").rstrip(".").lower())
        for did, dname in (await db.execute(select(Domain.id, Domain.name))).all()
    ]
    zones.sort(key=lambda z: len(z[1]), reverse=True)
    domains.sort(key=lambda d: len(d[1]), reverse=True)

    relinked = 0
    # Only targets actually missing a link can be updated here — scanning
    # every target each tick is wasted work.
    targets = (
        (
            await db.execute(
                select(TLSCertTarget).where(
                    or_(
                        TLSCertTarget.dns_zone_id.is_(None),
                        TLSCertTarget.domain_id.is_(None),
                    )
                )
            )
        )
        .scalars()
        .all()
    )
    for t in targets:
        sans = [s.rstrip(".").lower() for s in (t.sans_json or []) if isinstance(s, str)]
        if not sans:
            continue
        if t.dns_zone_id is None:
            zid = _best_suffix_match(sans, zones)
            if zid is not None:
                t.dns_zone_id = zid
                relinked += 1
        if t.domain_id is None:
            did = _best_suffix_match(sans, domains)
            if did is not None:
                t.domain_id = did
                relinked += 1
    return relinked


async def reconcile_discovered_targets(
    db: AsyncSession, now: datetime | None = None
) -> dict[str, int]:
    """Create / disable discovered targets + relink by SAN. No commit."""
    _ = now or datetime.now(UTC)

    # Unified candidate map keyed on the connect tuple (host, 443, None).
    # Each value carries whatever provenance links apply (DNS record/zone/
    # domain + IPAM IP) — the same FQDN can surface from a DNS record AND a
    # TLS-serving IP, which merge into one target.
    candidates: dict[tuple[str, int, None], dict[str, uuid.UUID | None]] = {}

    # Source 1 — opted-in DNS A/AAAA records.
    dns_rows = (
        await db.execute(
            select(DNSRecord, DNSZone)
            .join(DNSZone, DNSRecord.zone_id == DNSZone.id)
            .where(
                DNSRecord.record_type.in_(("A", "AAAA")),
                or_(
                    DNSZone.auto_tls_probe.is_(True),
                    DNSRecord.auto_tls_probe.is_(True),
                ),
            )
        )
    ).all()
    for rec, zone in dns_rows:
        host = (rec.fqdn or "").rstrip(".").lower()
        if not host:
            continue
        cand = candidates.setdefault((host, 443, None), {})
        cand.setdefault("dns_record_id", rec.id)
        cand.setdefault("dns_zone_id", zone.id)
        cand.setdefault("domain_id", zone.domain_id)

    # Source 2 — IPs classified into a TLS-serving role (#118 Phase 2).
    ip_rows = (
        (await db.execute(select(IPAddress).where(IPAddress.role.in_(TLS_SERVING_ROLES))))
        .scalars()
        .all()
    )
    for ip in ip_rows:
        host = _host_for_ip(ip)
        if not host:
            continue
        cand = candidates.setdefault((host, 443, None), {})
        cand.setdefault("ip_address_id", ip.id)

    existing = (
        (await db.execute(select(TLSCertTarget).where(TLSCertTarget.source == SOURCE_DISCOVERED)))
        .scalars()
        .all()
    )
    existing_by_key = {(t.host.lower(), t.port, t.server_name): t for t in existing}

    created = reenabled = 0
    for (host, port, sni), cand in candidates.items():
        et = existing_by_key.get((host, port, sni))
        if et is not None:
            # Already tracked. Re-enable + refresh provenance. Discovered
            # targets are a projection of DNS/IPAM state — to stop probing,
            # opt the source out; a manually-disabled discovered row is
            # re-enabled here by design.
            touched = False
            if not et.enabled:
                et.enabled = True
                touched = True
            for field in ("dns_record_id", "dns_zone_id", "domain_id", "ip_address_id"):
                val = cand.get(field)
                if val is not None and getattr(et, field) != val:
                    setattr(et, field, val)
                    touched = True
            reenabled += 1 if touched else 0
            continue
        # Don't collide with a manually-added target on the same tuple.
        clash = await db.scalar(
            select(TLSCertTarget).where(
                func.lower(TLSCertTarget.host) == host,
                TLSCertTarget.port == port,
                TLSCertTarget.server_name.is_(None),
            )
        )
        if clash is not None:
            continue
        db.add(
            TLSCertTarget(
                host=host,
                port=port,
                server_name=None,
                display_name=host,
                source=SOURCE_DISCOVERED,
                dns_record_id=cand.get("dns_record_id"),
                dns_zone_id=cand.get("dns_zone_id"),
                domain_id=cand.get("domain_id"),
                ip_address_id=cand.get("ip_address_id"),
                enabled=True,
                next_check_at=None,  # picked up on the next probe sweep
            )
        )
        created += 1

    # Disable discovered targets no longer backed by any opted-in source —
    # keyed on the connect tuple (not the FK), so a hard-deleted record /
    # role change (FK SET NULL'd) is caught too.
    candidate_keys = set(candidates.keys())
    disabled = 0
    for t in existing:
        key = (t.host.lower(), t.port, t.server_name)
        if t.enabled and key not in candidate_keys:
            t.enabled = False
            disabled += 1

    relinked = await _relink_by_san(db)

    if created or disabled or relinked or reenabled:
        logger.info(
            "tls_cert_discovery",
            created=created,
            reenabled=reenabled,
            disabled=disabled,
            relinked=relinked,
        )
    return {
        "created": created,
        "reenabled": reenabled,
        "disabled": disabled,
        "relinked": relinked,
    }
