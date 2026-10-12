"""Cloud DNS live-pull importer (issue #37, Part B).

Reuses the agentless :class:`CloudDNSDriverBase` read surface that the
four cloud drivers (Cloudflare / Route 53 / Azure DNS / Google Cloud
DNS) already expose for the ``sync-from-server`` drift path:

* :meth:`CloudDNSDriverBase.pull_zones_from_server` — lists every
  hosted zone visible to the account credentials and returns one
  neutral dict per zone (same shape ``windows_dns`` returns).
* :meth:`CloudDNSDriverBase.pull_zone_records` — returns
  ``list[RecordData]`` for one zone, names relative to the apex.

Both method names match Windows DNS Path B verbatim, so this module is
a near-clone of :mod:`app.services.dns_import.windows_dns`: it wraps the
driver's reads into the canonical :class:`ImportPreview` shape and hands
the IR to the same source-agnostic :func:`commit_import` pipeline that
ships BIND9 / Windows / PowerDNS zones.

**SOA fields:** cloud providers own the SOA on their side and the
record walkers return records relative to the apex without an SOA row
(SOA / apex-NS are provider-managed). As Windows DNS does, we apply
standards-compliant defaults (86400/7200/3600000/3600/3600) on the
imported zone and surface a per-zone warning. SpatiumDDI's apply
pipeline rewrites the SOA from the zone's own ``primary_ns`` /
``admin_email`` columns when it pushes config back, so the defaults are
placeholders for the operator-facing preview, not load-bearing values.

**DNSSEC:** providers report ``dnssec_enabled`` on the zone-list dict,
but the canonical IR can't model DNSKEY / RRSIG / NSEC chains (the
shared committer drops them, same as the BIND9 archive importer). When
a source zone is signed we surface a per-zone warning so the operator
knows online-signing state has to be re-established on the destination
driver after import.

**Source label:** ``ImportPreview.source`` carries the *provider* name
(``cloudflare`` / ``route53`` / ``azure_dns`` / ``google_dns``), not a
generic ``"cloud"`` — that's the same string stamped into every created
row's ``import_source`` column so provenance stays queryable per
provider. The :data:`app.services.dns_import.canonical.ImportSource`
``Literal`` is widened to include all four provider names, so the label
is type-honest; ``server.driver`` (a runtime ``str``) is ``cast`` to
``ImportSource`` at the assignment site since the column type is plain
``String(20)``.
"""

from __future__ import annotations

import uuid
from typing import Any, cast

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns import CLOUD_DNS_DRIVERS, get_driver
from app.models.auth import User
from app.models.dns import DNSServer

from .canonical import (
    ImportedRecord,
    ImportedSOA,
    ImportedZone,
    ImportPreview,
    ImportSource,
)
from .commit import (
    CommitResult,
    ConflictAction,
    commit_import,
    detect_conflicts,
)

logger = structlog.get_logger(__name__)


class CloudDNSImportError(ValueError):
    """Raised when a cloud DNS server can't be live-pulled.

    Mirrors :class:`WindowsDNSImportError`: per-zone failures don't
    raise this — they surface as ``ImportedZone.parse_warnings`` on the
    affected zone so the operator sees the partial-success state instead
    of losing the whole import to a flake on one zone.
    """


# Driver names that route through this importer — sourced directly from the
# driver registry so a newly-registered CloudDNSDriverBase subclass (e.g. the
# token-only providers in #327) is recognised here with no second edit. The
# preview validates ``server.driver`` against this set before touching the
# driver so a BIND9 / PowerDNS / Windows server gets a clear error rather than
# a confusing AttributeError downstream.
CLOUD_DRIVERS: frozenset[str] = CLOUD_DNS_DRIVERS

# Default SOA fields applied when the source doesn't provide them.
# Same conservative RFC 1035 reference numbers ``windows_dns`` uses so
# both importers seed identical placeholder zones.
_DEFAULT_SOA = {
    "refresh": 86400,
    "retry": 7200,
    "expire": 3600000,
    "minimum": 3600,
    "ttl": 3600,
}


def _normalize_fqdn(name: str) -> str:
    return name if name.endswith(".") else name + "."


async def preview_cloud_import(
    db: AsyncSession,
    *,
    server_id: uuid.UUID,
    target_group_id: uuid.UUID,
    target_view_id: uuid.UUID | None = None,
) -> ImportPreview:
    """Live-pull every hosted zone + its records from a cloud DNS server.

    Loads the :class:`DNSServer` row identified by ``server_id``,
    validates it's backed by a cloud driver, resolves the driver via the
    registry, and coerces the driver's neutral zone / record reads into
    the canonical :class:`ImportPreview` shape. Conflicts against
    existing :class:`DNSZone` rows in ``target_group_id`` (+ optional
    ``target_view_id``) are computed via the shared
    :func:`detect_conflicts` so the preview's per-zone strategy picker
    matches every other source.

    Raises :class:`CloudDNSImportError` (a ``ValueError`` subclass) when
    the server doesn't exist or isn't a cloud driver. Per-zone record
    pull failures are non-fatal — they land in the affected zone's
    ``parse_warnings``.
    """

    server = (
        await db.execute(select(DNSServer).where(DNSServer.id == server_id))
    ).scalar_one_or_none()
    if server is None:
        raise CloudDNSImportError(f"DNS server {server_id} does not exist")
    if server.driver not in CLOUD_DRIVERS:
        raise CloudDNSImportError(
            f"DNS server {server.name!r} uses driver {server.driver!r}; "
            f"cloud import requires one of {sorted(CLOUD_DRIVERS)}"
        )

    # Provider name doubles as the import_source provenance label.
    source = cast(ImportSource, server.driver)
    driver = get_driver(server.driver)

    try:
        zone_meta_list: list[dict[str, Any]] = await driver.pull_zones_from_server(server)
    except Exception as exc:  # noqa: BLE001 — operator-facing error capture
        raise CloudDNSImportError(
            f"Could not list zones on cloud DNS server {server.name!r}: {exc}"
        ) from exc

    zones: list[ImportedZone] = []
    overall_warnings: list[str] = []

    for meta in zone_meta_list:
        raw_name = str(meta.get("name") or "").strip()
        if not raw_name:
            continue
        fqdn = _normalize_fqdn(raw_name).lower()
        # Cloud providers only host primary (authoritative) zones; the
        # driver's pull_zones_from_server already reports "Primary".
        zone_type = "primary"
        kind = "reverse" if meta.get("is_reverse_lookup") else "forward"

        # SOA defaults — providers own the SOA + apex NS, and the record
        # walker returns neither. SpatiumDDI rewrites the SOA from the
        # zone's columns at push time, so these are operator-facing
        # placeholders, flagged with a warning.
        soa = ImportedSOA(
            primary_ns="",
            admin_email="",
            serial=0,
            refresh=_DEFAULT_SOA["refresh"],
            retry=_DEFAULT_SOA["retry"],
            expire=_DEFAULT_SOA["expire"],
            minimum=_DEFAULT_SOA["minimum"],
            ttl=_DEFAULT_SOA["ttl"],
        )

        per_zone_warnings: list[str] = [
            "SOA defaults applied; edit primary_ns / admin_email / serial via the zone editor post-import"
        ]
        if meta.get("dnssec_enabled"):
            per_zone_warnings.append(
                f"{raw_name!r} is DNSSEC-signed on the provider; signing state "
                "is not imported — re-enable online signing on the destination "
                "driver after commit if required."
            )

        # Per-zone record pull. Failures here are non-fatal — surface
        # them as warnings on the zone and move on so one bad zone in a
        # large account doesn't abort the whole import.
        records: list[ImportedRecord] = []
        try:
            pulled = await driver.pull_zone_records(server, raw_name)
            for r in pulled:
                records.append(
                    ImportedRecord(
                        name=r.name,
                        record_type=r.record_type,
                        value=r.value,
                        ttl=r.ttl,
                        priority=r.priority,
                        weight=r.weight,
                        port=r.port,
                    )
                )
        except Exception as exc:  # noqa: BLE001 — operator-facing
            per_zone_warnings.append(f"Record pull failed: {exc}")

        zones.append(
            ImportedZone(
                name=fqdn,
                zone_type=zone_type,
                kind=kind,
                soa=soa,
                records=records,
                # Cloud providers have no BIND9-style view concept; the
                # operator targets a SpatiumDDI view via target_view_id.
                view_name=None,
                forwarders=[],
                skipped_record_types={},
                parse_warnings=per_zone_warnings,
            )
        )

    if not zones:
        overall_warnings.append(
            f"No hosted zones reported by the {server.driver} account. Check "
            "that the configured credentials have list-zone permission."
        )

    total_records = sum(len(z.records) for z in zones)
    histogram: dict[str, int] = {}
    for z in zones:
        for r in z.records:
            histogram[r.record_type] = histogram.get(r.record_type, 0) + 1

    conflicts = await detect_conflicts(
        db,
        zone_names=[z.name for z in zones],
        target_group_id=target_group_id,
        target_view_id=target_view_id,
    )

    logger.info(
        "cloud_dns_import.preview",
        driver=server.driver,
        server=str(server.id),
        zones=len(zones),
        records=total_records,
        conflicts=len(conflicts),
    )

    return ImportPreview(
        source=source,
        zones=zones,
        conflicts=conflicts,
        warnings=overall_warnings,
        total_records=total_records,
        record_type_histogram=histogram,
        source_server_id=server.id,
    )


async def commit_cloud_import(
    db: AsyncSession,
    *,
    preview: ImportPreview,
    target_group_id: uuid.UUID,
    target_view_id: uuid.UUID | None,
    conflict_actions: dict[str, tuple[ConflictAction, str | None]],
    current_user: User,
) -> CommitResult:
    """Commit a cloud import preview.

    Thin pass-through to the source-agnostic :func:`commit_import`. The
    committer reads ``preview.source`` (the provider name) and stamps it
    onto every ``DNSZone`` / ``DNSRecord`` ``import_source`` column, so
    there's no cloud-specific commit logic — this wrapper exists only so
    the API router can import a symmetric ``preview_*`` / ``commit_*``
    pair (matching the Windows DNS endpoint's structure).
    """

    return await commit_import(
        db,
        preview=preview,
        target_group_id=target_group_id,
        target_view_id=target_view_id,
        conflict_actions=conflict_actions,
        current_user=current_user,
    )
