"""Read-only conformance report for existing DNS-shaped names (issue #597).

The #597 validators reject non-conforming names on *write*, but rows that
predate them stay in the database untouched (the deliberate "validate +
report, never auto-mutate" stance). This module scans the existing
IPAM hostnames, DNS record owners, DNS zone names, and DHCP static
reservation hostnames and reports which ones would now be rejected, so an
operator can fix them deliberately. It never mutates anything.

Each category caps the number of returned examples (the full offending
set on a large install could be huge) but reports the true total count so
the operator knows the real scale.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import (
    validate_fqdn,
    validate_hostname,
    validate_record_owner,
)
from app.models.dhcp import DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IP_STATUSES_INTEGRATION_OWNED, IPAddress

# Yield the event loop every this-many rows so a large scan (CPU-bound regex
# + IDNA validation) doesn't monopolize the loop and stall other requests.
_YIELD_EVERY = 2000

# Cap the examples returned per category — the count is always exact, only
# the ``examples`` list is truncated.
_EXAMPLES_PER_CATEGORY = 100
# Hard ceiling on rows scanned per category so the report can't run away on
# a multi-million-row install; ``scanned_capped`` flags when it bit.
_MAX_SCAN_PER_CATEGORY = 200_000


@dataclass
class _CategoryReport:
    category: str
    total: int = 0
    scanned_capped: bool = False
    examples: list[dict[str, Any]] = field(default_factory=list)

    def add(self, *, row_id: Any, value: str, reason: str, context: str | None = None) -> None:
        self.total += 1
        if len(self.examples) < _EXAMPLES_PER_CATEGORY:
            ex: dict[str, Any] = {"id": str(row_id), "value": value, "reason": reason}
            if context is not None:
                ex["context"] = context
            self.examples.append(ex)

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "total": self.total,
            "scanned_capped": self.scanned_capped,
            "examples": self.examples,
        }


async def _scan_category(
    db: AsyncSession,
    report: _CategoryReport,
    stmt: Select,
    check: Callable[[str], Any],
    *,
    has_context: bool = False,
) -> None:
    """Stream one category's rows through ``check``; flag violations.

    Fetches ``cap + 1`` so ``scanned_capped`` distinguishes "exactly at the
    cap" (fully scanned) from "truncated" (issue #597 review), and yields the
    event loop every ``_YIELD_EVERY`` rows so the CPU-bound validation can't
    stall other requests. ``check`` raises ``ValueError`` on a bad value.
    """
    rows = (await db.execute(stmt.limit(_MAX_SCAN_PER_CATEGORY + 1))).all()
    report.scanned_capped = len(rows) > _MAX_SCAN_PER_CATEGORY
    for i, row in enumerate(rows[:_MAX_SCAN_PER_CATEGORY]):
        row_id, value = row[0], row[1]
        ctx = row[2] if has_context else None
        try:
            check(value)
        except ValueError as exc:
            report.add(row_id=row_id, value=value, reason=str(exc), context=ctx)
        if i and i % _YIELD_EVERY == 0:
            await asyncio.sleep(0)


async def scan_name_conformance(db: AsyncSession) -> dict[str, Any]:
    """Scan existing rows for names the #597 validators would now reject.

    Returns a dict with one entry per category plus a ``total`` rollup.
    Read-only — issues plain SELECTs and validates in Python.
    """
    ipam = _CategoryReport("ipam_hostname")
    rec = _CategoryReport("dns_record_name")
    zone = _CategoryReport("dns_zone_name")
    static = _CategoryReport("dhcp_static_hostname")

    # IPAM hostnames (host rule). Exclude integration-owned rows: their names
    # are set by an external mirror (Docker / Proxmox / UniFi / …) the operator
    # can't fix here, and the render boundary + DDNS re-sanitize already keep
    # them safe — flagging them would be permanent unfixable noise (#597 review).
    await _scan_category(
        db,
        ipam,
        select(IPAddress.id, IPAddress.hostname).where(
            IPAddress.hostname.isnot(None),
            IPAddress.hostname != "",
            IPAddress.status.notin_(IP_STATUSES_INTEGRATION_OWNED),
        ),
        validate_hostname,
    )

    # DNS record owners (RFC 2181 rule).
    await _scan_category(
        db,
        rec,
        select(DNSRecord.id, DNSRecord.name, DNSRecord.fqdn),
        lambda v: validate_record_owner(v or "@"),
        has_context=True,
    )

    # DNS zone names (FQDN rule). Strip the stored trailing dot first.
    await _scan_category(
        db,
        zone,
        select(DNSZone.id, DNSZone.name),
        lambda v: validate_fqdn((v or "").rstrip("."), field="zone name"),
    )

    # DHCP static reservation hostnames (host rule; empty is allowed here).
    await _scan_category(
        db,
        static,
        select(DHCPStaticAssignment.id, DHCPStaticAssignment.hostname).where(
            DHCPStaticAssignment.hostname.isnot(None),
            DHCPStaticAssignment.hostname != "",
        ),
        validate_hostname,
    )

    categories = [ipam, rec, zone, static]
    return {
        "total_nonconforming": sum(c.total for c in categories),
        "examples_per_category": _EXAMPLES_PER_CATEGORY,
        "categories": [c.as_dict() for c in categories],
    }
