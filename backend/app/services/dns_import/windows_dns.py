"""Windows DNS live-pull importer (issue #128 Phase 2).

Reuses the existing ``WindowsDNSDriver`` Path B (WinRM + PowerShell)
read methods that the Logs surface already drives:

* :meth:`WindowsDNSDriver.pull_zones_from_server` — walks
  ``Get-DnsServerZone`` and returns one neutral dict per zone.
* :meth:`WindowsDNSDriver.pull_zone_records` — walks
  ``Get-DnsServerResourceRecord`` and returns ``list[RecordData]``.

Both already exist for read-only zone topology surfacing; this
module just wraps them into the canonical
:class:`ImportPreview` shape so the same commit pipeline that
ships BIND9 zones can ship Windows DNS zones too.

**SOA fields:** Windows DNS owns SOA on the server side. The
PowerShell record walker explicitly skips SOA records (and apex
NS — Windows generates those from the zone's authoritative server
list). For Phase 2 we apply standards-compliant defaults
(3600/86400/7200/3600000/3600) on the imported zone and surface a
warning. SpatiumDDI's apply pipeline will overwrite the SOA with
its own zone-level ``primary_ns`` / ``admin_email`` values when it
pushes config back, so the defaults aren't load-bearing — they're
just placeholders for the operator-facing UI.

**System zones:** Windows ships a handful of internal zones that
operators almost never want in IPAM (``TrustAnchors``,
``RootDNSServers``, ``0.in-addr.arpa``, the AD-internal ``_msdcs.*``
forest zone). We surface them in the preview with a per-zone
warning so the operator can pick "skip" if they don't want them,
but we don't filter them out blindly — some shops do replicate
``_msdcs`` into a secondary SpatiumDDI-managed zone for staging.
"""

from __future__ import annotations

from typing import Any

from app.drivers.dns.windows import WindowsDNSDriver

from .canonical import (
    ImportedRecord,
    ImportedSOA,
    ImportedZone,
    ImportPreview,
)


class WindowsDNSImportError(ValueError):
    """Raised when the Windows server can't be live-pulled.

    Per-zone errors don't raise this — they surface as
    ``ImportedZone.parse_warnings`` so the operator sees the
    partial-success state.
    """


# Default SOA fields applied when the source doesn't provide them.
# Conservative numbers — match the BIND9 RFC 1035 reference values
# the DNSZone column defaults already use.
_DEFAULT_SOA = {
    "refresh": 86400,
    "retry": 7200,
    "expire": 3600000,
    "minimum": 3600,
    "ttl": 3600,
}

# Lowercased zone-name suffixes for AD-internal / Windows-system
# zones. Surfaced with a warning so the operator picks skip in the
# UI; not silently filtered (some shops want them).
_SYSTEM_ZONE_HINTS = (
    "trustanchors",
    "rootdnsservers",
    "_msdcs.",
    "domaindnszones.",
    "forestdnszones.",
)


def _looks_like_system_zone(name: str) -> bool:
    n = name.lower().rstrip(".")
    if n in {"trustanchors", "rootdnsservers", "0.in-addr.arpa"}:
        return True
    return any(n.startswith(h) or n.endswith("." + h.rstrip(".")) for h in _SYSTEM_ZONE_HINTS)


def _classify_zone(name: str, is_reverse_lookup: bool | None) -> str:
    """``forward`` or ``reverse``. Honours the Windows-side
    ``IsReverseLookupZone`` flag if present, else falls back to the
    ``in-addr.arpa`` / ``ip6.arpa`` suffix match the BIND9 importer
    uses."""
    if is_reverse_lookup is True:
        return "reverse"
    if is_reverse_lookup is False:
        # Trust the Windows-side classification.
        return "forward"
    n = name.lower().rstrip(".")
    if n.endswith(".in-addr.arpa") or n == "in-addr.arpa":
        return "reverse"
    if n.endswith(".ip6.arpa") or n == "ip6.arpa":
        return "reverse"
    return "forward"


def _zone_type_from_windows(value: str | None) -> str:
    """Map Windows DNS zone-type strings to our internal vocabulary.

    Windows: ``Primary``, ``Secondary``, ``Stub``, ``Forwarder``.
    Internal: ``primary``, ``secondary``, ``stub``, ``forward``.
    """

    if not value:
        return "primary"
    v = value.lower().strip()
    if v == "forwarder":
        return "forward"
    if v in {"primary", "secondary", "stub", "forward"}:
        return v
    return "primary"


def _normalize_fqdn(name: str) -> str:
    return name if name.endswith(".") else name + "."


async def parse_windows_dns_server(server: Any) -> ImportPreview:
    """Live-pull every zone + its records from a Windows DNS server.

    ``server`` is a :class:`app.models.dns.DNSServer` row; its
    ``credentials_encrypted`` blob carries the WinRM creds and
    ``host`` carries the server FQDN. The caller (the API
    endpoint) validates ``server.driver == "windows_dns"`` + creds
    presence before delegating here, so we don't re-check.

    Per-zone failures (RPC timeout, "zone not found" race) become
    ``parse_warnings`` on the affected ``ImportedZone`` rather than
    aborting the whole pull — operators with 50+ zones don't want a
    flake on zone 12 to kill the whole import.
    """

    driver = WindowsDNSDriver()

    try:
        zone_meta_list: list[dict[str, Any]] = await driver.pull_zones_from_server(server)
    except Exception as exc:  # noqa: BLE001 — operator-facing error capture
        raise WindowsDNSImportError(f"Could not list zones on Windows DNS server: {exc}") from exc

    zones: list[ImportedZone] = []
    overall_warnings: list[str] = []
    seen_system = False

    for meta in zone_meta_list:
        raw_name = str(meta.get("name") or "").strip()
        if not raw_name:
            continue
        fqdn = _normalize_fqdn(raw_name).lower()
        zone_type = _zone_type_from_windows(meta.get("zone_type"))
        kind = _classify_zone(raw_name, meta.get("is_reverse_lookup"))
        is_system = _looks_like_system_zone(raw_name)
        if is_system:
            seen_system = True

        # SOA defaults — Windows owns the SOA on the server side and
        # the PowerShell record walker drops it. SpatiumDDI's apply
        # pipeline rewrites SOA from zone-level columns at push
        # time, so the defaults aren't load-bearing — but the
        # operator should still see them flagged.
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
        if is_system:
            per_zone_warnings.append(
                f"{raw_name!r} looks like a Windows-internal zone — pick 'skip' "
                "on the conflict picker if you don't want it in IPAM"
            )

        # Per-zone record pull. Failures here are non-fatal — we
        # surface them as warnings on the zone and move on.
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
                view_name=None,  # Windows DNS has no view concept
                forwarders=[],
                skipped_record_types={},
                parse_warnings=per_zone_warnings,
            )
        )

    if seen_system:
        overall_warnings.append(
            "Source includes Windows-internal zones (TrustAnchors / RootDNSServers / "
            "_msdcs / DomainDnsZones / ForestDnsZones). Most shops skip these on "
            "import — set the per-zone action to 'skip' before commit."
        )

    if not zones:
        overall_warnings.append(
            "No zones reported by Get-DnsServerZone. Check that the WinRM "
            "service account has DnsAdmins read rights on the target server."
        )

    total_records = sum(len(z.records) for z in zones)
    histogram: dict[str, int] = {}
    for z in zones:
        for r in z.records:
            histogram[r.record_type] = histogram.get(r.record_type, 0) + 1

    return ImportPreview(
        source="windows_dns",
        zones=zones,
        conflicts=[],  # filled by the API endpoint via detect_conflicts
        warnings=overall_warnings,
        total_records=total_records,
        record_type_histogram=histogram,
        source_server_id=getattr(server, "id", None),
    )
