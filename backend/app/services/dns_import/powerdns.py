"""PowerDNS Authoritative REST live-pull importer (issue #128 Phase 3).

Walks the PowerDNS REST API on a non-managed PowerDNS server (the
operator is migrating *from* it) and emits the canonical
:class:`ImportPreview` shape. Same output schema as the BIND9 +
Windows DNS importers — the shared commit pipeline writes the rows.

PowerDNS REST API (v1) shape:

* ``GET /api/v1/servers/{server}/zones`` → list of zone summaries::

      [{"id": "example.com.", "name": "example.com.", "kind": "Native",
        "serial": 2026050901, "url": "/api/v1/...", ...}, ...]

* ``GET /api/v1/servers/{server}/zones/{zone_id}`` → full zone with
  rrsets::

      {"id": "example.com.", "name": "example.com.", "kind": "Native",
       "serial": 2026050901,
       "rrsets": [
         {"name": "example.com.", "type": "SOA", "ttl": 3600,
          "records": [{"content": "ns1.ex.com. admin.ex.com. 1 3600 1800 1209600 3600",
                       "disabled": false}],
          "comments": []},
         {"name": "www.example.com.", "type": "A", "ttl": 3600,
          "records": [{"content": "192.0.2.10", "disabled": false}], ...},
         ...
       ]}

Auth: ``X-API-Key: <key>`` header. The operator pastes both the API
URL (``http://pdns.internal:8081``) and the key into the import
form; we never persist either — they're read-once and discarded
after the pull. PowerDNS supports per-server API keys, so the key
need only have read access on the source server.
"""

from __future__ import annotations

from typing import Any

import httpx

from .canonical import (
    ImportedRecord,
    ImportedSOA,
    ImportedZone,
    ImportPreview,
)


class PowerDNSImportError(ValueError):
    """Raised when the PowerDNS REST API can't be reached / parsed.

    Per-zone parse errors don't raise this — they land in
    ``ImportedZone.parse_warnings`` so partial-success is visible.
    """


# Reasonable timeouts for a control-plane → operator-supplied
# PowerDNS pull. Connect should be quick (we're either on the LAN
# or going over a fast WAN); per-zone read can take a few seconds
# on a giant zone, so the read timeout is generous.
_DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0)

# Hard cap on zones-per-pull. PowerDNS deployments with 10k+ zones
# do exist; we don't want one to OOM the control plane. Operators
# with that many zones can split across multiple imports (the
# importer is a one-shot migration tool, not an ongoing mirror).
_MAX_ZONES_PER_PULL = 5000

# Record types the importer can model. PowerDNS-specific rdtypes
# (LUA, ALIAS) and DNSSEC-side records get dropped on the way in
# with a per-zone warning. Same set the BIND9 importer uses, plus
# we explicitly recognise SOA so we can hoist its content into the
# ImportedSOA shape.
_SUPPORTED_RECORD_TYPES = {
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "TXT",
    "NS",
    "PTR",
    "SRV",
    "CAA",
    "TLSA",
    "SSHFP",
    "NAPTR",
    "LOC",
}

_DNSSEC_RECORDS = {"DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DS", "CDS", "CDNSKEY"}


def _normalize_fqdn(name: str) -> str:
    return name if name.endswith(".") else name + "."


def _classify_zone(name: str) -> str:
    """``forward`` or ``reverse`` based on the in-addr.arpa /
    ip6.arpa suffix — same convention the other two importers use."""
    n = name.lower().rstrip(".")
    if n.endswith(".in-addr.arpa") or n == "in-addr.arpa":
        return "reverse"
    if n.endswith(".ip6.arpa") or n == "ip6.arpa":
        return "reverse"
    return "forward"


def _zone_type_from_powerdns(kind: str | None) -> str:
    """Map PowerDNS ``kind`` to our internal vocabulary.

    PowerDNS values: ``Native``, ``Master``, ``Slave``, ``Producer``,
    ``Consumer`` (catalog zones, 4.7+), ``Forward``.

    * ``Native`` / ``Master`` → ``primary`` (Native is "no replication";
      both behave like an authoritative primary from our perspective).
    * ``Slave`` → ``secondary``.
    * ``Producer`` / ``Consumer`` → ``primary`` for Phase 1; the
      catalog-zone semantics get layered on in Phase 4.
    * ``Forward`` → ``forward``.
    """

    if not kind:
        return "primary"
    k = kind.lower().strip()
    if k in {"master", "native", "producer", "consumer"}:
        return "primary"
    if k == "slave":
        return "secondary"
    if k == "forward":
        return "forward"
    return "primary"


def _parse_soa_content(text: str, ttl: int) -> ImportedSOA | None:
    """PowerDNS encodes SOA as one space-separated string in the
    rrset's ``content`` field: ``primary admin serial refresh retry
    expire minimum``. Returns None on malformed input rather than
    raising — the caller surfaces a warning."""

    parts = text.split()
    if len(parts) < 7:
        return None
    try:
        return ImportedSOA(
            primary_ns=parts[0],
            admin_email=parts[1],
            serial=int(parts[2]),
            refresh=int(parts[3]),
            retry=int(parts[4]),
            expire=int(parts[5]),
            minimum=int(parts[6]),
            ttl=ttl,
        )
    except (ValueError, IndexError):
        return None


def _split_priority(rtype: str, content: str) -> tuple[str, int | None, int | None, int | None]:
    """Pull priority / weight / port out of MX / SRV content. Same
    convention as :func:`app.services.dns_io.parser._format_rdata` —
    the priority columns on DNSRecord get the integer values; the
    ``value`` column gets just the target name."""

    priority: int | None = None
    weight: int | None = None
    port: int | None = None
    if rtype == "MX":
        # PowerDNS content for MX: ``<pref> <exchange>``
        parts = content.split(maxsplit=1)
        if len(parts) == 2:
            try:
                priority = int(parts[0])
                content = parts[1]
            except ValueError:
                # Malformed preference field — tolerate it: leave
                # ``priority`` as None and pass ``content`` through
                # unchanged so the operator still sees the original
                # rdata in the import preview rather than losing the
                # row entirely.
                pass
    elif rtype == "SRV":
        # ``<priority> <weight> <port> <target>``
        parts = content.split(maxsplit=3)
        if len(parts) == 4:
            try:
                priority = int(parts[0])
                weight = int(parts[1])
                port = int(parts[2])
                content = parts[3]
            except ValueError:
                # Same tolerance as the MX branch above: any
                # non-numeric field leaves all three priority
                # columns at None and preserves the original
                # ``content`` for operator review.
                pass
    return content, priority, weight, port


def _rel_name(rrset_name: str, zone_fqdn: str) -> str:
    """``rrset_name`` is FQDN with trailing dot. Return the relative
    label (``@`` for apex)."""
    rn = rrset_name.rstrip(".").lower()
    zn = zone_fqdn.rstrip(".").lower()
    if rn == zn:
        return "@"
    if rn.endswith("." + zn):
        return rn[: -(len(zn) + 1)]
    # Mismatch — surface the FQDN as-is. ``parse_zone_file`` upstream
    # tolerates this and the operator sees the literal name in the
    # preview table.
    return rrset_name


def _build_imported_zone(
    summary: dict[str, Any],
    full: dict[str, Any],
) -> ImportedZone:
    """Translate one PowerDNS zone (summary + full record set) into
    the canonical :class:`ImportedZone`. Per-rrset oddities (LUA
    records, disabled records, malformed SOA) become
    ``parse_warnings`` on the returned zone."""

    raw_name = str(full.get("name") or summary.get("name") or "").strip()
    fqdn = _normalize_fqdn(raw_name).lower()
    zone_type = _zone_type_from_powerdns(full.get("kind") or summary.get("kind"))
    kind = _classify_zone(raw_name)

    soa: ImportedSOA | None = None
    records: list[ImportedRecord] = []
    skipped: dict[str, int] = {}
    warnings: list[str] = []
    disabled_count = 0

    for rrset in full.get("rrsets") or []:
        rtype = str(rrset.get("type") or "").upper()
        rname = str(rrset.get("name") or "")
        raw_ttl = rrset.get("ttl")
        ttl = int(raw_ttl) if raw_ttl is not None else 3600
        rec_list = rrset.get("records") or []

        if rtype == "SOA":
            # SOA always has exactly one record. Hoist into ImportedSOA;
            # don't add to the records list (matches BIND9 path).
            if rec_list:
                content = str(rec_list[0].get("content") or "")
                parsed_soa = _parse_soa_content(content, ttl)
                if parsed_soa is None:
                    warnings.append(f"Malformed SOA for {fqdn!r}: {content!r}")
                else:
                    soa = parsed_soa
            continue

        if rtype in _DNSSEC_RECORDS:
            skipped[rtype] = skipped.get(rtype, 0) + len(rec_list)
            continue

        if rtype not in _SUPPORTED_RECORD_TYPES:
            skipped[rtype] = skipped.get(rtype, 0) + len(rec_list)
            continue

        rel = _rel_name(rname, fqdn)
        for rec in rec_list:
            if rec.get("disabled"):
                disabled_count += 1
                continue
            content = str(rec.get("content") or "").strip()
            if not content:
                continue
            value, priority, weight, port = _split_priority(rtype, content)
            records.append(
                ImportedRecord(
                    name=rel,
                    record_type=rtype,
                    value=value,
                    ttl=ttl,
                    priority=priority,
                    weight=weight,
                    port=port,
                )
            )

    if disabled_count:
        warnings.append(
            f"Skipped {disabled_count} disabled record(s) — PowerDNS marks them "
            "as ``disabled: true`` and we treat that as an explicit "
            "operator-managed soft-delete"
        )

    dnssec_skipped = {k: v for k, v in skipped.items() if k in _DNSSEC_RECORDS}
    if dnssec_skipped:
        total = sum(dnssec_skipped.values())
        warnings.append(
            f"Stripped {total} DNSSEC record(s) "
            f"({', '.join(f'{k}={v}' for k, v in sorted(dnssec_skipped.items()))}) "
            "— re-sign post-import via the zone DNSSEC tab"
        )
    other_skipped = {k: v for k, v in skipped.items() if k not in _DNSSEC_RECORDS}
    if other_skipped:
        warnings.append(
            f"Dropped {sum(other_skipped.values())} unsupported record(s) "
            f"({', '.join(f'{k}={v}' for k, v in sorted(other_skipped.items()))}) "
            "— PowerDNS-specific rdtypes (LUA, ALIAS, ...) don't carry over"
        )
    if soa is None and zone_type in {"primary", "secondary"}:
        warnings.append(
            "Source did not return SOA in rrsets — zone created with "
            "default SOA values; edit via the zone editor post-import"
        )

    return ImportedZone(
        name=fqdn,
        zone_type=zone_type,
        kind=kind,
        soa=soa,
        records=records,
        view_name=None,  # PowerDNS doesn't expose the view tag in v1 REST
        forwarders=[],
        skipped_record_types=skipped,
        parse_warnings=warnings,
    )


async def parse_powerdns_server(
    *,
    api_url: str,
    api_key: str,
    server_name: str = "localhost",
    timeout: httpx.Timeout = _DEFAULT_TIMEOUT,
) -> ImportPreview:
    """Live-pull every zone + its records from a PowerDNS REST API.

    ``api_url`` should NOT include the ``/api/v1`` suffix —
    typical inputs are ``http://pdns.internal:8081``. We append
    ``/api/v1/servers/{server_name}/zones`` ourselves so the
    operator-facing form stays simple.

    ``server_name`` defaults to ``localhost`` (PowerDNS's
    convention for the server-id of the running daemon). Set to a
    different value if the upstream is fronted by a multi-server
    API (rare in practice).

    Failures during the per-zone pull become ``parse_warnings`` on
    the affected zone — same partial-success semantics as the
    other two importers.
    """

    base = api_url.rstrip("/")
    if base.endswith("/api/v1"):
        base = base[: -len("/api/v1")]
    headers = {
        "X-API-Key": api_key,
        "Accept": "application/json",
    }
    zones_url = f"{base}/api/v1/servers/{server_name}/zones"

    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        try:
            resp = await client.get(zones_url)
        except httpx.HTTPError as exc:
            raise PowerDNSImportError(
                f"Could not reach PowerDNS API at {zones_url!r}: {exc}"
            ) from exc
        if resp.status_code == 401:
            raise PowerDNSImportError(
                "PowerDNS rejected the API key (HTTP 401). "
                "Check that the key has read access on the server."
            )
        if resp.status_code == 404:
            raise PowerDNSImportError(
                f"Server {server_name!r} not found on the PowerDNS API "
                f"(HTTP 404). Common alternative is 'localhost'."
            )
        if resp.status_code >= 400:
            raise PowerDNSImportError(
                f"PowerDNS API returned HTTP {resp.status_code}: " f"{resp.text[:200]!r}"
            )
        try:
            zones_summary: list[dict[str, Any]] = resp.json()
        except ValueError as exc:
            raise PowerDNSImportError(f"PowerDNS API returned invalid JSON: {exc}") from exc

        if not isinstance(zones_summary, list):
            raise PowerDNSImportError(
                "PowerDNS API returned a non-list zones payload — "
                "this server doesn't speak the v1 REST API."
            )

        if len(zones_summary) > _MAX_ZONES_PER_PULL:
            raise PowerDNSImportError(
                f"Source has {len(zones_summary)} zones — over the "
                f"{_MAX_ZONES_PER_PULL}-zone per-pull cap. Split the "
                f"import across multiple runs."
            )

        zones: list[ImportedZone] = []
        overall_warnings: list[str] = []

        # PowerDNS zones expose an ``id`` (URL-encoded zone name) and
        # a ``url`` (full path back to the zone resource). Prefer the
        # ``url`` field when present — it's the canonical way to
        # follow into the zone, including any URL escaping PowerDNS
        # applied to special characters in zone names.
        for summary in zones_summary:
            zone_name = str(summary.get("name") or summary.get("id") or "").strip()
            if not zone_name:
                continue
            zone_id = summary.get("id") or zone_name
            zone_url = summary.get("url")
            full_url = (
                f"{base}{zone_url}"
                if zone_url and zone_url.startswith("/")
                else f"{base}/api/v1/servers/{server_name}/zones/{zone_id}"
            )
            try:
                zresp = await client.get(full_url)
                zresp.raise_for_status()
                full = zresp.json()
            except (httpx.HTTPError, ValueError) as exc:
                # Surface as a placeholder zone with a warning so the
                # operator sees the gap; don't abort the whole pull.
                zones.append(
                    ImportedZone(
                        name=_normalize_fqdn(zone_name).lower(),
                        zone_type=_zone_type_from_powerdns(summary.get("kind")),
                        kind=_classify_zone(zone_name),
                        soa=None,
                        records=[],
                        view_name=None,
                        forwarders=[],
                        skipped_record_types={},
                        parse_warnings=[f"Failed to fetch full zone payload: {exc}"],
                    )
                )
                continue
            zones.append(_build_imported_zone(summary, full))

    if not zones:
        overall_warnings.append(
            "PowerDNS returned no zones. Check that the API key has "
            "read access and that the server is the right server-id."
        )

    total_records = sum(len(z.records) for z in zones)
    histogram: dict[str, int] = {}
    for z in zones:
        for r in z.records:
            histogram[r.record_type] = histogram.get(r.record_type, 0) + 1

    return ImportPreview(
        source="powerdns",
        zones=zones,
        conflicts=[],
        warnings=overall_warnings,
        total_records=total_records,
        record_type_histogram=histogram,
    )


async def test_powerdns_connection(
    *,
    api_url: str,
    api_key: str,
    server_name: str = "localhost",
) -> dict[str, Any]:
    """Quick read-only probe — fetches the server-info object and
    returns its identifying fields. The UI calls this from a "Test
    connection" button so the operator finds out about a bad URL /
    key / server-name *before* hitting "Preview" on a 5000-zone
    daemon.
    """

    base = api_url.rstrip("/")
    if base.endswith("/api/v1"):
        base = base[: -len("/api/v1")]
    headers = {"X-API-Key": api_key, "Accept": "application/json"}
    url = f"{base}/api/v1/servers/{server_name}"
    async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT, headers=headers) as client:
        try:
            resp = await client.get(url)
        except httpx.HTTPError as exc:
            raise PowerDNSImportError(f"Could not reach {url!r}: {exc}") from exc
        if resp.status_code == 401:
            raise PowerDNSImportError("PowerDNS rejected the API key (HTTP 401)")
        if resp.status_code == 404:
            raise PowerDNSImportError(
                f"Server {server_name!r} not found (HTTP 404). "
                f"PowerDNS's default server-id is 'localhost'."
            )
        if resp.status_code >= 400:
            raise PowerDNSImportError(
                f"PowerDNS returned HTTP {resp.status_code}: {resp.text[:200]!r}"
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise PowerDNSImportError(f"Invalid JSON from PowerDNS: {exc}") from exc

    return {
        "type": str(data.get("type") or ""),
        "id": str(data.get("id") or ""),
        "daemon_type": str(data.get("daemon_type") or ""),
        "version": str(data.get("version") or ""),
        "url": str(data.get("url") or ""),
    }
