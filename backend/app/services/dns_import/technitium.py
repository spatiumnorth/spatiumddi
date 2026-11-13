"""Technitium DNS Server live-pull importer (issue #744).

Walks the REST API of a Technitium server the operator is migrating
*from* and emits the canonical :class:`ImportPreview` shape, same as the
BIND9 / Windows DNS / PowerDNS importers — the shared commit pipeline
writes the rows.

Two calls per pull:

* ``GET /api/zones/list`` → every zone::

      {"status": "ok", "response": {"zones": [
        {"name": "example.com", "type": "Primary", "disabled": false,
         "isExpired": false, "catalog": null}, ...]}}

* ``GET /api/zones/records/get?domain=<z>&zone=<z>&listZone=true`` →
  its records, each carrying a **structured** ``rData`` object rather
  than a wire-format string.

That last point is the whole difference from the PowerDNS importer.
PowerDNS hands back ``content`` strings that parse straight into a
record value; Technitium hands back per-type fields whose names do NOT
match the ones its own *write* API takes, and which translate numeric
rdata into enum names (``tlsaSelector=1`` reads back as
``selector="SPKI"``). ``rdata_to_value`` is the inverse: it rebuilds
the presentation-format string SpatiumDDI stores.

That translation lives in :mod:`app.services.technitium.rdata` (issue
#810) rather than here, because the agentless ``technitium_api`` driver
needs the identical mapping — plus its inverse for writes. This module
imports it under the old private names so the rest of the file reads
unchanged. The agent driver keeps a third copy it cannot share, being a
separate package; see that module's docstring.

Auth: a bearer token, passed as a ``token`` query param (Technitium's
own convention — it accepts ``Authorization: Bearer`` too, but the
token param is what its docs and console use). The operator pastes the
API URL and a token into the import form; neither is persisted.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.core.exc_text import describe_exc
from app.drivers.dns._cloud_base import CloudDNSError
from app.drivers.dns.technitium_api import TechnitiumAPIDriver
from app.services.technitium.rdata import (
    DNSSEC_RECORD_TYPES as _DNSSEC_RECORDS,
)
from app.services.technitium.rdata import (
    SUPPORTED_RECORD_TYPES as _SUPPORTED_RECORD_TYPES,
)
from app.services.technitium.rdata import (
    classify_zone as _classify_zone,
)
from app.services.technitium.rdata import (
    int_or as _int_or,
)
from app.services.technitium.rdata import (
    normalize_fqdn as _normalize_fqdn,
)
from app.services.technitium.rdata import (
    rdata_to_value as _rdata_to_value,
)
from app.services.technitium.rdata import (
    rel_name as _rel_name,
)

from .canonical import (
    ImportedRecord,
    ImportedSOA,
    ImportedZone,
    ImportPreview,
)


class TechnitiumImportError(ValueError):
    """Raised when the Technitium API can't be reached / parsed.

    Per-zone parse errors don't raise — they land in
    ``ImportedZone.parse_warnings`` so partial success stays visible.
    """


_DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0)

_MAX_ZONES_PER_PULL = 5000

# Page size asked of ``zones/list``; pages are followed via ``totalPages``.
_ZONES_PER_PAGE = 1000

# Only these zone types can be imported as authoritative data. A Secondary
# holds a copy of someone else's zone and a Forwarder holds no records at
# all, so importing either would mint rows SpatiumDDI would then try to
# serve as its own.
_IMPORTABLE_ZONE_TYPES = {"Primary"}


def _rname_to_soa_form(raw: str) -> str:
    """Technitium's ``responsiblePerson`` (``hostmaster@example.com``, the
    email form) as the domain-name form SpatiumDDI stores.

    The local part's dots are escaped (``a.b@x.com`` is ``a\\.b.x.com``) and
    the ``@`` becomes the first dot. A value already in domain form (no
    ``@``) passes through. The result is stored via
    :func:`importable_admin_email`, which refuses what BIND cannot serve.
    """
    value = raw.strip().rstrip(".")
    if "@" not in value:
        return _normalize_fqdn(value) if value else ""
    local, _, domain = value.rpartition("@")
    if not local or not domain:
        return ""
    return _normalize_fqdn(f"{local.replace('.', chr(92) + '.')}.{domain}")


def _soa_from_rdata(rdata: dict[str, Any], ttl: int) -> ImportedSOA:
    return ImportedSOA(
        primary_ns=_normalize_fqdn(str(rdata.get("primaryNameServer") or "")),
        admin_email=_rname_to_soa_form(str(rdata.get("responsiblePerson") or "")),
        serial=_int_or(rdata.get("serial"), 0),
        refresh=_int_or(rdata.get("refresh"), 86400),
        retry=_int_or(rdata.get("retry"), 7200),
        expire=_int_or(rdata.get("expire"), 3600000),
        minimum=_int_or(rdata.get("minimum"), 3600),
        ttl=ttl,
    )


def _build_imported_zone(zone_name: str, records_payload: list[dict[str, Any]]) -> ImportedZone:
    fqdn = _normalize_fqdn(zone_name)
    soa: ImportedSOA | None = None
    records: list[ImportedRecord] = []
    skipped: dict[str, int] = {}
    warnings: list[str] = []

    for rec in records_payload:
        rtype = str(rec.get("type") or "").upper()
        rdata = rec.get("rData") or {}
        ttl = _int_or(rec.get("ttl"), 3600)

        if rtype == "SOA":
            soa = _soa_from_rdata(rdata, ttl)
            continue
        if rtype in _DNSSEC_RECORDS or rtype not in _SUPPORTED_RECORD_TYPES:
            skipped[rtype] = skipped.get(rtype, 0) + 1
            continue
        # Technitium marks a disabled record rather than omitting it.
        if rec.get("disabled"):
            skipped[rtype] = skipped.get(rtype, 0) + 1
            continue

        try:
            value, extra = _rdata_to_value(rtype, rdata)
        except (TypeError, ValueError) as exc:
            warnings.append(f"Unparseable {rtype} at {rec.get('name')!r}: {exc}")
            continue
        if not value:
            warnings.append(f"Empty {rtype} value at {rec.get('name')!r} — skipped")
            continue

        records.append(
            ImportedRecord(
                name=_rel_name(str(rec.get("name") or ""), fqdn),
                record_type=rtype,
                value=value,
                ttl=ttl,
                priority=extra.get("priority"),
                weight=extra.get("weight"),
                port=extra.get("port"),
            )
        )

    dnssec_skipped = {k: v for k, v in skipped.items() if k in _DNSSEC_RECORDS}
    if dnssec_skipped:
        warnings.append(
            "Skipped DNSSEC records ("
            + ", ".join(f"{k}×{v}" for k, v in sorted(dnssec_skipped.items()))
            + ") — re-sign the zone after import rather than carrying "
            "signatures across."
        )
    other_skipped = {k: v for k, v in skipped.items() if k not in _DNSSEC_RECORDS}
    if other_skipped:
        warnings.append(
            "Skipped unsupported or disabled records ("
            + ", ".join(f"{k}×{v}" for k, v in sorted(other_skipped.items()))
            + ")."
        )

    return ImportedZone(
        name=fqdn,
        zone_type="primary",
        kind=_classify_zone(fqdn),
        soa=soa,
        records=records,
        parse_warnings=warnings,
    )


def _api_url(base: str, path: str) -> str:
    """``<root>/api/<path>``, with the root normalised exactly as the
    ``technitium_api`` driver does (``…/api`` and a trailing slash are
    accepted; a scheme-less URL is refused rather than guessed)."""
    try:
        root = TechnitiumAPIDriver.normalize_api_url(base)
    except CloudDNSError as exc:
        raise TechnitiumImportError(str(exc)) from exc
    return f"{root}/api/{path}"


def _unwrap(payload: dict[str, Any], what: str) -> dict[str, Any]:
    """Technitium answers HTTP 200 even on failure — the real status is
    in the body. Same trap the agent driver documents for its own calls."""
    status = payload.get("status")
    if status != "ok":
        raise TechnitiumImportError(
            f"Technitium rejected the {what} request "
            f"(status={status!r}): {payload.get('errorMessage') or 'no detail'}"
        )
    return payload.get("response") or {}


async def _list_zone_summaries(
    client: httpx.AsyncClient, api_url: str, api_token: str
) -> list[dict[str, Any]]:
    """Every zone summary, following ``totalPages`` (Technitium paginates
    ``zones/list`` and honours ``pageNumber`` / ``zonesPerPage``).

    Stops at the per-pull cap rather than walking an unbounded estate.
    """
    out: list[dict[str, Any]] = []
    page = 1
    while True:
        try:
            resp = await client.get(
                _api_url(api_url, "zones/list"),
                params={
                    "token": api_token,
                    "pageNumber": page,
                    "zonesPerPage": _ZONES_PER_PAGE,
                },
            )
        except httpx.HTTPError as exc:
            raise TechnitiumImportError(
                f"Could not reach the Technitium API at {api_url!r}: {describe_exc(exc)}"
            ) from exc
        if resp.status_code >= 400:
            raise TechnitiumImportError(
                f"Technitium API returned HTTP {resp.status_code}: {resp.text[:200]!r}"
            )
        try:
            body = resp.json()
        except ValueError as exc:
            raise TechnitiumImportError(f"Technitium API returned invalid JSON: {exc}") from exc
        # An expired or wrong token comes back as HTTP 200 with
        # status="invalid-token", so this is the only place it surfaces.
        listing = _unwrap(body, "zone list")
        out.extend(z for z in listing.get("zones") or [] if isinstance(z, dict))
        total_pages = listing.get("totalPages")
        if len(out) > _MAX_ZONES_PER_PULL or not isinstance(total_pages, int):
            return out
        if page >= total_pages:
            return out
        page += 1


async def parse_technitium_server(
    *,
    api_url: str,
    api_token: str,
    verify_tls: bool = True,
    timeout: httpx.Timeout = _DEFAULT_TIMEOUT,
) -> ImportPreview:
    """Live-pull every primary zone + its records from a Technitium server.

    ``api_url`` is the console base (``http://tdns.internal:5380``); the
    ``/api`` suffix is appended here so the operator-facing form stays
    simple.

    Only ``Primary`` zones are imported. Secondary / Stub / Forwarder /
    Catalog zones are reported as warnings instead — a secondary is a
    copy of someone else's data, and importing it would mint rows
    SpatiumDDI then tries to serve authoritatively.

    Per-zone failures become ``parse_warnings`` on that zone rather than
    aborting the pull, matching the other importers' partial-success
    semantics.
    """
    zones: list[ImportedZone] = []
    warnings: list[str] = []

    async with httpx.AsyncClient(
        timeout=timeout, verify=verify_tls, follow_redirects=False
    ) as client:
        summaries = await _list_zone_summaries(client, api_url, api_token)
        if len(summaries) > _MAX_ZONES_PER_PULL:
            raise TechnitiumImportError(
                f"Source has {len(summaries)} zones — over the "
                f"{_MAX_ZONES_PER_PULL}-zone per-pull cap. Split the import "
                "across multiple runs."
            )

        for summary in summaries:
            name = str(summary.get("name") or "")
            ztype = str(summary.get("type") or "")
            if not name:
                continue
            # Technitium's own stubs (localhost, 0./127./255.in-addr.arpa, the
            # ip6 loopback) are ``internal: true``; nobody created them, and
            # the technitium_api driver drops them too.
            if summary.get("internal"):
                continue
            if ztype not in _IMPORTABLE_ZONE_TYPES:
                warnings.append(
                    f"Skipped {name!r}: {ztype} zones aren't imported — only a "
                    "Primary holds authoritative data of its own."
                )
                continue
            # A disabled zone is one the operator turned OFF on the source
            # server. Importing it would bring it back live here — the same
            # outcome the per-record disabled guard prevents, one level up.
            if summary.get("disabled"):
                warnings.append(
                    f"Skipped {name!r}: disabled on the source server. Re-enable "
                    "it there first if it should be imported."
                )
                continue

            try:
                rec_resp = await client.get(
                    _api_url(api_url, "zones/records/get"),
                    params={
                        "token": api_token,
                        "domain": name,
                        "zone": name,
                        "listZone": "true",
                    },
                )
                rec_body = _unwrap(rec_resp.json(), f"records for {name!r}")
            except (httpx.HTTPError, ValueError, TechnitiumImportError) as exc:
                zones.append(
                    ImportedZone(
                        name=_normalize_fqdn(name),
                        zone_type="primary",
                        kind=_classify_zone(name),
                        soa=None,
                        records=[],
                        parse_warnings=[f"Could not pull records: {describe_exc(exc)}"],
                    )
                )
                continue

            zones.append(_build_imported_zone(name, rec_body.get("records") or []))

    total_records = sum(len(z.records) for z in zones)
    histogram: dict[str, int] = {}
    for zone in zones:
        for rec in zone.records:
            histogram[rec.record_type] = histogram.get(rec.record_type, 0) + 1

    return ImportPreview(
        source="technitium",
        zones=zones,
        conflicts=[],
        warnings=warnings,
        total_records=total_records,
        record_type_histogram=histogram,
    )


async def test_technitium_connection(
    *,
    api_url: str,
    api_token: str,
    verify_tls: bool = True,
    timeout: httpx.Timeout = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Cheap reachability + auth probe for the import form."""
    async with httpx.AsyncClient(
        timeout=timeout, verify=verify_tls, follow_redirects=False
    ) as client:
        summaries = await _list_zone_summaries(client, api_url, api_token)
    summaries = [z for z in summaries if not z.get("internal")]
    importable = [z for z in summaries if str(z.get("type")) in _IMPORTABLE_ZONE_TYPES]
    return {
        "ok": True,
        "zone_count": len(summaries),
        "importable_zone_count": len(importable),
    }
