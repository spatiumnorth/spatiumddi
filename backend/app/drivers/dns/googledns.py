"""Google Cloud DNS agentless cloud DNS driver (issue #37).

Cloud DNS is managed exactly like a local BIND9 / PowerDNS zone — same
Zones / Records / group surfaces — but the control plane drives the
``google-cloud-dns`` SDK directly instead of an agent. See
``drivers/dns/_cloud_base.py`` for the agentless contract; this module
only implements the five provider hooks plus the ``name`` /
``credential_fields`` class attrs.

Credential dict shape (decrypted from ``DNSServer.credentials_encrypted``)::

    {"service_account_json": "<service-account-key JSON string>",
     "project_id": "my-gcp-project"}

The ``service_account_json`` is the raw JSON key the operator downloads
from the GCP console (a string, not a dict) — we ``json.loads`` it and
hand it to ``Credentials.from_service_account_info``.

A few Cloud-DNS-specific wrinkles the hooks paper over:

* **Managed zone id vs. DNS name.** Cloud DNS scopes every call by the
  *managed-zone id* (``z.name`` — a slug like ``"example-com"``), not by
  the zone's DNS name (``z.dns_name`` — the FQDN ``"example.com."``).
  We surface the DNS name as ``CloudDNSZone.name`` and stash the slug in
  ``zone_id``; the record / zone hooks re-resolve the managed zone by
  matching ``dns_name`` when they only know the FQDN.
* **rrdatas is a list.** A single ``ResourceRecordSet`` carries one or
  more ``rrdatas`` strings (Cloud DNS groups same-name/same-type values
  into one rrset; the rest of SpatiumDDI keys records per value). We
  expand one ``RecordData`` per ``rrdata`` on read. On write, a per-value
  create / delete **read-merges** against the provider's live rrset so a
  single-value op never drops the sibling values that share the rrset
  (see ``_apply_record``); an update replaces the rrset with its single
  new value (per-row→RRset value-edit limitation, tracked in #29).
* **Changes are transactional + asynchronous.** A write builds a
  ``Changes`` object (additions + deletions), commits it with
  ``changes.create()``, and the change goes ``pending`` → ``done``. We
  poll ``changes.status`` with a bounded sleep loop so the op only
  returns once Cloud DNS has applied it.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import structlog

from app.drivers.dns._cloud_base import (
    CloudDNSDriverBase,
    CloudDNSError,
    CloudDNSZone,
    compose_structured_rdata,
    normalize_fqdn,
    split_structured_rdata,
)
from app.drivers.dns.base import RecordChange, RecordData

logger = structlog.get_logger(__name__)

# Bounded poll loop for a committed change set reaching ``done``. Cloud
# DNS changes usually settle in a few seconds; cap the wait so a stuck
# change surfaces as an error instead of blocking the op forever.
_CHANGE_POLL_INTERVAL_S = 1.0
_CHANGE_POLL_MAX_ATTEMPTS = 60


def _zone_slug(dns_name: str) -> str:
    """Derive a Cloud DNS managed-zone id from a zone DNS name.

    Cloud DNS managed-zone ids must start with a letter, contain only
    lower-case letters / digits / hyphens, and be ≤ 63 chars. We slugify
    the FQDN (``"example.com."`` → ``"example-com"``) for the create
    path; the operator can rename it in the GCP console afterwards.
    """
    base = normalize_fqdn(dns_name).rstrip(".")
    slug = re.sub(r"[^a-z0-9-]+", "-", base.lower()).strip("-")
    if not slug or not slug[0].isalpha():
        slug = "zone-" + slug
    return slug[:63].rstrip("-")


class GoogleCloudDNSDriver(CloudDNSDriverBase):
    """Agentless driver for Google Cloud DNS managed zones."""

    name: str = "google_dns"
    # Ordered credential fields the Add-DNS-server modal renders + the
    # probe validates as required.
    credential_fields: tuple[str, ...] = ("service_account_json", "project_id")

    # ── Client factory ──────────────────────────────────────────────────
    def _client(self, creds: dict[str, Any]) -> Any:
        """Build a ``google.cloud.dns.Client`` from the decrypted creds.

        The GCP SDKs are imported lazily so importing this module never
        fails on a host without ``google-cloud-dns`` installed, and so
        tests can monkeypatch this factory without the wheel present.
        """
        # Deferred import: keeps worker startup light + lets agent-only
        # hosts skip the google-cloud-dns wheel entirely.
        from google.cloud import dns  # noqa: PLC0415
        from google.oauth2 import service_account  # noqa: PLC0415

        sa_json = creds.get("service_account_json")
        project_id = creds.get("project_id")
        if not sa_json or not project_id:
            raise CloudDNSError(
                "google_dns credentials require both 'service_account_json' and 'project_id'."
            )
        try:
            info = json.loads(sa_json) if isinstance(sa_json, str) else sa_json
            credentials = service_account.Credentials.from_service_account_info(info)
        except (ValueError, TypeError) as exc:
            raise CloudDNSError(
                f"google_dns service_account_json is not valid JSON: {exc}"
            ) from exc
        return dns.Client(project=project_id, credentials=credentials)

    def _wrap_call(self, what: str, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Run a blocking SDK call in a thread, wrapping GCP errors.

        ``google.api_core.exceptions.GoogleAPICallError`` (API-side
        failures) and ``google.auth.exceptions.GoogleAuthError``
        (credential failures) are imported lazily and re-raised as
        :class:`CloudDNSError` so the record-ops + import + probe paths
        surface a clean operator-facing message instead of a raw SDK
        traceback.
        """
        # Imported lazily so the except clauses don't drag the SDK in at
        # module import time (mirrors ``_client``).
        from google.api_core import exceptions as gax_exceptions  # noqa: PLC0415
        from google.auth import exceptions as gauth_exceptions  # noqa: PLC0415

        try:
            return fn(*args, **kwargs)
        except (
            gax_exceptions.GoogleAPICallError,
            gauth_exceptions.GoogleAuthError,
        ) as exc:
            raise CloudDNSError(f"google_dns {what} failed: {exc}") from exc

    # ── Zone listing ────────────────────────────────────────────────────
    async def _list_zones(self, server: Any, creds: dict[str, Any]) -> list[CloudDNSZone]:
        client = self._client(creds)
        # ``client.list_zones()`` returns an iterator that lazily pages
        # under the hood — materialise it inside the thread so we don't
        # block the event loop on per-page network round trips.
        managed_zones = await asyncio.to_thread(
            self._wrap_call, "list_zones", lambda: list(client.list_zones())
        )
        zones: list[CloudDNSZone] = []
        for z in managed_zones:
            name = normalize_fqdn(z.dns_name)
            zones.append(
                CloudDNSZone(
                    name=name,
                    # ``z.name`` is the GCP managed-zone id (slug); calls
                    # scope by it, so keep it for the import provenance.
                    zone_id=z.name,
                    is_reverse=name.rstrip(".").endswith("arpa"),
                    dnssec_enabled=False,
                )
            )
        return zones

    # ── Record listing ──────────────────────────────────────────────────
    async def _list_zone_records(
        self, server: Any, creds: dict[str, Any], zone_name: str
    ) -> list[RecordData]:
        client = self._client(creds)
        apex = normalize_fqdn(zone_name)
        zone = await self._resolve_zone(client, apex)

        rrsets = await asyncio.to_thread(
            self._wrap_call,
            "list_resource_record_sets",
            lambda: list(zone.list_resource_record_sets()),
        )
        records: list[RecordData] = []
        for rrset in rrsets:
            rtype = str(rrset.record_type).upper()
            # Cloud DNS owns the apex SOA; skip it so the import +
            # drift machinery doesn't try to round-trip it.
            if rtype == "SOA":
                continue
            name = self._relativize(str(rrset.name), apex)
            ttl = rrset.ttl
            for rdata in rrset.rrdatas:
                # MX / SRV rdata arrives composed ("10 mail.example.com.")
                # — split it into the structured columns so the stored
                # shape matches the record API's split contract (#1526).
                bare, priority, weight, port = split_structured_rdata(rtype, str(rdata))
                records.append(
                    RecordData(
                        name=name,
                        record_type=rtype,
                        value=bare,
                        ttl=int(ttl) if ttl is not None else None,
                        priority=priority,
                        weight=weight,
                        port=port,
                    )
                )
        return records

    def _relativize(self, fqdn: str, apex: str) -> str:
        """Return ``fqdn`` relative to ``apex`` (``"@"`` for the apex itself).

        Both inputs are normalised to trailing-dot FQDNs first. A name
        outside the apex (shouldn't happen for a zone's own rrsets) is
        returned as its normalised FQDN unchanged.
        """
        f = normalize_fqdn(fqdn)
        a = normalize_fqdn(apex)
        if f == a:
            return "@"
        suffix = "." + a
        if f.endswith(suffix):
            return f[: -len(suffix)]
        return f

    def _absolutize(self, name: str, apex: str) -> str:
        """Render a relative record label into an absolute FQDN for the apex."""
        apex = normalize_fqdn(apex)
        if name in ("", "@"):
            return apex
        label = normalize_fqdn(name)
        # Already absolute under the apex (or some other suffix) — leave it.
        if label.endswith("." + apex) or label == apex:
            return label
        return normalize_fqdn(name.rstrip(".") + "." + apex.rstrip("."))

    # ── Record write ────────────────────────────────────────────────────
    async def _apply_record(self, server: Any, creds: dict[str, Any], change: RecordChange) -> None:
        if change.op not in {"create", "update", "delete"}:
            raise CloudDNSError(f"google_dns._apply_record: bad op {change.op!r}")

        client = self._client(creds)
        apex = normalize_fqdn(change.zone_name)
        zone = await self._resolve_zone(client, apex)

        rr = change.record
        rtype = rr.record_type.upper()
        absolute = self._absolutize(rr.name, apex)
        # The op's value in provider form — MX / SRV compose the structured
        # columns into the rdata string Cloud DNS stores (#1526). The live
        # rrset's rrdatas are already in that form.
        composed = compose_structured_rdata(rr)

        # Cloud DNS groups every same-{name,type} value under a single
        # rrset (round-robin A, multiple MX/NS/TXT, …) but SpatiumDDI
        # stores one DB row → one ``RecordChange`` per value. Writing a
        # one-value rrset on create / delete would silently DROP the
        # sibling values that share the rrset. So create + delete
        # read-merge against the provider's CURRENT rrset and write the
        # FULL merged/reduced value set in one transactional change.
        def _build_and_commit() -> Any:
            changes = zone.changes()

            if change.op == "create":
                existing = self._find_rrset(zone, absolute, rtype)
                merged, ttl = self._merge_create(existing, composed, rr.ttl)
                if existing is not None and self._rrdatas(existing) == merged:
                    # Value already present with an unchanged set — no-op.
                    return None
                if existing is not None:
                    # Cloud DNS has no in-place update; replace the whole
                    # rrset (delete old + add merged) in one atomic change.
                    changes.delete_record_set(existing)
                new_rrset = zone.resource_record_set(absolute, rtype, ttl, merged)
                changes.add_record_set(new_rrset)
                changes.create()
                return changes

            if change.op == "delete":
                existing = self._find_rrset(zone, absolute, rtype)
                if existing is None or composed not in self._rrdatas(existing):
                    # Value (or whole rrset) already gone — idempotent
                    # no-op. Skip the commit so we don't fire an empty
                    # change set (Cloud DNS rejects those).
                    return None
                reduced = [v for v in self._rrdatas(existing) if v != composed]
                changes.delete_record_set(existing)
                if reduced:
                    # Siblings remain — re-add the reduced rrset rather
                    # than dropping the whole set.
                    ttl = int(existing.ttl) if existing.ttl is not None else 300
                    changes.add_record_set(zone.resource_record_set(absolute, rtype, ttl, reduced))
                changes.create()
                return changes

            # ``update`` replaces the whole rrset — Cloud DNS has no in-place
            # edit. #783: with a resolved RRset the replacement is the
            # COMPLETE desired set, so editing one of two A records at a name
            # no longer retires the other. This was described as an inherent
            # per-row→RRset limitation; it was only inherent while the op
            # carried a single value.
            #
            # Without a resolved set (a caller that opted out via
            # ``rrset_action``) the single-value replace is kept — right for
            # the common single-value rrset (CNAME, a host with one A/TXT).
            if change.rrset is not None and change.rrset.members:
                values = [compose_structured_rdata(m) for m in change.rrset.as_records(rr)]
                ttl = int(change.rrset.ttl or (rr.ttl if rr.ttl else 0) or 300)
            else:
                values = [composed]
                ttl = int(rr.ttl) if rr.ttl else 300
            existing = self._find_rrset(zone, absolute, rtype)
            if existing is not None:
                changes.delete_record_set(existing)
            changes.add_record_set(zone.resource_record_set(absolute, rtype, ttl, values))
            changes.create()
            return changes

        committed = await asyncio.to_thread(
            self._wrap_call, "change_record_sets", _build_and_commit
        )
        if committed is None:
            # create-already-present or delete-missing — desired end state
            # already met, nothing to commit.
            logger.info(
                "google_dns.apply_record.noop",
                server=str(getattr(server, "id", "")),
                zone=change.zone_name,
                name=rr.name,
                rtype=rtype,
                op=change.op,
            )
            return
        await self._wait_for_change(committed)

    @staticmethod
    def _rrdatas(rrset: Any) -> list[str]:
        """Return an rrset's values as a list of strings (empty if none)."""
        return [str(v) for v in (getattr(rrset, "rrdatas", None) or [])]

    def _merge_create(
        self, existing: Any | None, value: str, change_ttl: int | None
    ) -> tuple[list[str], int]:
        """Compute the merged value set + ttl for a create.

        New values = existing values ∪ {``value``}, order-preserving + de-
        duped (an already-present value yields an unchanged set, which the
        caller treats as a no-op). TTL is the change's ttl, falling back to
        the existing rrset's ttl, then the 300 s default.
        """
        merged: list[str] = list(self._rrdatas(existing)) if existing is not None else []
        if value not in merged:
            merged.append(value)
        if change_ttl:
            ttl = int(change_ttl)
        elif existing is not None and existing.ttl is not None:
            ttl = int(existing.ttl)
        else:
            ttl = 300
        return merged, ttl

    def _find_rrset(self, zone: Any, absolute_name: str, rtype: str) -> Any | None:
        """Fetch the existing rrset matching ``absolute_name`` + ``rtype``.

        Cloud DNS deletes must reference the *exact* current rrset (same
        ttl + rrdatas), so we read the zone's record sets and return the
        matching ``ResourceRecordSet`` object. Returns ``None`` when no
        such rrset exists (the delete becomes a no-op).
        """
        target = normalize_fqdn(absolute_name)
        for rrset in zone.list_resource_record_sets():
            if (
                normalize_fqdn(str(rrset.name)) == target
                and str(rrset.record_type).upper() == rtype
            ):
                return rrset
        return None

    async def _wait_for_change(self, changes: Any) -> None:
        """Poll a committed ``Changes`` object until it reaches ``done``.

        Bounded loop — Cloud DNS settles a change in a few seconds; a
        change still ``pending`` after the cap surfaces as an error so a
        stuck op doesn't block the caller forever.
        """
        for _ in range(_CHANGE_POLL_MAX_ATTEMPTS):
            status = getattr(changes, "status", None)
            if status == "done":
                return
            await asyncio.sleep(_CHANGE_POLL_INTERVAL_S)
            await asyncio.to_thread(self._wrap_call, "changes.reload", changes.reload)
        raise CloudDNSError(
            f"google_dns change did not reach 'done' within "
            f"{_CHANGE_POLL_MAX_ATTEMPTS}s (last status: {getattr(changes, 'status', None)!r})"
        )

    # ── Zone write ──────────────────────────────────────────────────────
    async def _apply_zone(self, server: Any, creds: dict[str, Any], zone: Any, op: str) -> None:
        client = self._client(creds)
        name = normalize_fqdn(getattr(zone, "name", "") or "")
        if name == ".":
            raise CloudDNSError("google_dns._apply_zone: zone name is required")

        if op == "create":
            slug = _zone_slug(name)
            managed = await asyncio.to_thread(
                self._wrap_call,
                "zone",
                client.zone,
                slug,
                dns_name=name,
            )
            await asyncio.to_thread(self._wrap_call, "create_zone", managed.create)
            return

        if op == "delete":
            managed = await self._resolve_zone(client, name)
            await asyncio.to_thread(self._wrap_call, "delete_zone", managed.delete)
            return

        raise CloudDNSError(f"google_dns._apply_zone: unsupported op {op!r}")

    # ── Managed-zone resolution ─────────────────────────────────────────
    async def _resolve_zone(self, client: Any, zone_name: str) -> Any:
        """Resolve a Cloud DNS managed-zone object from a zone FQDN.

        Cloud DNS scopes record / delete calls by the managed-zone id
        (``z.name`` slug), not by DNS name, so iterate ``list_zones()``
        and match on ``dns_name``.
        """
        apex = normalize_fqdn(zone_name)
        managed_zones = await asyncio.to_thread(
            self._wrap_call, "list_zones", lambda: list(client.list_zones())
        )
        for z in managed_zones:
            if normalize_fqdn(z.dns_name) == apex:
                return z
        raise CloudDNSError(f"google_dns: managed zone {zone_name!r} not found")

    # ── Capabilities ────────────────────────────────────────────────────
    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "google_dns",
            "agentless": True,
            "manages_zones": True,
            "views": False,
            "rpz": False,
            # #29 — Google Cloud DNS DNSSEC is a managed-zone toggle, not the
            # per-record online signing these ops model; deferred.
            "dnssec_online": False,
            "record_types": [
                "A",
                "AAAA",
                "CNAME",
                "MX",
                "TXT",
                "NS",
                "SRV",
                "CAA",
                "PTR",
                "SOA",
            ],
            "notes": (
                "Agentless Google Cloud DNS driver. Zone + record CRUD via "
                "the google-cloud-dns SDK from the control plane (no agent). "
                "Calls scope by the managed-zone id (slug) resolved from the "
                "zone DNS name; writes go through transactional change sets "
                "and the op blocks until the change reaches 'done'. MX/SRV "
                "structured fields are composed into the provider rdata on "
                "write and split back out on read."
            ),
        }


__all__ = ["GoogleCloudDNSDriver"]
