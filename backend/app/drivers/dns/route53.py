"""Amazon Route 53 agentless cloud DNS driver (issue #37).

Route 53 is managed exactly like a local BIND9 / PowerDNS zone — same
Zones / Records / group surfaces — but the control plane drives the AWS
SDK (``boto3``) directly instead of an agent. See
``drivers/dns/_cloud_base.py`` for the agentless contract; this module
only implements the five provider hooks plus the ``name`` /
``credential_fields`` class attrs.

Credential dict shape (decrypted from ``DNSServer.credentials_encrypted``)::

    {"access_key_id": "AKIA...", "secret_access_key": "..."}

Route 53 is a global service — there is no region to configure. Each
hosted-zone API call is scoped by the opaque hosted-zone id (``Z...``),
which we resolve from the zone FQDN with ``list_hosted_zones_by_name``
when the caller only knows the name.

A couple of Route-53-specific wrinkles the hooks paper over:

* **MX / SRV structured fields are split in ``RecordData``.** Route 53's
  ``ResourceRecords[].Value`` for an MX record is the full
  ``"10 mail.example.com."`` string, so the driver composes it from
  ``priority`` / ``weight`` / ``port`` + the bare-target ``value`` on
  write and splits it back into those columns on read (#1526).
* **ALIAS records** (``AliasTarget``) have no ``ResourceRecords`` and no
  TTL (Route 53 inherits the target's TTL). We surface them as a record
  whose ``value`` is the alias target DNS name and ``ttl`` is ``None``.
"""

from __future__ import annotations

import asyncio
import uuid
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


class Route53DNSDriver(CloudDNSDriverBase):
    """Agentless driver for Amazon Route 53 hosted zones."""

    name: str = "route53"
    # Ordered credential fields the Add-DNS-server modal renders + the
    # probe validates as required. Route 53 is global — no region.
    credential_fields: tuple[str, ...] = ("access_key_id", "secret_access_key")

    # ── Client factory ──────────────────────────────────────────────────
    def _client(self, creds: dict[str, Any]) -> Any:
        """Build a boto3 Route 53 client from the decrypted creds.

        ``boto3`` is imported lazily so importing this module never fails
        on a host without the AWS SDK installed, and so tests can
        monkeypatch this factory without the wheel present.
        """
        # Deferred import: keeps worker startup light + lets agent-only
        # hosts skip the boto3 wheel entirely.
        import boto3  # noqa: PLC0415

        access_key_id = creds.get("access_key_id")
        secret_access_key = creds.get("secret_access_key")
        if not access_key_id or not secret_access_key:
            raise CloudDNSError(
                "route53 credentials require both 'access_key_id' and 'secret_access_key'."
            )
        # Route 53 is a global endpoint; pass a region anyway because some
        # boto3/botocore configurations refuse to construct a client
        # without one, even though the service ignores it.
        return boto3.client(
            "route53",
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name="us-east-1",
        )

    # ── Zone listing ────────────────────────────────────────────────────
    async def _list_zones(self, server: Any, creds: dict[str, Any]) -> list[CloudDNSZone]:
        client = self._client(creds)
        zones: list[CloudDNSZone] = []
        marker: str | None = None
        try:
            while True:
                kwargs: dict[str, Any] = {"MaxItems": "100"}
                if marker:
                    kwargs["Marker"] = marker
                resp = await asyncio.to_thread(client.list_hosted_zones, **kwargs)
                for z in resp.get("HostedZones", []):
                    name = normalize_fqdn(z.get("Name", ""))
                    zones.append(
                        CloudDNSZone(
                            name=name,
                            # Route 53 hosted-zone ids arrive as
                            # ``/hostedzone/Z123ABC`` — keep only the bare id.
                            zone_id=str(z.get("Id", "")).split("/")[-1],
                            is_reverse=name.rstrip(".").endswith("arpa"),
                            record_count=z.get("ResourceRecordSetCount"),
                        )
                    )
                if resp.get("IsTruncated"):
                    marker = resp.get("NextMarker")
                    continue
                break
        except Exception as exc:  # noqa: BLE001 — wrap any botocore/SDK error
            raise CloudDNSError(f"route53 list_hosted_zones failed: {exc}") from exc
        return zones

    # ── Record listing ──────────────────────────────────────────────────
    async def _list_zone_records(
        self, server: Any, creds: dict[str, Any], zone_name: str
    ) -> list[RecordData]:
        client = self._client(creds)
        apex = normalize_fqdn(zone_name)
        zone_id = await self._resolve_zone_id(client, apex)

        records: list[RecordData] = []
        next_name: str | None = None
        next_type: str | None = None
        try:
            while True:
                kwargs: dict[str, Any] = {"HostedZoneId": zone_id, "MaxItems": "300"}
                if next_name:
                    kwargs["StartRecordName"] = next_name
                if next_type:
                    kwargs["StartRecordType"] = next_type
                resp = await asyncio.to_thread(client.list_resource_record_sets, **kwargs)
                for rrset in resp.get("ResourceRecordSets", []):
                    records.extend(self._expand_rrset(rrset, apex))
                if resp.get("IsTruncated"):
                    next_name = resp.get("NextRecordName")
                    next_type = resp.get("NextRecordType")
                    continue
                break
        except CloudDNSError:
            raise
        except Exception as exc:  # noqa: BLE001 — wrap any botocore/SDK error
            raise CloudDNSError(
                f"route53 list_resource_record_sets failed for {zone_name!r}: {exc}"
            ) from exc
        return records

    def _expand_rrset(self, rrset: dict[str, Any], apex: str) -> list[RecordData]:
        """Expand one Route 53 ResourceRecordSet into ``RecordData`` rows.

        A normal rrset carries an ``ResourceRecords`` list — one
        ``RecordData`` per value (Route 53 groups same-name/same-type
        values into a single rrset; the rest of SpatiumDDI keys records
        per value). An ALIAS rrset carries ``AliasTarget`` instead and
        has no TTL — surface its ``DNSName`` as the value.
        """
        rtype = str(rrset.get("Type", "")).upper()
        name = self._relativize(str(rrset.get("Name", "")), apex)
        ttl = rrset.get("TTL")

        alias = rrset.get("AliasTarget")
        if alias:
            return [
                RecordData(
                    name=name,
                    record_type=rtype,
                    value=normalize_fqdn(str(alias.get("DNSName", ""))),
                    ttl=None,
                )
            ]

        out: list[RecordData] = []
        for rr in rrset.get("ResourceRecords", []):
            value = rr.get("Value")
            if value is None:
                continue
            # MX / SRV rdata arrives composed ("10 mail.example.com.") —
            # split it into the structured columns so the stored shape
            # matches the record API's split contract (#1526).
            bare, priority, weight, port = split_structured_rdata(rtype, str(value))
            out.append(
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
        return out

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

    # ── Record write ────────────────────────────────────────────────────
    async def _apply_record(self, server: Any, creds: dict[str, Any], change: RecordChange) -> None:
        if change.op not in {"create", "update", "delete"}:
            raise CloudDNSError(f"route53._apply_record: bad op {change.op!r}")

        client = self._client(creds)
        apex = normalize_fqdn(change.zone_name)
        zone_id = await self._resolve_zone_id(client, apex)

        rr = change.record
        rtype = rr.record_type.upper()
        absolute = self._absolutize(rr.name, apex)
        default_ttl = int(rr.ttl) if rr.ttl else 300

        # SpatiumDDI stores one DB row per record value and emits one
        # RecordChange per row, but Route 53 groups every value sharing the
        # same {Name, Type} into a single ResourceRecordSet. Writing only
        # this op's value would clobber the rrset's siblings (round-robin A,
        # multiple MX/NS/TXT). For create/delete we read the live rrset and
        # merge so siblings survive; update keeps the single-value replace
        # (see below).
        if change.op == "update":
            # #783 — UPSERT the COMPLETE desired rrset when the control plane
            # resolved one. This used to write only the op's own value, which
            # is a whole-rrset replace against an API that has no other kind
            # of write: editing one of two A records at a name retired the
            # other. The comment here used to call that an inherent
            # per-row→RRset limitation; it was only inherent while the op
            # carried a single value.
            #
            # Without a resolved set (a caller that opted out via
            # ``rrset_action``) the single-value replace is kept — correct for
            # the common single-value rrset (CNAME, a host with one A/TXT),
            # and unchanged from before.
            values = (
                [{"Value": compose_structured_rdata(m)} for m in change.rrset.as_records(rr)]
                if change.rrset is not None and change.rrset.members
                # MX / SRV: compose the provider rdata from the split
                # structured columns + bare target (#1526).
                else [{"Value": compose_structured_rdata(rr)}]
            )
            ttl = int(
                (change.rrset.ttl if change.rrset else None) or (rr.ttl if rr.ttl else 0) or 300
            )
            rrset: dict[str, Any] = {
                "Name": absolute,
                "Type": rtype,
                "TTL": ttl,
                "ResourceRecords": values,
            }
            await self._submit_change(server, client, zone_id, "UPSERT", rrset, change)
            return

        # Read the provider's current rrset for {name, type} so we can merge.
        existing = await self._read_rrset(server, client, zone_id, absolute, rtype)
        # The op's value in provider form — MX / SRV compose the structured
        # columns into the rdata string Route 53 stores (#1526). The live
        # rrset's values are already in that form.
        composed = compose_structured_rdata(rr)

        if change.op == "create":
            if existing is not None and existing.get("AliasTarget"):
                # ALIAS rrsets (AliasTarget) are single-valued and have no
                # ResourceRecords — never merge a value into an alias rrset.
                # Replace it with the new value-bearing rrset instead.
                existing = None
            existing_values = self._existing_values(existing)
            if composed in existing_values:
                # Value already present — the desired set is unchanged, so
                # this is an idempotent no-op.
                logger.info(
                    "route53.apply_record.create_noop",
                    server=str(getattr(server, "id", "")),
                    zone=change.zone_name,
                    name=rr.name,
                    rtype=rtype,
                )
                return
            merged_values = existing_values + [composed]
            ttl = self._merge_ttl(rr.ttl, existing, default_ttl)
            rrset = {
                "Name": absolute,
                "Type": rtype,
                "TTL": ttl,
                "ResourceRecords": [{"Value": v} for v in merged_values],
            }
            await self._submit_change(server, client, zone_id, "UPSERT", rrset, change)
            return

        # op == "delete": remove this value from the live rrset.
        if existing is None or existing.get("AliasTarget"):
            # Nothing to delete (or an alias rrset whose single value isn't a
            # plain ResourceRecords value) — idempotent no-op.
            logger.info(
                "route53.apply_record.delete_noop",
                server=str(getattr(server, "id", "")),
                zone=change.zone_name,
                name=rr.name,
                rtype=rtype,
            )
            return
        existing_values = self._existing_values(existing)
        if composed not in existing_values:
            # Value isn't in the rrset — idempotent no-op.
            logger.info(
                "route53.apply_record.delete_noop",
                server=str(getattr(server, "id", "")),
                zone=change.zone_name,
                name=rr.name,
                rtype=rtype,
            )
            return
        remaining = [v for v in existing_values if v != composed]
        if remaining:
            # Other values survive — UPSERT the reduced set, keeping the
            # rrset's live TTL.
            ttl = int(existing.get("TTL", default_ttl) or default_ttl)
            rrset = {
                "Name": absolute,
                "Type": rtype,
                "TTL": ttl,
                "ResourceRecords": [{"Value": v} for v in remaining],
            }
            await self._submit_change(server, client, zone_id, "UPSERT", rrset, change)
            return
        # Last value removed — delete the whole rrset. Route 53 requires the
        # EXACT existing rrset (incl. its TTL + every value) to delete.
        await self._submit_change(server, client, zone_id, "DELETE", existing, change)

    async def _read_rrset(
        self, server: Any, client: Any, zone_id: str, absolute: str, rtype: str
    ) -> dict[str, Any] | None:
        """Return the live Route 53 rrset for exactly ``{absolute, rtype}``.

        ``list_resource_record_sets`` returns the first rrset at-or-after the
        start key lexically, so when no exact match exists Route 53 hands
        back the NEXT rrset — we compare normalised names + type and discard
        a non-match. Returns ``None`` when no such rrset exists.
        """
        try:
            resp = await asyncio.to_thread(
                client.list_resource_record_sets,
                HostedZoneId=zone_id,
                StartRecordName=absolute,
                StartRecordType=rtype,
                MaxItems="1",
            )
        except Exception as exc:  # noqa: BLE001 — wrap any botocore/SDK error
            raise CloudDNSError(
                f"route53 list_resource_record_sets (read-merge) failed for "
                f"{absolute!r} {rtype} on {zone_id!r}: {exc}"
            ) from exc
        for candidate in resp.get("ResourceRecordSets", []):
            if (
                normalize_fqdn(str(candidate.get("Name", ""))) == normalize_fqdn(absolute)
                and str(candidate.get("Type", "")).upper() == rtype
            ):
                return candidate
        return None

    @staticmethod
    def _existing_values(rrset: dict[str, Any] | None) -> list[str]:
        """Return the rrset's current ``ResourceRecords[].Value`` list."""
        if not rrset:
            return []
        return [
            str(rr["Value"])
            for rr in rrset.get("ResourceRecords", [])
            if rr.get("Value") is not None
        ]

    @staticmethod
    def _merge_ttl(
        change_ttl: int | None, existing: dict[str, Any] | None, default_ttl: int
    ) -> int:
        """TTL for a merged rrset: the change's ttl, else the live rrset's,
        else the default."""
        if change_ttl:
            return int(change_ttl)
        if existing and existing.get("TTL") is not None:
            return int(existing["TTL"])
        return default_ttl

    async def _submit_change(
        self,
        server: Any,
        client: Any,
        zone_id: str,
        action: str,
        rrset: dict[str, Any],
        change: RecordChange,
    ) -> None:
        """Submit a single-change ChangeBatch, wrapping errors + treating an
        InvalidChangeBatch on DELETE as an idempotent no-op."""
        change_batch = {"Changes": [{"Action": action, "ResourceRecordSet": rrset}]}
        try:
            await asyncio.to_thread(
                client.change_resource_record_sets,
                HostedZoneId=zone_id,
                ChangeBatch=change_batch,
            )
        except Exception as exc:  # noqa: BLE001 — wrap any botocore/SDK error
            # A DELETE of a non-existent rrset raises InvalidChangeBatch.
            # The desired end state (record gone) is already met, so treat
            # it as an idempotent no-op rather than a failed op.
            if change.op == "delete" and _is_invalid_change_batch(exc):
                logger.info(
                    "route53.apply_record.delete_noop",
                    server=str(getattr(server, "id", "")),
                    zone=change.zone_name,
                    name=change.record.name,
                    rtype=change.record.record_type.upper(),
                )
                return
            raise CloudDNSError(
                f"route53 change_resource_record_sets ({action}) failed for "
                f"{change.record.name!r} {change.record.record_type.upper()} "
                f"in {change.zone_name!r}: {exc}"
            ) from exc

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

    # ── Zone write ──────────────────────────────────────────────────────
    async def _apply_zone(self, server: Any, creds: dict[str, Any], zone: Any, op: str) -> None:
        client = self._client(creds)
        name = normalize_fqdn(getattr(zone, "name", "") or "")
        if name == ".":
            raise CloudDNSError("route53._apply_zone: zone name is required")

        if op == "create":
            try:
                await asyncio.to_thread(
                    client.create_hosted_zone,
                    Name=name,
                    # CallerReference must be unique per create — a fresh
                    # uuid makes the call idempotently safe to retry only
                    # within the same uuid; a new attempt mints a new one.
                    CallerReference=uuid.uuid4().hex,
                )
            except Exception as exc:  # noqa: BLE001 — wrap any botocore/SDK error
                raise CloudDNSError(
                    f"route53 create_hosted_zone failed for {name!r}: {exc}"
                ) from exc
            return

        if op == "delete":
            zone_id = await self._resolve_zone_id(client, name)
            try:
                await asyncio.to_thread(client.delete_hosted_zone, Id=zone_id)
            except Exception as exc:  # noqa: BLE001 — wrap any botocore/SDK error
                raise CloudDNSError(
                    f"route53 delete_hosted_zone failed for {name!r}: {exc}"
                ) from exc
            return

        raise CloudDNSError(f"route53._apply_zone: unsupported op {op!r}")

    # ── Hosted-zone id resolution ───────────────────────────────────────
    async def _resolve_zone_id(self, client: Any, zone_name: str) -> str:
        """Resolve a hosted-zone id from a zone FQDN.

        ``list_hosted_zones_by_name`` returns hosted zones in Route 53's
        name sort order starting at-or-after ``DNSName``. A single
        ``MaxItems='1'`` result can be a *neighbouring* zone (one that
        sorts at-or-after the queried name but isn't the exact match —
        common when the account holds sibling / sub-zones), so we must not
        conclude "not found" from one row. Instead we page through the
        result set via the ``IsTruncated`` / ``NextDNSName`` /
        ``NextHostedZoneId`` continuation tokens, scanning each page for the
        exact apex match. A modest page size keeps the common case (the
        match is the first row) to a single round-trip.
        """
        apex = normalize_fqdn(zone_name)
        next_dns_name: str | None = apex
        next_zone_id: str | None = None
        while True:
            kwargs: dict[str, Any] = {"MaxItems": "100"}
            if next_dns_name is not None:
                kwargs["DNSName"] = next_dns_name
            if next_zone_id is not None:
                kwargs["HostedZoneId"] = next_zone_id
            try:
                resp = await asyncio.to_thread(client.list_hosted_zones_by_name, **kwargs)
            except Exception as exc:  # noqa: BLE001 — wrap any botocore/SDK error
                raise CloudDNSError(
                    f"route53 list_hosted_zones_by_name failed for {zone_name!r}: {exc}"
                ) from exc
            for z in resp.get("HostedZones", []):
                if normalize_fqdn(z.get("Name", "")) == apex:
                    return str(z.get("Id", "")).split("/")[-1]
            if not resp.get("IsTruncated"):
                break
            # Route 53 hands back the start key for the NEXT page. Without
            # both tokens advancing we'd re-request the same page forever, so
            # bail out (treat as exhausted) if the API omits them.
            next_dns_name = resp.get("NextDNSName")
            next_zone_id = resp.get("NextHostedZoneId")
            if next_dns_name is None and next_zone_id is None:
                break
        raise CloudDNSError(f"route53: hosted zone {zone_name!r} not found")

    # ── Capabilities ────────────────────────────────────────────────────
    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "route53",
            "agentless": True,
            "manages_zones": True,
            "views": False,
            "rpz": False,
            # #29 — cloud DNSSEC is a provider zone-toggle (Route 53 needs a
            # KMS asymmetric key), not the per-record online signing the
            # dnssec_sign/unsign ops model; gated to powerdns/bind9. Deferred.
            "dnssec_online": False,
            # #29 — Route 53 ALIAS targets need an AWS resource + HostedZoneId
            # the generic ALIAS record type can't express, so authoring is not
            # supported via this driver yet (existing alias rrsets still read
            # back). Deferred.
            "alias_records": False,
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
                "Agentless Amazon Route 53 driver. Zone + record CRUD via "
                "the boto3 SDK from the control plane (no agent). Route 53 "
                "is a global service — no region to configure. MX/SRV "
                "structured fields are composed into the provider rdata on "
                "write and split back out on read; ALIAS records "
                "(AliasTarget) surface with a null TTL."
            ),
        }


def _is_invalid_change_batch(exc: Exception) -> bool:
    """True when ``exc`` is a Route 53 InvalidChangeBatch (e.g. delete of a
    record that doesn't exist).

    botocore raises ``ClientError`` with the AWS error code under
    ``response["Error"]["Code"]``. We sniff that without importing
    botocore (which may not be installed) and fall back to a substring
    check on the message so the behaviour holds for stubbed SDKs in tests.
    """
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = str(response.get("Error", {}).get("Code", ""))
        if code in {"InvalidChangeBatch", "NoSuchChange"}:
            return True
    return "InvalidChangeBatch" in str(exc)


__all__ = ["Route53DNSDriver"]
