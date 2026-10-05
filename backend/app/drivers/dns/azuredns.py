"""Azure DNS driver (issue #37, Part B — agentless cloud provider).

Drives Azure DNS public zones through the ``azure-mgmt-dns`` management
SDK, authenticating with a service-principal client secret. Like the
other cloud drivers (Cloudflare / Route 53 / Google Cloud DNS) it
subclasses :class:`CloudDNSDriverBase` and implements only the five
provider hooks — everything DNSDriver-shaped (no-op renders, credential
decrypt, the import / drift / probe wrappers) lives in the base.

Credential dict shape (decrypted from ``DNSServer.credentials_encrypted``)::

    {"tenant_id": ..., "client_id": ..., "client_secret": ...,
     "subscription_id": ..., "resource_group": ...}

The Azure resource model splits a zone's records into *record sets*, one
per ``(relative_name, record_type)`` pair, each carrying a typed list of
records (``a_records``, ``mx_records``, …). We expand each record set into
one neutral :class:`RecordData` per contained record so the import + drift
machinery sees a flat record list like every other driver.

The ``azure.*`` SDKs are lazy-imported inside :meth:`_client` so importing
this module never fails when the optional dependency is absent, and tests
can monkeypatch the client factory. Blocking SDK calls run in
``asyncio.to_thread`` per the async-throughout non-negotiable.
"""

from __future__ import annotations

import asyncio
from typing import Any

from app.drivers.dns._cloud_base import (
    CloudDNSDriverBase,
    CloudDNSError,
    CloudDNSZone,
    normalize_fqdn,
)
from app.drivers.dns.base import RecordChange, RecordData

# Azure record-set ``type`` is the full ARM resource type. Map the suffix
# back to the neutral record-type label we expose everywhere else. SOA is
# intentionally absent — Azure manages the apex SOA itself and we skip it.
_AZURE_TYPE_TO_RECORD_TYPE = {
    "Microsoft.Network/dnszones/A": "A",
    "Microsoft.Network/dnszones/AAAA": "AAAA",
    "Microsoft.Network/dnszones/CNAME": "CNAME",
    "Microsoft.Network/dnszones/MX": "MX",
    "Microsoft.Network/dnszones/TXT": "TXT",
    "Microsoft.Network/dnszones/NS": "NS",
    "Microsoft.Network/dnszones/SRV": "SRV",
    "Microsoft.Network/dnszones/PTR": "PTR",
    "Microsoft.Network/dnszones/CAA": "CAA",
}

# Neutral record type → the typed record-list attribute on an Azure record
# set (``a_records`` / ``mx_records`` / …). Used by the read-merge path to
# pull the live RRset's per-record entries off whatever the SDK returned.
# ``CNAME`` is intentionally absent — it is a single-valued ``cname_record``,
# never a list, so it always uses the replace path.
_RECORD_TYPE_TO_AZURE_ATTR = {
    "A": "a_records",
    "AAAA": "aaaa_records",
    "MX": "mx_records",
    "TXT": "txt_records",
    "NS": "ns_records",
    "SRV": "srv_records",
    "PTR": "ptr_records",
    "CAA": "caa_records",
}


def _zone_label(zone_name: str) -> str:
    """Azure zone resource names carry no trailing dot — strip it."""
    return normalize_fqdn(zone_name).rstrip(".")


def _relative_name(name: str) -> str:
    """Azure uses ``"@"`` for the apex, same as us — pass through."""
    n = (name or "").strip()
    return n or "@"


class AzureDNSDriver(CloudDNSDriverBase):
    """Agentless Azure DNS driver via the ``azure-mgmt-dns`` SDK."""

    name = "azure_dns"
    credential_fields = (
        "tenant_id",
        "client_id",
        "client_secret",
        "subscription_id",
        "resource_group",
    )

    # ── SDK client factory (lazy import; patched in tests) ───────────────
    def _client(self, creds: dict[str, Any]) -> Any:
        """Build a ``DnsManagementClient`` from a service-principal secret.

        Lazy-imports the Azure SDKs so this module imports cleanly without
        ``azure-identity`` / ``azure-mgmt-dns`` installed. Raises
        :class:`CloudDNSError` on a missing dependency so the operator gets
        an actionable message rather than a bare ``ImportError``.
        """
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.dns import DnsManagementClient
        except ImportError as exc:  # pragma: no cover — env-dependent
            raise CloudDNSError(
                "azure_dns driver requires the 'azure-identity' and "
                "'azure-mgmt-dns' packages to be installed."
            ) from exc

        credential = ClientSecretCredential(
            tenant_id=creds["tenant_id"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
        )
        return DnsManagementClient(credential, creds["subscription_id"])

    def _wrap_errors(self, exc: Exception) -> CloudDNSError:
        """Translate an Azure SDK error into a clean :class:`CloudDNSError`.

        Lazy-imports the SDK exception types so we recognise auth / HTTP
        failures even though the import lives inside a method. Any other
        exception is re-wrapped verbatim by the caller.
        """
        try:
            from azure.core.exceptions import (
                ClientAuthenticationError,
                HttpResponseError,
            )
        except ImportError:  # pragma: no cover — env-dependent
            return CloudDNSError(f"azure_dns API error: {exc}")
        if isinstance(exc, ClientAuthenticationError):
            return CloudDNSError(f"azure_dns authentication failed: {exc}")
        if isinstance(exc, HttpResponseError):
            return CloudDNSError(f"azure_dns API error: {exc}")
        return CloudDNSError(f"azure_dns error: {exc}")

    # ── Zone listing ─────────────────────────────────────────────────────
    async def _list_zones(self, server: Any, creds: dict[str, Any]) -> list[CloudDNSZone]:
        client = self._client(creds)
        rg = (creds.get("resource_group") or "").strip()

        def _list() -> list[Any]:
            if rg:
                return list(client.zones.list_by_resource_group(rg))
            return list(client.zones.list())

        try:
            zones = await asyncio.to_thread(_list)
        except Exception as exc:  # noqa: BLE001 — wrapped into CloudDNSError
            raise self._wrap_errors(exc) from exc

        out: list[CloudDNSZone] = []
        for z in zones:
            name = normalize_fqdn(z.name)
            out.append(
                CloudDNSZone(
                    name=name,
                    zone_id=z.name,
                    is_reverse=name.rstrip(".").endswith("arpa"),
                    record_count=getattr(z, "number_of_record_sets", None),
                )
            )
        return out

    # ── Record listing ───────────────────────────────────────────────────
    async def _list_zone_records(
        self, server: Any, creds: dict[str, Any], zone_name: str
    ) -> list[RecordData]:
        client = self._client(creds)
        rg = (creds.get("resource_group") or "").strip()
        zone_label = _zone_label(zone_name)

        def _list() -> list[Any]:
            return list(client.record_sets.list_by_dns_zone(rg, zone_label))

        try:
            record_sets = await asyncio.to_thread(_list)
        except Exception as exc:  # noqa: BLE001 — wrapped into CloudDNSError
            raise self._wrap_errors(exc) from exc

        records: list[RecordData] = []
        for rs in record_sets:
            records.extend(self._expand_record_set(rs))
        return records

    def _expand_record_set(self, rs: Any) -> list[RecordData]:
        """Expand one Azure record set into per-record neutral rows.

        Skips SOA (apex, Azure-managed) and any record-set ``type`` we
        don't map. ``name`` is already relative to the apex (``"@"``).
        """
        rtype = _AZURE_TYPE_TO_RECORD_TYPE.get(getattr(rs, "type", "") or "")
        if rtype is None:
            return []  # SOA or an unmapped type — drop silently

        name = _relative_name(getattr(rs, "name", "@"))
        ttl = getattr(rs, "ttl", None)
        out: list[RecordData] = []

        def add(value: str) -> None:
            out.append(RecordData(name=name, record_type=rtype, value=value, ttl=ttl))

        if rtype == "A":
            for r in getattr(rs, "a_records", None) or []:
                add(r.ipv4_address)
        elif rtype == "AAAA":
            for r in getattr(rs, "aaaa_records", None) or []:
                add(r.ipv6_address)
        elif rtype == "CNAME":
            cname = getattr(rs, "cname_record", None)
            if cname is not None:
                add(cname.cname)
        elif rtype == "MX":
            for r in getattr(rs, "mx_records", None) or []:
                # Split form (#1526): bare exchange in value, preference in
                # its own column — NOT the composed "10 mail.example.com".
                out.append(
                    RecordData(
                        name=name,
                        record_type=rtype,
                        value=r.exchange,
                        ttl=ttl,
                        priority=int(r.preference),
                    )
                )
        elif rtype == "TXT":
            for r in getattr(rs, "txt_records", None) or []:
                add("".join(r.value))
        elif rtype == "NS":
            for r in getattr(rs, "ns_records", None) or []:
                add(r.nsdname)
        elif rtype == "SRV":
            for r in getattr(rs, "srv_records", None) or []:
                out.append(
                    RecordData(
                        name=name,
                        record_type=rtype,
                        value=r.target,
                        ttl=ttl,
                        priority=int(r.priority),
                        weight=int(r.weight),
                        port=int(r.port),
                    )
                )
        elif rtype == "PTR":
            for r in getattr(rs, "ptr_records", None) or []:
                add(r.ptrdname)
        elif rtype == "CAA":
            for r in getattr(rs, "caa_records", None) or []:
                add(f"{r.flags} {r.tag} {r.value}")
        return out

    # ── Record write ─────────────────────────────────────────────────────
    async def _apply_record(self, server: Any, creds: dict[str, Any], change: RecordChange) -> None:
        client = self._client(creds)
        rg = (creds.get("resource_group") or "").strip()
        zone_label = _zone_label(change.zone_name)
        relative = _relative_name(change.record.name)
        rtype = change.record.record_type.upper()

        if change.op == "delete":
            await self._apply_delete(client, rg, zone_label, relative, rtype, change.record)
            return

        if change.op == "create":
            await self._apply_create(client, rg, zone_label, relative, rtype, change.record)
            return

        # update — replace the RRset. #783: with a resolved RRset the
        # replacement is the COMPLETE desired set, so editing one of two A
        # records at a name no longer retires the other. That used to be
        # described here as an inherent per-row→RRset limitation; it was
        # only inherent while the op carried a single value.
        #
        # Without a resolved set (a caller that opted out via
        # ``rrset_action``), or for a single-valued type with no typed list
        # to fill, the previous single-value replace is kept — right for the
        # common single-value RRset (CNAME, a host with one A/TXT).
        attr = _RECORD_TYPE_TO_AZURE_ATTR.get(rtype)
        if change.rrset is not None and change.rrset.members and attr is not None:
            params = {
                "ttl": (
                    change.rrset.ttl
                    if change.rrset.ttl is not None
                    else (change.record.ttl if change.record.ttl is not None else 3600)
                ),
                attr: [self._build_record_entry(r) for r in change.rrset.as_records(change.record)],
            }
        else:
            params = self._build_record_set_params(change.record)

        def _put() -> None:
            client.record_sets.create_or_update(rg, zone_label, relative, rtype, params)

        try:
            await asyncio.to_thread(_put)
        except Exception as exc:  # noqa: BLE001 — wrapped into CloudDNSError
            raise self._wrap_errors(exc) from exc

    async def _apply_create(
        self,
        client: Any,
        rg: str,
        zone_label: str,
        relative: str,
        rtype: str,
        record: RecordData,
    ) -> None:
        """Create one record value, read-merging into the live RRset.

        Cloud providers group every value under one RRset keyed by
        ``{name, type}`` (round-robin A, multiple MX/NS/TXT). SpatiumDDI
        emits one op per stored row, so we must read the provider's current
        RRset and write back the union — otherwise the first PUT would drop
        every sibling value already in the set.
        """
        # CNAME (and any non-listable type) is single-valued — there is no
        # set to merge into, so use the plain replace path.
        if rtype not in _RECORD_TYPE_TO_AZURE_ATTR:
            params = self._build_record_set_params(record)

            def _put() -> None:
                client.record_sets.create_or_update(rg, zone_label, relative, rtype, params)

            try:
                await asyncio.to_thread(_put)
            except Exception as exc:  # noqa: BLE001 — wrapped into CloudDNSError
                raise self._wrap_errors(exc) from exc
            return

        new_entry = self._build_record_entry(record)

        def _merge_and_put() -> None:
            existing = self._get_record_set(client, rg, zone_label, relative, rtype)
            entries = [] if existing is None else self._existing_entries(existing, rtype)
            # Dedupe: if this value is already in the set, it's a no-op.
            present = {self._entry_key(rtype, e) for e in entries}
            if self._entry_key(rtype, new_entry) not in present:
                entries = entries + [new_entry]
            # TTL: prefer the change's ttl, fall back to the existing set's,
            # then the driver default.
            ttl = record.ttl
            if ttl is None and existing is not None:
                ttl = getattr(existing, "ttl", None)
            if ttl is None:
                ttl = 3600
            params = {"ttl": ttl, _RECORD_TYPE_TO_AZURE_ATTR[rtype]: entries}
            client.record_sets.create_or_update(rg, zone_label, relative, rtype, params)

        try:
            await asyncio.to_thread(_merge_and_put)
        except Exception as exc:  # noqa: BLE001 — wrapped into CloudDNSError
            raise self._wrap_errors(exc) from exc

    async def _apply_delete(
        self,
        client: Any,
        rg: str,
        zone_label: str,
        relative: str,
        rtype: str,
        record: RecordData,
    ) -> None:
        """Delete one record value, reducing the live RRset.

        Reads the current RRset, removes THIS value, and writes the reduced
        set. If the value was the last one (or the set is gone) the whole
        RRset is deleted. A missing value/RRset is an idempotent no-op.
        """

        def _read_and_reduce() -> None:
            existing = self._get_record_set(client, rg, zone_label, relative, rtype)
            if existing is None:
                # RRset already absent — idempotent no-op.
                return

            # CNAME / unlistable types: deleting the value deletes the set.
            if rtype not in _RECORD_TYPE_TO_AZURE_ATTR:
                client.record_sets.delete(rg, zone_label, relative, rtype)
                return

            target_key = self._entry_key(rtype, self._build_record_entry(record))
            entries = self._existing_entries(existing, rtype)
            remaining = [e for e in entries if self._entry_key(rtype, e) != target_key]
            if len(remaining) == len(entries):
                # Value isn't present — idempotent no-op.
                return
            if not remaining:
                client.record_sets.delete(rg, zone_label, relative, rtype)
                return
            ttl = getattr(existing, "ttl", None) or 3600
            params = {"ttl": ttl, _RECORD_TYPE_TO_AZURE_ATTR[rtype]: remaining}
            client.record_sets.create_or_update(rg, zone_label, relative, rtype, params)

        try:
            await asyncio.to_thread(_read_and_reduce)
        except Exception as exc:  # noqa: BLE001 — wrapped into CloudDNSError
            raise self._wrap_errors(exc) from exc

    def _get_record_set(
        self, client: Any, rg: str, zone_label: str, relative: str, rtype: str
    ) -> Any | None:
        """Read the live record set, or ``None`` when it doesn't exist.

        Azure raises ``ResourceNotFoundError`` (a ``HttpResponseError``
        subclass) for an absent set; we lazy-import both and treat either as
        "no existing set". Any other SDK error propagates to be wrapped.
        """
        not_found_types: tuple[type[Exception], ...] = ()
        http_error_type: type[Exception] | None = None
        try:
            from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

            not_found_types = (ResourceNotFoundError,)
            http_error_type = HttpResponseError
        except ImportError:  # pragma: no cover — env-dependent
            pass
        try:
            return client.record_sets.get(rg, zone_label, relative, rtype)
        except Exception as exc:  # noqa: BLE001 — narrowed below
            if not_found_types and isinstance(exc, not_found_types):
                return None
            if (
                http_error_type is not None
                and isinstance(exc, http_error_type)
                and getattr(getattr(exc, "response", None), "status_code", None) == 404
            ):
                return None
            raise

    def _existing_entries(self, record_set: Any, rtype: str) -> list[dict[str, Any]]:
        """Normalise a live record set's typed records into entry dicts.

        Returns the same dict shape :meth:`_build_record_entry` produces so
        merge/dedupe/removal can compare with ``==`` / ``in``.
        """
        attr = _RECORD_TYPE_TO_AZURE_ATTR[rtype]
        records = getattr(record_set, attr, None) or []
        out: list[dict[str, Any]] = []
        for r in records:
            if rtype == "A":
                out.append({"ipv4_address": r.ipv4_address})
            elif rtype == "AAAA":
                out.append({"ipv6_address": r.ipv6_address})
            elif rtype == "MX":
                out.append({"preference": int(r.preference), "exchange": r.exchange})
            elif rtype == "TXT":
                out.append({"value": list(r.value)})
            elif rtype == "NS":
                out.append({"nsdname": r.nsdname})
            elif rtype == "SRV":
                out.append(
                    {
                        "priority": int(r.priority),
                        "weight": int(r.weight),
                        "port": int(r.port),
                        "target": r.target,
                    }
                )
            elif rtype == "PTR":
                out.append({"ptrdname": r.ptrdname})
            elif rtype == "CAA":
                out.append({"flags": int(r.flags), "tag": r.tag, "value": r.value})
        return out

    def _build_record_entry(self, record: RecordData) -> dict[str, Any]:
        """Build the single per-type record-entry dict for one neutral value.

        This is the element that lives inside the typed record list
        (``a_records[i]`` etc.); :meth:`_build_record_set_params` wraps it as
        a one-element list. Sharing this builder keeps the merge path's
        dedupe comparison identical to what a plain write would produce.
        """
        rtype = record.record_type.upper()
        params = self._build_record_set_params(record)
        attr = _RECORD_TYPE_TO_AZURE_ATTR.get(rtype)
        if attr is None:  # pragma: no cover — only listable types reach here
            raise CloudDNSError(f"azure_dns: {rtype!r} is not a multi-value record type")
        entry: dict[str, Any] = params[attr][0]
        return entry

    def _entry_key(self, rtype: str, entry: dict[str, Any]) -> tuple[Any, ...]:
        """A hashable, comparison-stable identity for one record entry.

        Used for dedupe (create) and removal (delete) so the same value
        compares equal regardless of incidental representation. The TXT case
        joins the value chunks: Azure may store a long TXT string split into
        several 255-byte chunks (``["v=spf1 ", "-all"]``) while a freshly
        built entry has a single chunk (``["v=spf1 -all"]``) — both denote
        the same record and must dedupe / remove correctly.
        """
        if rtype == "TXT":
            return ("TXT", "".join(entry.get("value", [])))
        return (rtype, tuple(sorted(entry.items(), key=lambda kv: kv[0])))

    def _build_record_set_params(self, record: RecordData) -> dict[str, Any]:
        """Build the create_or_update body for one neutral record.

        Returns the loosely-typed dict form the SDK accepts (``ttl`` plus
        the type-specific record list). MX / SRV take their structured
        components from the record's own columns (#1526) — ``value`` is
        the bare target, never a composed string to split back apart.
        """
        rtype = record.record_type.upper()
        ttl = record.ttl if record.ttl is not None else 3600
        params: dict[str, Any] = {"ttl": ttl}
        value = (record.value or "").strip()

        if rtype == "A":
            params["a_records"] = [{"ipv4_address": value}]
        elif rtype == "AAAA":
            params["aaaa_records"] = [{"ipv6_address": value}]
        elif rtype == "CNAME":
            params["cname_record"] = {"cname": value}
        elif rtype == "MX":
            pref = record.priority if record.priority is not None else 10
            params["mx_records"] = [{"preference": pref, "exchange": value}]
        elif rtype == "TXT":
            params["txt_records"] = [{"value": [value]}]
        elif rtype == "NS":
            params["ns_records"] = [{"nsdname": value}]
        elif rtype == "SRV":
            params["srv_records"] = [
                {
                    "priority": record.priority if record.priority is not None else 0,
                    "weight": record.weight if record.weight is not None else 0,
                    "port": record.port if record.port is not None else 0,
                    "target": value,
                }
            ]
        elif rtype == "PTR":
            params["ptr_records"] = [{"ptrdname": value}]
        elif rtype == "CAA":
            flags, tag, caa_value = (value.split(None, 2) + ["", "", ""])[:3]
            params["caa_records"] = [{"flags": int(flags), "tag": tag, "value": caa_value.strip()}]
        else:
            raise CloudDNSError(f"azure_dns: unsupported record type {rtype!r}")
        return params

    # ── Zone write ───────────────────────────────────────────────────────
    async def _apply_zone(self, server: Any, creds: dict[str, Any], zone: Any, op: str) -> None:
        client = self._client(creds)
        rg = (creds.get("resource_group") or "").strip()
        zone_label = _zone_label(getattr(zone, "name", ""))

        if op == "create":

            def _create() -> None:
                client.zones.create_or_update(rg, zone_label, {"location": "global"})

            try:
                await asyncio.to_thread(_create)
            except Exception as exc:  # noqa: BLE001 — wrapped into CloudDNSError
                raise self._wrap_errors(exc) from exc
            return

        # delete — zone delete is a long-running operation; block on the
        # poller. Some SDK versions expose a synchronous ``delete`` instead.
        def _delete() -> None:
            if hasattr(client.zones, "begin_delete"):
                client.zones.begin_delete(rg, zone_label).result()
            else:
                client.zones.delete(rg, zone_label)

        try:
            await asyncio.to_thread(_delete)
        except Exception as exc:  # noqa: BLE001 — wrapped into CloudDNSError
            raise self._wrap_errors(exc) from exc

    # ── Capabilities ─────────────────────────────────────────────────────
    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "azure_dns",
            "agentless": True,
            "manages_zones": True,
            "views": False,
            "rpz": False,
            "dnssec_online": False,
            # #29 — Azure DNS alias records target Azure resources and have no
            # apply path via the generic ALIAS type here; authoring deferred.
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
            "notes": "Azure DNS — online DNSSEC not supported via this driver.",
        }


__all__ = ["AzureDNSDriver"]
