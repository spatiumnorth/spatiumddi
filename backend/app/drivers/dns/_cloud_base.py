"""Shared base for agentless cloud-hosted DNS drivers (issue #37, Part B).

Cloudflare / Route 53 / Azure DNS / Google Cloud DNS are managed exactly
like a local BIND9 / PowerDNS / Windows zone — same Zones / Records /
group surfaces — but the control plane calls the provider's REST/SDK API
directly instead of driving an agent. This mirrors how ``windows_dns``
Path B already works (see ``drivers/dns/windows.py``):

* No ConfigBundle / long-poll. The render_* methods return ``""`` and
  reload_* are no-ops — agentless drivers never render daemon config.
* Credentials live Fernet-encrypted in the existing
  ``DNSServer.credentials_encrypted`` column (no new credential store).
* Record writes run synchronously from the control plane via
  ``record_ops._apply_agentless`` once the driver name is listed in
  ``AGENTLESS_DRIVERS``.
* Zone topology reads use the same ``pull_zones_from_server`` /
  ``pull_zone_records`` method names Windows DNS exposes, so the existing
  ``sync-from-server`` drift path + the new "import existing zones"
  service both work against any cloud driver with no per-provider glue.

A concrete provider driver subclasses :class:`CloudDNSDriverBase` and
implements only the five cloud-specific hooks (``_list_zones``,
``_list_zone_records``, ``_apply_record``, ``_apply_zone``,
``capabilities``) plus the ``name`` / ``credential_fields`` class attrs.
Everything DNSDriver-shaped is handled here.

Per-driver credential dict shapes (decrypted from
``DNSServer.credentials_encrypted``):
    cloudflare → {"api_token"}
    route53    → {"access_key_id", "secret_access_key"}
    azure_dns  → {"tenant_id","client_id","client_secret",
                  "subscription_id","resource_group"}
    google_dns → {"service_account_json", "project_id"}
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import structlog

from app.core.crypto import decrypt_dict
from app.drivers.dns.base import (
    ConfigBundle,
    DNSDriver,
    EffectiveBlocklistData,
    RecordChange,
    RecordData,
    ServerOptions,
    TsigKey,
    ZoneData,
)

logger = structlog.get_logger(__name__)


class CloudDNSError(Exception):
    """Auth / API / config failure from a cloud DNS provider call.

    Raised so the record-ops + import + probe paths surface a clean
    operator-facing message instead of a raw SDK traceback.
    """


class CloudDNSConflictError(CloudDNSError):
    """The provider already holds a resource SpatiumDDI must not take over.

    Raised e.g. when a zone create names a hosted zone that already
    exists in the provider account: silently adopting it would put a
    zone SpatiumDDI never created under management (and a later delete
    would tear it down). Callers map this to HTTP 409; the remedy is
    the explicit "Import existing zones" flow, which is the one
    sanctioned adoption path.
    """


def provider_value_candidates(record: RecordData) -> set[str]:
    """Spellings a cloud provider may store for one DB record's value.

    Most providers store the value verbatim, but MX / SRV bake the
    numeric fields into the rdata string (``"10 mail.example.com."``,
    ``"0 5 5060 sip.example.com."``) while a SpatiumDDI DB row keeps
    them in separate columns — so a managed-record match has to try
    both shapes. Trailing-dot variants are included because providers
    normalise host targets to FQDNs while DB rows may not.
    """
    value = record.value
    candidates = {value, value.rstrip(".")}
    rtype = record.record_type.upper()
    if record.priority is not None and rtype == "MX":
        baked = f"{record.priority} {value}"
        candidates.update({baked, baked.rstrip(".")})
    elif (
        record.priority is not None
        and record.weight is not None
        and record.port is not None
        and rtype == "SRV"
    ):
        baked = f"{record.priority} {record.weight} {record.port} {value}"
        candidates.update({baked, baked.rstrip(".")})
    return candidates


def managed_value_index(
    records: list[RecordData],
    apex: str,
    absolutize: Callable[[str, str], str],
) -> dict[tuple[str, str], set[str]]:
    """Index managed (DB) records by (absolute name, type) → value spellings.

    Used by zone-delete emptying: a provider rrset value may only be
    deleted when it appears in this index — anything else belongs to
    whoever else writes to the zone and must be left untouched.
    """
    index: dict[tuple[str, str], set[str]] = {}
    for rec in records:
        key = (normalize_fqdn(absolutize(rec.name, apex)), rec.record_type.upper())
        index.setdefault(key, set()).update(provider_value_candidates(rec))
    return index


def value_is_managed(live_value: str, candidates: set[str]) -> bool:
    """True when a provider-side rrset value matches a managed spelling."""
    return live_value in candidates or live_value.rstrip(".") in candidates


@dataclass(frozen=True)
class CloudDNSZone:
    """A hosted zone discovered on a cloud DNS provider.

    ``name`` is normalised to a trailing-dot FQDN. ``zone_id`` is the
    provider's opaque handle (Cloudflare zone id, Route 53 hosted-zone
    id, Azure zone resource name, GCP managed-zone name) — providers may
    need it to scope record calls and should cache/resolve it from
    ``name`` when not threaded through.
    """

    name: str
    zone_id: str = ""
    is_reverse: bool = False
    dnssec_enabled: bool = False
    record_count: int | None = None


@dataclass(frozen=True)
class CloudDNSProbe:
    """Result of a cloud DNS credential probe (Add-DNS-server test button)."""

    ok: bool
    message: str
    zone_count: int | None = None


def normalize_fqdn(name: str) -> str:
    """Lower-case + ensure a single trailing dot. ``""`` / ``"@"`` → ``"."``."""
    n = (name or "").strip().lower()
    if not n or n == "@":
        return "."
    if not n.endswith("."):
        n += "."
    return n


def compose_structured_rdata(record: RecordData) -> str:
    """Compose the provider rdata string for one record from the split form.

    The record API stores MX / SRV split: ``value`` is the bare target and
    priority / weight / port live in their own columns (#1526). Providers
    whose rdata is a single string (Route 53, Google Cloud DNS) need the
    composed wire form — ``"<pref> <target>"`` for MX,
    ``"<priority> <weight> <port> <target>"`` for SRV. Defaults mirror the
    agent renderers: MX preference 10, SRV fields 0. Every other type's
    rdata is the value verbatim.
    """
    rtype = record.record_type.upper()
    if rtype == "MX":
        pref = record.priority if record.priority is not None else 10
        return f"{pref} {record.value}"
    if rtype == "SRV":
        prio = record.priority if record.priority is not None else 0
        weight = record.weight if record.weight is not None else 0
        port = record.port if record.port is not None else 0
        return f"{prio} {weight} {port} {record.value}"
    return record.value


def split_structured_rdata(
    record_type: str, rdata: str
) -> tuple[str, int | None, int | None, int | None]:
    """Split a provider rdata string into ``(value, priority, weight, port)``.

    The inverse of :func:`compose_structured_rdata`, for MX / SRV reads so
    imports + drift store the same split shape the record API writes. A
    value that doesn't parse as the structured form is returned verbatim
    with all three fields ``None`` rather than failing the whole pull.
    """
    rtype = record_type.upper()
    raw = (rdata or "").strip()
    if rtype == "MX":
        head, sep, rest = raw.partition(" ")
        if sep and head.isdigit() and rest.strip():
            return rest.strip(), int(head), None, None
        return raw, None, None, None
    if rtype == "SRV":
        parts = raw.split(None, 3)
        if len(parts) == 4 and all(p.isdigit() for p in parts[:3]):
            return parts[3].strip(), int(parts[0]), int(parts[1]), int(parts[2])
        return raw, None, None, None
    return raw, None, None, None


class CloudDNSDriverBase(DNSDriver):
    """Agentless base for cloud-hosted authoritative DNS providers."""

    name: str = "cloud_dns"
    # Ordered credential field names the Add-DNS-server modal renders +
    # the probe validates as required. Providers override.
    credential_fields: tuple[str, ...] = ()

    # ── Agentless no-ops (control plane talks to the cloud API) ─────────
    def render_server_config(
        self, server: Any, options: ServerOptions, *, bundle: ConfigBundle | None = None
    ) -> str:
        return ""

    def render_zone_config(self, zone: ZoneData) -> str:
        return ""

    def render_zone_file(self, zone: ZoneData, records: list[RecordData]) -> str:
        return ""

    def render_rpz_zone(self, blocklist: EffectiveBlocklistData) -> str:
        return ""

    async def reload_config(self, server: Any) -> None:
        return

    async def reload_zone(self, server: Any, zone_name: str) -> None:
        return

    def validate_config(self, bundle: ConfigBundle) -> tuple[bool, list[str]]:
        # No daemon config is rendered for cloud DNS; the bundle is
        # informational. Accept anything so upstream validators don't block.
        return (True, [])

    # ── Credential handling ─────────────────────────────────────────────
    def _load_credentials(self, server: Any) -> dict[str, Any]:
        """Decrypt the provider credential dict from the server row.

        Raises :class:`CloudDNSError` when unset so the caller can tell
        "not configured" apart from "API rejected the key".
        """
        blob = getattr(server, "credentials_encrypted", None)
        if not blob:
            raise CloudDNSError(
                f"DNS server {getattr(server, 'name', '<unknown>')!r} has no "
                f"{self.name} credentials configured."
            )
        try:
            return decrypt_dict(blob)
        except ValueError as exc:
            raise CloudDNSError(f"{self.name} credentials could not be decrypted: {exc}") from exc

    # ── Record write path (synchronous, control-plane) ──────────────────
    async def apply_record_change(self, server: Any, change: RecordChange) -> None:
        """Apply one record op against the cloud provider.

        ``record_ops._apply_agentless`` calls this and records the op as
        ``applied`` / ``failed`` on a ``DNSRecordOp`` row. Per-op failures
        raise here; the default batch loop in :class:`DNSDriver` isolates
        them into ``RecordChangeResult(ok=False)``.
        """
        creds = self._load_credentials(server)
        await self._apply_record(server, creds, change)
        logger.info(
            "cloud_dns.apply_record_change",
            driver=self.name,
            server=str(getattr(server, "id", "")),
            zone=change.zone_name,
            op=change.op,
            rtype=change.record.record_type,
        )

    async def apply_zone_change(
        self,
        server: Any,
        zone: Any,
        op: str,
        *,
        managed_records: list[RecordData] | None = None,
    ) -> None:
        """Create / delete a hosted zone on the provider.

        Called by the zone-CRUD service helper for agentless drivers. ``op``
        is ``create`` | ``delete``. Cloud providers have no rename — the
        caller sends delete+create.

        ``managed_records`` (delete only) is the zone's record set as
        SpatiumDDI's DB knows it, loaded by the caller while the rows
        still exist. A provider that must empty a zone before deleting
        it scopes that emptying to these records: provider-side records
        SpatiumDDI never managed are left untouched, and if they keep
        the provider from deleting the zone, the provider's refusal
        surfaces as the error (an honest failure, never a silent wipe).
        ``None`` means "no scoping information" — the provider must
        not delete ANY record on the way out, only attempt the zone
        delete itself.
        """
        if op not in {"create", "delete"}:
            raise ValueError(f"{self.name}.apply_zone_change: unsupported op {op!r}")
        creds = self._load_credentials(server)
        await self._apply_zone(server, creds, zone, op, managed_records=managed_records)
        logger.info(
            "cloud_dns.apply_zone_change",
            driver=self.name,
            server=str(getattr(server, "id", "")),
            zone=getattr(zone, "name", ""),
            op=op,
        )

    # ── Zone / record reads (import + drift sync) ───────────────────────
    async def pull_zones_from_server(self, server: Any) -> list[dict[str, Any]]:
        """List hosted zones on the provider account.

        Returns the same neutral dict shape ``windows_dns`` uses so the
        existing sync-from-server reconciliation + the cloud import
        service consume it identically::

            {"name": "example.com.", "zone_type": "Primary",
             "is_reverse_lookup": False, "dnssec_enabled": False,
             "zone_id": "<provider-handle>", "record_count": 12}
        """
        creds = self._load_credentials(server)
        zones = await self._list_zones(server, creds)
        return [
            {
                "name": normalize_fqdn(z.name),
                "zone_type": "Primary",
                "is_reverse_lookup": z.is_reverse,
                "dnssec_enabled": z.dnssec_enabled,
                "zone_id": z.zone_id,
                "record_count": z.record_count,
            }
            for z in zones
        ]

    async def pull_zone_records(
        self,
        server: Any,
        zone_name: str,
        *,
        tsig: TsigKey | None = None,  # noqa: ARG002 — no AXFR here; see below
    ) -> list[RecordData]:
        """Return the records for ``zone_name`` from the provider.

        Record names are returned **relative** to the zone apex (``"@"``
        for apex) to match BIND9 / Windows pulls, so the import + drift
        machinery keys records consistently across drivers.

        ``tsig`` is accepted and ignored: cloud providers are read over
        their own authenticated HTTP APIs, not AXFR, so there is nothing to
        sign. Callers only pass a key for the drivers in
        ``AXFR_TSIG_DRIVERS``, so in practice this always arrives as None
        — the parameter exists to keep one call signature across drivers
        rather than making every call site branch (#734).
        """
        creds = self._load_credentials(server)
        records = await self._list_zone_records(server, creds, normalize_fqdn(zone_name))
        logger.info(
            "cloud_dns.pull_zone_records",
            driver=self.name,
            server=str(getattr(server, "id", "")),
            zone=zone_name,
            count=len(records),
        )
        return records

    async def probe(self, server: Any) -> CloudDNSProbe:
        """Cheap credential check for the Add-DNS-server test button.

        Default: list zones and report the count. Providers with a
        cheaper auth-only call may override. Never raises for an expected
        failure — returns ``ok=False`` with the provider message.
        """
        try:
            zones = await self.pull_zones_from_server(server)
        except CloudDNSError as exc:
            return CloudDNSProbe(ok=False, message=str(exc))
        except Exception as exc:  # noqa: BLE001 — surface any SDK error cleanly
            return CloudDNSProbe(ok=False, message=f"{self.name} API error: {exc}")
        return CloudDNSProbe(
            ok=True,
            message=f"Authenticated; {len(zones)} hosted zone(s) visible.",
            zone_count=len(zones),
        )

    async def health_check(self, server: Any) -> tuple[bool, str]:
        """Health hook for ``app.tasks.dns._check_health`` (#1455).

        Without it the health task falls back to a SOA query against
        ``server.host:server.port`` — for a cloud provider that is the
        literal ``"cloudflare"`` on 443, which can never answer, so every
        cloud server sat at ``unreachable`` while its API calls worked.
        The provider API is what the control plane actually drives, so it
        is also what health should measure: reuse :meth:`probe`, which
        already never raises for an expected failure.
        """
        result = await self.probe(server)
        return result.ok, result.message

    # ── Provider hooks (subclasses implement) ───────────────────────────
    @abstractmethod
    async def _list_zones(self, server: Any, creds: dict[str, Any]) -> list[CloudDNSZone]:
        """Return every hosted zone visible to the credentials."""

    @abstractmethod
    async def _list_zone_records(
        self, server: Any, creds: dict[str, Any], zone_name: str
    ) -> list[RecordData]:
        """Return records for ``zone_name`` (FQDN), names relative to apex."""

    @abstractmethod
    async def _apply_record(self, server: Any, creds: dict[str, Any], change: RecordChange) -> None:
        """Create / update / delete one record on the provider."""

    @abstractmethod
    async def _apply_zone(
        self,
        server: Any,
        creds: dict[str, Any],
        zone: Any,
        op: str,
        *,
        managed_records: list[RecordData] | None = None,
    ) -> None:
        """Create / delete one hosted zone on the provider.

        ``managed_records`` is threaded through from
        :meth:`apply_zone_change` — see its docstring for the
        delete-scoping contract.
        """

    @abstractmethod
    def capabilities(self) -> dict[str, Any]:
        """Driver capability dict (see ``windows.py`` for the shape)."""


__all__ = [
    "CloudDNSDriverBase",
    "CloudDNSConflictError",
    "CloudDNSError",
    "CloudDNSProbe",
    "CloudDNSZone",
    "compose_structured_rdata",
    "managed_value_index",
    "normalize_fqdn",
    "provider_value_candidates",
    "split_structured_rdata",
    "value_is_managed",
]
